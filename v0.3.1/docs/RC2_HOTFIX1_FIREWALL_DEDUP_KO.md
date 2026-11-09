# restore v0.7.0-rc2-hotfix1 — 전체 방화벽 중복 ON 방지

작성: 2026-11-05 (KST). **커널 v0.7.0-rc2/ABI v1 호환.** `firewall-manager` 외부 저장소와 IPC 스키마는 변경하지 않았다.

## 원인과 수정

기존 rc2 `FirewallHoldManager.acquire()`는 사건이 추가될 때마다 `get → on → get`을 호출했다. 외부 데몬의 `on`은 이미 활성화된 경우에도 `setWhitelist()`를 호출하며 기존 허용 필터를 삭제·재등록한다. 따라서 사건이 겹칠 때 불필요한 WFP 필터 재적용과 JEV 연결 단절 위험이 있었다.

hotfix1의 동작:

1. 첫 사건에서 `get`이 `active=false`면 `on(승인된 화이트리스트)`을 1회 호출하고 `get`으로 다시 확인한다.
2. 다음 사건 또는 동일 사건 재시도 시 `get`이 `active=true`이고, SQLite에 저장된 소유권/화이트리스트가 일치하면 **`on/set/refresh`를 호출하지 않고** 새 hold만 추가한다.
3. 데몬 재시작 등으로 정책이 꺼져 있으면 다음 `acquire()`에서 `on`을 1회 다시 요청하고, 응답과 `get`을 확인한다.
4. 활성 정책이 외부에서 변경됐거나 소유권을 증명할 수 없으면 정책을 덮어쓰지 않는다. 새 사건을 `review_required`로 영속 기록하고 운영자 확인을 요구한다.
5. 마지막 확인된 사건이 안전하게 처리된 경우에만 `off`를 1회 요청한다. 다른 사건이나 `review_required` hold가 있으면 `off`하지 않는다.

두 사건이 겹치는 동안 중복 `on`은 사라졌지만, **사건들이 겹치지 않고 연속으로 들어올 때의 ON/OFF 반복은 아직 남아 있다.** 안전한 종료 유예(cooldown), 수동/자동 해제 정책, Track A 오탐 억제는 별도의 설계·시험이 필요하다. 현재 정책은 마지막 hold 해제 즉시 `off`를 호출한다.

또한 데몬 응답의 `active=true`와 허용 목록 일치는 실제 WFP 패킷 차단이 검증되었다는 의미가 아니다. 기존 데몬의 outbound-only, DNS 53 예외, 전 프로세스 공통 화이트리스트, 기존 세션/inbound 미검증 문제는 유지된다.

## Windows 11 격리 VM 준비

1. VMware 스냅샷을 만든다. **기존 `C:\RG_Test\restore`, 상태 DB, 원래 rc2 파일을 삭제하거나 덮어쓰지 않는다.**
2. `RansomGuard-restore-v0.7.0-rc2-hotfix1.zip`을 `C:\RG_Test\restore_hotfix1\restore`로 압축 해제한다.
3. 해당 폴더에서 관리자 PowerShell로 새 venv를 만든다. 인터넷 접속은 필요 없다.

```powershell
cd C:\RG_Test\restore_hotfix1\restore
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.7.0rc2.post1-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard capabilities
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`capabilities.version`이 `0.7.0-rc2-hotfix1`이면 새 패키지를 실행한 것이다. **이 테스트에는 실제 방화벽 변경, 프로세스 종료, JEV 네트워크 질의가 없다.**

## 검증 상태

- 오프라인 가짜 데몬 회귀 시험: 서로 다른 Track A/B 사건 중복 `on` 방지, 같은 사건 중복 요청, 데몬 재시작 후 비활성 정책 재적용, 외부 화이트리스트 변경 시 fail-closed, 다른 사건의 조기 `off` 방지.
- 실제 Windows 방화벽 데몬 `on/get/off`, WFP 필터 적용과 JEV HTTPS 생존 여부는 **아직 미검증**이다. 시뮬레이션 성공을 실제 방화벽 완성으로 해석하지 않는다.
- 현재 사용자가 검증한 커널 이벤트 경로, SQLite outbox, write/rename 관측 기능은 그대로 유지한다. 이전에 확인된 초기 이벤트 재정렬/시퀀스 경고와 파일 이벤트 pre-operation 한계도 그대로다.

## 실동작 검증 진입 조건

1. 커널/복구 패키지 버전과 정책 설정, 팀장 데몬의 설치·실행 상태를 확인한다.
2. VM 스냅샷과 비상 복구 경로를 확보한다. 외부 운영 PC에서 실행하지 않는다.
3. 겹치는 여러 사건에서 데몬 `on` 1회와 마지막 확인된 사건에 대해서만 `off` 1회가 호출되는지 확인한다.
4. 기존 연결, JEV HTTPS, DNS 53, outbound/inbound 한계는 실제 네트워크 패킷 수준에서 별도로 검증한다.

실제 대응 전에는 `--authorize-live`, `--live-track-b`, `respond-one`을 사용하지 말고 `capabilities`, `plan-network`, 읽기 전용 `firewall-status`, `replay`, 기본 `observe`로만 확인한다.
