# restore v0.3.0 설치 및 확인

2026-11-05. `ransomguard/restore` 저장소의 세 번째 버전 폴더(`v0.3.0`).

## 버전 표기만 변경

- `v0.3.0`은 기존 복구/JEV `v0.7.0-rc2-hotfix1` 기능을 **그대로** 포함한 이름 변경본이다. 보안 정책과 동작 코드는 추가 수정하지 않았다.
- Python 패키지 / wheel 메타데이터 / `capabilities.version`은 모두 `0.3.0`이다.
- 별도 커널 저장소(`knel`)의 드라이버는 **`v0.7.0-rc2 ABI v1` 호환**이다. 커널 버전을 `0.3.0`으로 바꾸면 안 된다.
- 이전 개발명 및 당시 테스트 기록은 `RC2_*` 문서에 남아 있다.

## Windows 11 격리 VM 설치

기존 작업 디렉터리 및 SQLite 상태 DB를 삭제·덮어쓰기 전에 VMware 스냅샷을 생성한다. 압축파일의 `v0.3.0` 폴더를 예를 들어 `C:\RG_Test\v0.3.0`으로 복사한다. 새 관리자 PowerShell:

```powershell
cd C:\RG_Test\v0.3.0
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.3.0-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard capabilities
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

`capabilities` 출력에서 `version: "0.3.0"`과 `kernel_compatibility: "v0.7.0-rc2 ABI v1"`가 나와야 한다.

이후 파괴적 동작이 없는 기본 확인 절차:

```powershell
.\.venv\Scripts\python.exe -m ransomguard plan-network --config .\config\example.json
.\.venv\Scripts\python.exe -m ransomguard firewall-status --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3
.\.venv\Scripts\python.exe -m ransomguard replay --scenario shared-host --db C:\RG_Test\v030-simulation.sqlite3
```

기존 환경에서 커널과 파일시스템 미니필터가 정상 구동 중일 때 **관측 전용** 실행:

```powershell
.\.venv\Scripts\python.exe -m ransomguard observe --config .\config\example.json --db C:\RG_Test\v030-events.sqlite3 --limit 30
```

위 명령들은 실제 방화벽을 차단하거나 의심 프로세스를 종료하지 않는다. `respond-one`, `--authorize-live`, `--live-track-b` 등은 별도의 격리 VM 실동작 검증 단계에서만 사용한다.

## 현재 검증 경계

- `replay`는 모의 시험이다. 실제 `firewall-manager` IPC, Windows WFP 적용, JEV HTTPS 통신, 실시간 종료 및 VSS 복구는 별도 검증이 필요하다.
- 외부 방화벽 데몬은 현재 호스트 아웃바운드 정책이며, 기본 DNS/53 허용과 공통 화이트리스트 등의 제한 사항은 변경되지 않았다.
- 여러 사건의 중복 `on` 억제 기능은 유지하지만, **연속 사건 간 ON/OFF 지연(cooldown)은 미구현**이다.
- 기능 세부 내용: `RC2_HOTFIX1_FIREWALL_DEDUP_KO.md`와 `RC2_FIREWALL_RESPONSE_KO.md`를 참조한다. 해당 문서 속 과거 설치 파일명 대신 위의 v0.3.0 wheel을 사용한다.
