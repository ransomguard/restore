# RansomGuard restore — v0.3.1 (Observer Hotfix + JEV 검증 체크포인트)

**2026-11-09 v0.3.1:** 기존 `v0.3.0` 소스에 Observer Hotfix를 반영했다. 자기 자신의 SQLite DB/WAL 관련 커널 파일 이벤트를 정확한 PID·경로로 필터링하며, 다른 프로세스의 이벤트는 유지한다. Python 패키지·CLI의 버전 표기를 `0.3.1`로 갱신했다. [새 설치·테스트·제한 사항](docs/V0_3_1_RELEASE_KO.md)을 먼저 참고한다.

**실제 통신 확인:** Windows 11 VM에서 커널 이벤트 시퀀스 `2421`의 Track B 후보가 SQLite에 기록됐고, 이를 수동 JEV 호출로 전송해 실제 `jev-1.14.0` 점수 `0.21`을 받았다. Track B 응답 로직의 모의 단위 테스트 11개도 통과했다. 그러나 **완전 자동 JEV 연동 및 실제 차단·종료·복구는 미검증**이다. 아래 v0.3.0 및 과거 RC 문서는 개발 이력이다.

**격리 정책 경고:** 현재 live 응답 구현은 `host_outbound` 전체 PC outbound 차단이며, 요구된 **의심 프로세스만 격리**하는 정책과 다르다. `observe --live-track-b`나 `respond-one`을 다음 검증 단계에서 바로 실행하지 않는다.

## 이전 버전 v0.3.0 기록

**버전 정리:** GitHub `ransomguard/restore`의 `v0.1.0`, `v0.2.0` 다음 배포본이다. 내부 개발명 `v0.7.0-rc2-hotfix1`을 복구/JEV 저장소 버전 `v0.3.0`으로 다시 표기했다. **엔진의 동작 로직은 변경하지 않았다.** `knel` 커널의 `v0.7.0-rc2 ABI v1` 호환 표기는 별개의 버전이므로 그대로 유지했다.

**v0.3.0 당시 설치·검증 안내:** [`docs/V0_3_0_RELEASE_KO.md`](docs/V0_3_0_RELEASE_KO.md). `v0.3.1` 설치에는 위의 새 안내를 사용한다.

**2026-11-05 hotfix1:** 여러 사건이 겹칠 때 방화벽 데몬에 `on` 요청을 반복하던 문제를 수정했다. 이미 이 코디네이터가 승인한 정책이 활성 상태이고 화이트리스트가 정확히 같으면 `get` 확인만 하고 사건 hold를 추가한다. 데몬 재시작 등으로 정책이 비활성화됐으면 `on`을 재적용하고 다시 `get`으로 확인한다. 승인된 정책이 외부에서 변경된 경우에는 임의로 덮어쓰지 않고 사건을 `REVIEW_REQUIRED`로 남긴다. **실제 Windows WFP 검증 및 연속 사건 사이의 재차단/해제 지연(cooldown)은 아직 수행/구현하지 않았다.**

방화벽 중복 ON 수정의 상세 내용은 [`docs/RC2_HOTFIX1_FIREWALL_DEDUP_KO.md`](docs/RC2_HOTFIX1_FIREWALL_DEDUP_KO.md)에 기록되어 있다. 동봉 wheel 버전은 `0.3.0`이고 커널 ABI는 rc2와 동일하다.

복구·JEV 저장소(`restore`)용 소스다. 커널 드라이버/Visual Studio 솔루션은 별도 `knel` 압축파일에 있다. **팀장 승인된 네트워크 격리 방식은 Track A/B 공통 PC 전체 outbound 차단 + JEV HTTPS만 화이트리스트**다. 이 저장소에는 원래 VSS 생성·파일 복구와 JEV 클라이언트, 커널 이벤트/로컬 UI 전달, 별도 `firewall-manager` named-pipe 제어, 영속 전역 hold, 명시적 Track A/B 실시간 대응 흐름이 들어 있다.

v0.7.0-rc1의 커널 이벤트 → SQLite outbox → UI IPC 기능을 유지한다. v0.7.0-rc2에서는 **전체 방화벽 정책 → JEV 판정 → 커널 종료 요청·실제 종료 확인 → 확인된 VSS 파일 복구 → 마지막 사건 hold 해제**를 실제 호출 가능한 모듈로 연결했다. 기본 `observe`는 여전히 관측 전용이며, 실시간 Track B 자동 연결은 **격리 VM·허용 시험 경로·명시적 승인 플래그**를 전제로 한다. 종료/복구/통신이 실제 Windows VM에서 검증된 완성 제품이라고 표시하지 않는다.

**v0.3.0 최신 설치·기능·실제 실험 절차는 [`docs/V0_3_0_RELEASE_KO.md`](docs/V0_3_0_RELEASE_KO.md)를 우선한다.** `docs/RC2_FIREWALL_RESPONSE_KO.md`, `docs/RC1_INTEGRATION_KO.md`와 이 파일 아래의 옛 RC1 설명은 이전 개발 이력이다.

## v0.3.0 명령 요약

```powershell
# 모든 시스템 변경 전: 상태·정책만 확인
.\.venv\Scripts\python.exe -m ransomguard capabilities
.\.venv\Scripts\python.exe -m ransomguard plan-network --config .\config\example.json
.\.venv\Scripts\python.exe -m ransomguard firewall-status --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3

# 기본 관측은 실제 네트워크 차단/종료를 하지 않음
.\.venv\Scripts\python.exe -m ransomguard observe --config .\config\example.json --db C:\RG_Test\events.sqlite3

# 실제 격리 VM의 승인된 테스트일 때만 respond-one 또는 observe --live-track-b
.\.venv\Scripts\python.exe -m ransomguard respond-one --help
.\.venv\Scripts\python.exe -m ransomguard observe --help
```

기존 `firewall-manager`와 UI receiver 소스는 **이 패키지에서 변경하지 않았다**. 현재 방화벽의 아웃바운드 범위·DNS/53 예외·모든 프로세스에 적용되는 화이트리스트·active 응답과 WFP 검증의 차이는 그대로이고, 사용자 요청대로 추후 검증/수정 항목으로 남겨두었다. 팀장 데몬이 실행되어 있지 않으면 live IPC가 실패한다.

---

## 이하 v0.7.0-rc1 이전 안내 (기록용)

## RC1: 커널 → UI IPC 연동 확인

**Windows VM에서 `Anti_Ransom_Driver`와 필요한 미니필터를 먼저 로드한다.** UI 수신기(`\\.\pipe\Ransom0_UI`)를 실행했다면 다음 명령으로 연결한다. UI가 없는 상태도 관측 및 SQLite 기록을 계속한다.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.7.0rc1-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard observe --ui --config .\config\example.json --db 'C:\RG_Test\store-events.sqlite3'
```

`--ui`를 빼면 기존 관측 동작이다. UI에는 프로세스 생성·종료·생성 차단, 파일 WRITE·RENAME 시도와 드라이버 상태가 JSONL로 전달된다. 높은 이벤트 양을 제한하기 위해 파일 이벤트는 기본 초당 최대 10개만 UI로 보내며 **원본 이벤트는 모두 outbox에 별도로 기록**한다(저장 용량이 찼을 때는 기존 outbox의 용량 오류 정책 적용). UI에 ACK가 없어 파이프 쓰기 성공은 수신·표시 성공이 아니다. 파일 이벤트는 완료가 아닌 사전 시도 관측이다.

정확한 프로세스 생성 시각의 FILETIME(100ns)은 SQLite에만 보관한다. UI `timestamp`와 `processCreateTime`은 표시용 Unix 밀리초로 변환해 JavaScript 숫자 정밀도를 지킨다. 이 UI 숫자를 다시 가져와 종료 요청의 생성 시간으로 쓰면 안 된다.

1시간 VSS 생성이 **실제로 검증되어 새로 생성된 경우에만**, 수동 `snapshot-run --ui`가 `VSS_STATUS/BACKUP_CREATED`를 전송한다. 기존 1시간 생성 규칙·작업 스케줄러는 변경하지 않았다. 미확인/실패/건너뜀은 생성 성공 알림을 만들지 않는다.

이번 버전은 프로세스별 실제 WFP 네트워크 격리, 파일 변경 억제, 자동 JEV 호출·종료·복구를 켜지 않는다. `WindowsDriverReader.terminate_checked`는 정확한 64비트 생성 시각과 `explicit_authorization=True`를 요구하는 저수준 인터페이스이며 일반 `observe`에서는 절대 호출되지 않는다.

## 파일별 역할

| 경로 | 구현 내용 |
| --- | --- |
| `create_snapshot.py` | 원본 `check_admin`, `create_vss_snapshot` 진입점 유지; 공통 시간 제한을 거친 생성 |
| `vss_recovery.py` | 원본 `VssRecoveryEngine` 진입점과 비동기 복구 인터페이스 유지 |
| `core/jev_client.py` | 원본의 합성 이벤트를 이용한 **실제 JEV 호출** 시험 코드 유지 |
| `ransomguard/snapshots.py` | CIM을 통한 실제 VSS 생성, 결과/볼륨 확인, SQLite 시간 제한·중복 방지·불명확한 결과의 보류 |
| `ransomguard/scheduling.py` | 다음 정시부터 1시간 간격으로 실행할 Windows 작업 XML 생성 |
| `scripts/Install-SnapshotTask.ps1` | 위 작업 등록; 설치 자체로 스냅샷을 생성하지 않음 |
| `scripts/Uninstall-SnapshotTask.ps1` | 예약 작업 제거; 기존 사본·상태 DB·로그 유지 |
| `ransomguard/recovery.py` | 같은 볼륨의 사건 이전 사본 선택, 파일 목록 검증, 복사·해시 검증·교체 |
| `ransomguard/triage.py` | 고엔트로피 → Track B 후보; 짧은 기간의 쓰기/rename 증거와 프로세스 세대별 중복 억제 |
| `ransomguard/cli.py` | `observe`의 실제 이벤트 수신→분류→outbox 연결, 스냅샷 명령 |
| `ransomguard/jev.py` | 실제 SDK 요청, 응답 점수/요청 ID 검증; 탐지 후보와의 자동 대응 연결은 남아 있음 |
| `ransomguard/outbox.py`, `dashboard.py` | 로컬 영속 로그, HTTPS 배치 전송과 개별 ACK 확인 |
| `ransomguard/incidents.py` | 명확하게 구분한 Track A/B **모의** 상태 전이; 실제 kill·격리를 수행하지 않음 |
| `ransomguard/network_policy.py` | 의심 프로세스 단위 격리의 계획 출력; 실제 WFP 적용은 미구현 |
| `scripts/Collect-Environment.ps1` | Windows/VS/WDK/Python/SDK 환경 조사; 요청 시 `environment.json` 저장 |

## 첫 설치와 예약 작업 등록

**Windows 11 시험 VM 안에서** 압축을 풀고 `store` 폴더에서 진행한다. Windows 드라이버 빌드 없이도 VSS 생성·수동 파일 복구부터 확인할 수 있다. 다음 명령은 VM에서 직접 실행할 절차이며 이 배포본을 만들면서 실행한 Windows 검증 결과가 아니다.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.7.0rc1-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard capabilities
```

프로젝트 요구 Python 버전은 3.10 이상이다. 이번 로컬 자동 검증은 Python 3.12에서 수행한다. 기존 `.env`는 본인 VM에서 유지하고 저장소에는 올리지 않는다. 원본 JEV 시험을 실행하려면 같은 환경에서 `pip install '.[jev]'`로 선택 의존성을 설치한다.

관리자 PowerShell에서 예약 작업을 등록한다.

```powershell
.\scripts\Install-SnapshotTask.ps1 -PythonPath (Resolve-Path .\.venv\Scripts\python.exe).Path
Get-ScheduledTaskInfo -TaskName RansomGuard-HourlySnapshot
```

기본 생성 볼륨은 VM의 `C:\`이고, 첫 파일 복구 시험 폴더는 `C:\RansomGuardLab\Protected`다. `config/example.json`에서 확인한다. 볼륨 사본을 만든다고 실행 중인 C: 전체를 덮어쓰지 않는다.

작업은 **등록한 관리자 계정으로 로그인되어 있고 VM이 실행·깨어 있을 때**, 다음 정시부터 매시간 실행한다. 시작/로그인/탐지/JEV/복구 시 추가 생성, 실패 즉시 재시도, 놓친 시간만큼 몰아서 생성하는 동작은 없다. 일정의 몇 초 차이는 최대 60초 대기한 뒤 시간 제한을 다시 확인하며, 마지막 실제 생성 시도부터 3600초가 지나야 다음 시도를 허용한다. 장시간 지연·꺼짐·실패로 생성이 빠질 수 있다.

기본 상태 DB는 `%ProgramData%\RansomGuard\snapshots.sqlite3`, 작업 결과 로그는 같은 폴더의 `events.sqlite3`다. 중복 방지를 위해 수동 시험과 예약 작업 모두 같은 상태 DB를 사용한다. DB를 지우거나 다른 경로로 바꾸면 기존 시도와의 연계가 끊긴다.

정기 사본이 생긴 뒤 조회한다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard snapshot-inventory --volume-root 'C:\' --output snapshots.json
.\.venv\Scripts\python.exe -m ransomguard export-events --db "$env:ProgramData\RansomGuard\events.sqlite3" --output snapshot-events.jsonl
```

복구 API의 사용법은 `docs/MODULE_USAGE.md`, 기존 진입점 호환 범위는 `docs/SNAPSHOTS_KO.md`에 있다. 타임아웃/중단 때문에 생성 결과가 불명확하면 자동 재생성하지 않는다. 기존 시도의 종료와 실제 사본 유무를 조사한 뒤 `snapshot-reconcile` 명령으로 상태를 정리한다.

## 고엔트로피 Track B

드라이버를 VM에 설치한 뒤 다음 명령을 사용한다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard observe --config .\config\example.json --db "$env:ProgramData\RansomGuard\events.sqlite3"
```

고엔트로피 쓰기 관측은 `track_b_candidate`를 만든다. 프로세스 세대 식별이 부족하면 `track_b_deferred`로 남긴다. 후보에는 쓰기/rename/고엔트로피 횟수와 경로 예시가 포함되고, 반복 후보는 제한한다. 고엔트로피 하나만으로 Track A나 kill을 발생시키지 않는다.

현재 `observe`는 **후보 기록까지 실제 연결**한다. 실제 프로세스 통신 차단·파일 쓰기 억제·비동기 JEV 판정·kill·복구를 잇는 자동 실행기는 남아 있다. `replay`는 그 흐름을 검사하는 모의 시험이고 실제 방어 기능의 증거가 아니다.

## 상태와 검증

두 저장소별 상세 상태는 `docs/IMPLEMENTATION_STATUS_KO.md`, 실제 수행한 검증은 `docs/VALIDATION.md`를 본다. Windows VSS 실행, 예약 작업 실행, 커널 빌드·로드, 실제 JEV와 대시보드 연동은 VM 검증이 필요하다.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```
