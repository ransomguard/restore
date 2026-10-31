# RansomGuard store — v0.6.1

복구·JEV 저장소용 소스다. 커널 드라이버/Visual Studio 솔루션은 별도 `knel` 압축파일에 있다. 이 저장소에는 원래 복구 코드의 진입점, 실제 Windows VSS 생성·파일 복구, JEV 클라이언트, 이벤트 수신·분류·로그 모듈이 들어 있다.

v0.6.0에서 원본의 **스냅샷 생성 기능을 새 모듈에 이관하지 않은 누락**을 수정했다. v0.6.1은 스냅샷 생성과 1시간 예약 작업을 추가하고, 기존 고엔트로피 신호를 실제 관측 루프의 Track B 후보 분류에 연결한다. 완성된 자동 랜섬웨어 대응 제품이라고 표시하지 않는다.

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
.\.venv\Scripts\python.exe -m pip install .
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
