# store v0.7.0-rc1: 커널 관측 → 영속 로그 → 로컬 UI 연동

> 이 문서는 RC1 기록이다. **최신 `restore v0.7.0-rc2`의 전역 네트워크/JEV/종료/복구 흐름은 [`RC2_FIREWALL_RESPONSE_KO.md`](RC2_FIREWALL_RESPONSE_KO.md)가 우선한다.** 아래의 PID 단위 격리·미구현 언급은 당시 상태다.

검토일: 2026-11-05 (KST). 기준 커널: 별도 `knel` 저장소의 **v0.7.0-rc2**, wire ABI `0x00010000`.

이 RC는 **통합 시험용 미리보기**다. 이번 Python 작업의 로컬 테스트 성공과 실제 Windows VM / UI 앱에 띄운 결과를 구분한다. 기존 `store` 0.6.1의 VSS, JEV, 복구 코드는 보존한다. 별도 `firewall-manager`와 UI 수신기 저장소는 수정하거나 이 패키지에 포함하지 않는다.

## 1. 구현된 연결

| 기능 | 실제 소스 | 적용·미적용 |
| --- | --- | --- |
| 커널 이벤트 수신 | `windows_reader.py`, `protocol.py`, `cli.py` | 실제 `\\.\RansomGuard` 등록/IOCTL 수신 코드. 로컬 fake reader 시험 완료, 새 store의 VM 실행 필요 |
| 영속 로그 | `outbox.py` | 원시 64비트 FILETIME 및 process generation과 이벤트·Track B 후보를 SQLite에 기록 |
| UI 매핑 | `ui_bridge.py` | type1~5 → PROCESS_CREATE / PROCESS_TERMINATE / PROCESS_BLOCKED / FILE_WRITE / FILE_RENAME |
| 상태 알림 | `ui_bridge.py`, `cli.py` | 시작과 매 100건(default)에 실제 드라이버 카운터를 SYSTEM_STATUS로 송신 |
| UI 전송 | `ui_pipe.py` | **이미 실행 중인** `\\.\pipe\Ransom0_UI`에 UTF-8 JSONL + `\n`; 연결·쓰기 제한 시간과 재접속, 파일 이벤트 기본 10건/s 제한 |
| VSS 상태 | `ui_bridge.py`, `cli.py` | `snapshot-run --ui`에서 새 VSS 생성이 검증된 경우에만 BACKUP_CREATED 송신 |
| 유실 감지 | `protocol.py`, `cli.py` | 100건마다 읽는 `events_dropped` 증가 시 PID 세대 캐시 및 triage 상태 무효화·기록 |
| 종료 IOCTL | `windows_reader.py` | 24바이트 요청/16바이트 응답 및 정확한 process generation·수동 승인 검사. `observe`의 자동 호출 없음 |
| Track B/JEV | `triage.py`, `jev.py` | 고엔트로피 후보 기록과 별도 JEV 클라이언트 유지. **후보를 실시간 JEV로 자동 송신하지 않음** |
| 실제 격리·자동 복구 | 별도 구현 필요 | **현재 미구현**. WFP의 PID 단위 격리, 파일 쓰기 보호·실시간 manifest, 안전한 사건 실행기 완성 전 자동 대응 비활성 |

`PROCESS_BLOCKED`는 커널의 **생성 거부 결과**이며, 이미 실행 중인 랜섬웨어 본체가 종료되었다는 의미가 아니다. `FILE_WRITE/RENAME` 역시 pre-operation **시도 관측**이지 파일 변조 성공 결과가 아니다. 고엔트로피 하나로 Track A를 발동하지 않는다.

### 숫자·전달 계약

- 원본 kernel FILETIME/생성 시간은 100ns 단위 64비트 정수다. JS `number`로 직접 전송하면 정밀도가 깨지므로 UI 표시용 `timestamp`, `processCreateTime`만 **Unix epoch 밀리초**로 변환한다. 생성 전 차단처럼 생성 시각을 알 수 없는 경우 `processCreateTime=0`이다. 종료 요청에는 UI 숫자가 아닌 **검증된 정확한 64비트 생성 시각**이 필요하다.
- `sequenceNumber`는 안전한 JS 정수 범위에서만 송신한다. 넘으면 UI 송신만 보류하고 원본 outbox는 유지한다. 드라이버 상태의 `SYSTEM_STATUS` 시작 메시지는 이벤트가 아닌 시점이므로 `sequenceNumber=0`을 사용하며 이후 주기 메시지는 최신 관측 번호를 표시한다.
- 수신기는 앱 수준 ACK를 보내지 않는다. Windows `WriteFile` 성공을 UI가 정상 소비하거나 디스크에 기록했다는 뜻으로 보지 않는다. UI 미연결·사용량 제한·오류 발생 시 **손실 없는 UI 큐를 약속하지 않는다**. 상세 카운터는 마지막 `observer_stopped.local_ui_diagnostics`에 있다. 원본 outbox도 무한정 쌓이지 않으므로 실제 배포 시 전송 ACK 및 보존/용량 정책이 추가로 필요하다.
- Unicode는 JSON의 ASCII escape로 인코딩한다. UTF-8 JSONL이라는 수신 규격을 유지하면서 기존 수신기의 chunk별 UTF-8 디코딩 이슈를 피한다.
- 커널 `termination_requests_succeeded`는 "요청 승인" 누적이며 실제 프로세스 종료 확인과 다를 수 있다. UI 필드 `processesTerminated` 매핑은 **표시용 기존 수신 스키마의 한계**이므로 운영 집계에서 종료 확정으로 간주하지 않는다.

## 2. Windows 11 VM 안전 점검 절차

1. VM 스냅샷을 찍어 둔다. 기존 `knel v0.7.0-rc2` 드라이버는 그대로 사용하고 `store`만 이 버전으로 교체한다. **다른 TestClient가 엔진 장치를 점유하고 있지 않아야 한다.** UI는 사전에 `Ransom0_UI` 수신기를 실행한다.
2. 관리자 PowerShell에서 `store` 디렉터리로 이동하고 Python 3.10 이상에서 설치한다. **VM 인터넷이 꺼져 있어도 동봉된 wheel을 `--no-index`로 설치**할 수 있다. 현재 버전은 Python 기본 의존성만으로 관측·UI 기능을 사용한다(실제 JEV SDK는 선택 의존성). 기존 `store`와 같은 DB 경로를 사용하면 기존 데이터가 유지된다.

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.7.0rc1-py3-none-any.whl
   .\.venv\Scripts\python.exe -m ransomguard capabilities
   ```

3. 드라이버의 현재 상태와 필터를 확인한다. 이전 테스트에서 내려 둔 상태라면 드라이버/미니필터를 먼저 로드한다. 테스트 전용 VM에서만 수행한다.

   ```powershell
   sc.exe query Anti_Ransom_Driver
   sc.exe query Anti_Ransom_FsFilter
   fltmc.exe filters
   # STOPPED이면 기존의 검증된 v0.7.0-rc2 설치 절차로 시작
   sc.exe start Anti_Ransom_Driver
   fltmc.exe load Anti_Ransom_FsFilter
   fltmc.exe instances -f Anti_Ransom_FsFilter
   ```

   이미 RUNNING이면 재시작하지 않는다. `fltmc load`는 필터가 이미 로드된 상태에서는 오류를 낼 수 있다. 미니필터가 없더라도 프로세스 이벤트는 수신될 수 있지만 파일 이벤트 검증을 통과했다고 볼 수 없다.

4. 같은 PowerShell에서 관측을 실행한다. `Ctrl+C`로 정상 종료하여 결과 카운터와 엔진 등록 해제를 확인한다. UI 앱 미실행이어도 outbox 기록은 계속된다.

   ```powershell
   .\.venv\Scripts\python.exe -m ransomguard observe --ui --config .\config\example.json --db 'C:\RG_Test\store-events.sqlite3' --status-every 10
   ```

5. 다른 PowerShell에서 **무해한 테스트 파일**을 생성·수정·이름 변경한다. 파일 경로는 사전에 준비한 `C:\RG_Test`로 제한한다.

   ```powershell
   New-Item -ItemType Directory -Path 'C:\RG_Test\store_bridge_test' -Force
   Set-Content -Path 'C:\RG_Test\store_bridge_test\normal.txt' -Value 'safe observe test'
   Rename-Item -Path 'C:\RG_Test\store_bridge_test\normal.txt' -NewName 'renamed.txt'
   ```

6. 관측 중 UI의 PROCESS_CREATE / FILE_WRITE / FILE_RENAME / SYSTEM_STATUS 여부를 확인하고, `Ctrl+C`로 관측을 종료한 뒤 원본 DB를 추출한다.

   ```powershell
   .\.venv\Scripts\python.exe -m ransomguard export-events --db 'C:\RG_Test\store-events.sqlite3' --output 'C:\RG_Test\store-events.jsonl'
   ```

   `kernel_event`, `observer_stopped`를 확인한다. 고엔트로피 플래그가 우연히 없으면 `track_b_candidate`가 없는 것도 정상이다. UI가 화면에 안 보이면 수신기 활성화·파이프 이름·`local_ui_diagnostics`를 확인한다.

7. VSS 알림 시험은 **정기 생성 시각에 맞거나 중복 방지 정책에서 생성 가능할 때만** 시행한다. `snapshot-run --ui`는 실제 VSS 생성을 수행할 수 있으므로 관리자 VM과 지정된 volume `C:\`에서만 실행한다. 이미 생성한 뒤라면 정상적으로 `skipped`가 반환되고 UI에 BACKUP_CREATED는 보내지 않는다. 기존 자동 예약 주기는 변경하지 않는다.

   ```powershell
   .\.venv\Scripts\python.exe -m ransomguard snapshot-run --ui --config .\config\example.json --state-db "$env:ProgramData\RansomGuard\snapshots.sqlite3" --db "$env:ProgramData\RansomGuard\events.sqlite3"
   ```

**이 단계에서는 일부러 `--terminate` 시험이나 자기보호/방화벽 on/off를 자동으로 수행하지 않는다.** `WindowsDriverReader.terminate_checked`는 이후 실제 격리/신원 재검증 계층이 마련되면 사용한다. 양성 PID·FILETIME만으로 실시간 자동 종료하지 않는다.

## 3. 검증 결과와 다음 구현 우선순위

- Linux/Python 3.12: `python -m unittest discover -s tests -q` → **150 tests OK**. 기존 회복·시간표·JEV·시뮬레이션 135개 보존, UI 매핑·ASCII JSONL·정밀도·오프라인 제한·IOCTL ABI·CLI 연결·드라이버 유실 감지 추가 테스트 통과. `pip wheel --no-deps --no-build-isolation .`로 순수 Python wheel도 구성·포함함.
- 실제 Windows v0.7.0-rc2 **커널 드라이버 자체**는 사용자의 2026-11-05 VM 스크린샷에서 로드/이벤트/수동 종료/자기보호 시험을 확인했다. **신규 store v0.7.0-rc1의 Windows named pipe 송신과 VSS/UI 연동은 아직 VM에서 시험하지 않았다.**
- 남은 핵심: (1) 파일 이벤트에 안전한 process generation·I/O 결과와 파일 ID 연결, (2) **PID 단위 WFP 적용/확인**과 파일 변경 보류, (3) 그 확인 이후에만 JEV 요청·임계값 판단·커널 종료 요청·종료 확인·정기 VSS 사본에서 manifest 기반 복구, (4) 재시작 시 사건/hold 복원과 실제 UI 통합 검증.

외부 `firewall-manager`는 **호스트 outbound 전체**를 다루는 별도 관리 데몬이다. 의심 PID 하나만 차단하는 WFP 백엔드의 대체품으로 사용하거나 해당 데몬/IPC 구현을 변경하지 않는다.
