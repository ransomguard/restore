# RansomGuard restore v0.7.0-rc2 — PC 전체 차단·Track A/B 통합 시험

> **hotfix1 업데이트:** `docs/RC2_HOTFIX1_FIREWALL_DEDUP_KO.md`를 먼저 읽는다. `acquire()`의 중복 `on` 전송을 방지하며, 새 wheel `ransomguard_integration-0.7.0rc2.post1-py3-none-any.whl`을 사용한다. 본문 아래의 기존 rc2 wheel 이름은 최초 배포 기록이다.

작성: 2026-11-05 (KST). 커널 호환 대상: `knel v0.7.0-rc2`, wire ABI `0x00010000`.

## 1. 이번 RC에서 구현한 것

| 영역 | 코드 | 동작과 한계 |
| --- | --- | --- |
| Firewall daemon IPC | `ransomguard/firewall_ipc.py` | 이미 실행 중인 `\\.\pipe\Ransom0_Firewall`로 `get/on/set/refresh/off` 1회 요청·응답. 요청 4095바이트 이하, 응답 JSONL, 타임아웃, 결과 검증. 데몬은 시작/중지/변경하지 않음 |
| 전역 차단 소유권 | `ransomguard/firewall_control.py` | SQLite에 사건별 host-outbound hold 저장. Track A/B 모두 같은 **PC 전체** 정책 사용. 마지막 사건이 해결될 때만 `off`; 모호한 상태에서는 유지. 미확인 외부 정책은 임의로 가로채거나 해제하지 않음 |
| 실시간 대응 흐름 | `ransomguard/live_response.py` | Track A: 전체 차단→생성 세대 검증→커널 종료→같은 핸들에서 종료 확인→선택한 기존 VSS 복구→해제. Track B: 전체 차단→JEV→임계값 판정→종료/복구 또는 해제. 오류·불명확 판정 시 REVIEW_REQUIRED |
| PID 재사용 방어 | `ransomguard/process_identity.py` | 실제 Windows 프로세스 핸들의 생성 FILETIME과 커널 이벤트의 원본 64비트 생성 시각 대조; 커널 종료 IOCTL에서도 재검증. UI 표시용 ms 값으로 종료하지 않음 |
| 실제 CLI | `ransomguard/cli.py`, `response_commands.py` | `firewall-status`(기본 로컬 읽기 전용), `respond-one`(명시적인 단일 사건 실험), `observe --live-track-b`(승인된 NT 시험 경로에서만 자동 연결), `firewall-review-release`(운영자 확인 후 해제) |
| VSS | 기존 `snapshots.py`, `recovery.py` | **사본은 매시간 예약 생성만**. 사건 당시 이미 존재한 정확한 볼륨의 사고 이전 사본 사용. 검증된 파일 manifest만 복구. 사본을 사고 시점에 새로 만들지 않음 |
| UI | `ui_bridge.py` | JEV 판정 결과 중 실질적으로 종료 확인 또는 정상 해제가 있는 경우에만 `ALERT`; 복구 검증/실패 시 `VSS_STATUS`. 단순 방화벽 active 응답만으로 `QUARANTINED` 성공 알림을 만들지 않음 |
| 모의 시험 | `incidents.py` | 기존 시뮬레이션도 **host_outbound 전역 hold** 기준으로 변경. 모의 결과는 실제 격리 증거가 아님 |

### 반드시 구분할 것

1. 외부 `firewall-manager`의 `active:true`는 WFP 필터 적용의 독립적인 증거가 아니다.
2. 팀장과 합의한 네트워크 방향은 **프로세스별 격리가 아니라 Track A/B 모두 PC 전체 새 outbound 연결 제한 + JEV URL만 화이트리스트**다. 추후 명시적으로 승인받은 추가 HTTPS 주소만 목록에 넣는다.
3. 기존 데몬은 아직 inbound/기존 세션 보장 미확인, 원격 DNS 53 허용, 허용 주소를 모든 프로세스가 사용할 수 있음. **이번 버전은 해당 한계를 수정하지 않고 추후 검증/개선 과제로 보류한다.** 완전한 정보 유출 방지라고 주장하지 않는다.
4. 네트워크 차단은 파일 쓰기 차단이 아니다. 커널 파일 이벤트는 pre-operation 시도 로그이므로 사건의 전체 손상 파일 목록은 자동으로 확보되지 않는다. **운영자 확인 manifest가 없으면 무작정 복구하지 않으며 REVIEW_REQUIRED로 남긴다.** 이 동작은 안전 측면의 의도된 제한이다.
5. 높은 엔트로피 신호는 **Track B 후보**이지 Track A의 확증이 아니다. Track A의 커널 생성 거부 `PROCESS_BLOCKED`는 생성 방지이며 기존 프로세스를 종료한 것이 아니다. 자동 Track A 판정의 오탐 안전성 검증은 남아 있다.
6. 자동 `observe --live-track-b`는 JEV 호출 중 같은 관측 루프를 기다리게 할 수 있다. 고부하 이벤트 유실, 재연결, 실제 JEV API, 방화벽 정책 지속성은 Windows VM 추가 시험이 필요하다.

## 2. 준비: 실제 **격리된 시험 VM**에서만

1. 최신 `knel v0.7.0-rc2`가 이미 로드·검증된 VM의 **VMware 스냅샷**을 만든다. Windows 호스트 PC에서 live 명령을 실행하지 않는다.
2. `RansomGuard-restore-v0.7.0-rc2.zip`을 VM에 옮기고 압축을 해제하여 `restore` 폴더에 들어간다. 기존 `store`/`restore` 작업 폴더와 SQLite DB는 삭제하지 않는다.
3. 관리자 PowerShell에서 의존성 없는 새 `venv`를 만들고 동봉 wheel로 설치한다.

```powershell
cd C:\RG_Test\restore
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.7.0rc2-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard capabilities
```

4. 외부 firewall-manager 데몬은 **팀장이 제공한 기존 프로그램이 정상 실행 중**이어야 한다. 이 restore는 데몬을 설치·시작·종료하지 않는다. 별도 테스트 클라이언트가 커널 엔진 장치를 등록 중이면 먼저 종료한다.

5. Track B 실제 HTTPS 요청을 할 경우, VM의 통제된 egress, `typesafe-sdk==0.7.5` 사전 설치, `TYPESAFE_API_KEY` 환경 변수 설정이 필요하다. SDK는 기본 오프라인 wheel에 포함되지 않는다. **VM 네트워크를 완전히 끊은 상태에서는 외부 JEV 서버에 도달하지 못한다.** API 키는 코드·스크린샷·outbox·GitHub에 적지 않는다.

## 3. 먼저 실제 차단 없이 확인

```powershell
# 하드웨어/방화벽을 변경하지 않는 읽기 전용 정책 계획
.\.venv\Scripts\python.exe -m ransomguard plan-network --config .\config\example.json

# 이 명령의 기본값은 LOCAL DB만 조회하고 방화벽 파이프를 호출하지 않음
.\.venv\Scripts\python.exe -m ransomguard firewall-status --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3

# 팀장 데몬이 실행 중일 때만: get 명령으로 데몬 상태 읽기
.\.venv\Scripts\python.exe -m ransomguard firewall-status --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3 --query-daemon

# 안전한 관측-only 기본 모드. 아래는 실제 네트워크 차단/kill/JEV 호출을 하지 않음.
.\.venv\Scripts\python.exe -m ransomguard observe --config .\config\example.json --db C:\RG_Test\rc2-events.sqlite3 --limit 30

# Track A/B 전역 hold 상태 전이를 실제 OS 변경 없이 재현
.\.venv\Scripts\python.exe -m ransomguard replay --scenario shared-host --db C:\RG_Test\simulation-rc2.sqlite3
```

`get.active`가 `true`인데 새 hold DB의 소유권이 없다면 **기존 외부 정책을 덮어쓰지 않고 중단**한다. 기존 정책을 임의로 `off`하지 않는다.

## 4. 실제 단일 사건 응답 (`respond-one`) — 선택적 시험

`--pid`, `--create-time`은 **실제 커널 생성 이벤트의 PID 및 원본 64비트 FILETIME**을 넣는다. 단순 PID만으로 확인하거나 UI에 표시된 밀리초 숫자를 넣으면 안 된다. 대상은 VM에서 사용자가 직접 만든, 종료해도 무해한 전용 시험 프로세스를 선택한다.

파일 변경이 전혀 없는 무해한 **종료 동작 단독 실험**은 명시적 `--no-recovery-required`를 붙일 수 있다. Track A는 강력한 악성 증거를 운영자가 확인한 경우(또는 이 VM에서 그 분기를 의도적으로 시험하는 경우)에만 `--track-a-confirmed`를 넣는다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard respond-one `
  --config .\config\example.json `
  --state-db C:\RG_Test\firewall-holds.sqlite3 --db C:\RG_Test\rc2-events.sqlite3 `
  --track A --pid 1234 --create-time 133000000000000001 `
  --track-a-confirmed --no-recovery-required `
  --authorize-live --confirm-isolated-vm
```

위 PID와 FILETIME은 **자리 표시자**이므로 그대로 실행하지 않는다. 응답이 종료 확인까지 통과하면 그 사건의 hold가 해제된다. `REVIEW_REQUIRED`이면 hold가 남을 수 있다. 오류 시 반드시 `firewall-status`로 확인한다.

Track B는 실제 JEV 상태 JSON을 준비해서 `--track B --jev-state-json C:\RG_Test\jev-evidence.json`을 지정한다. **정상/악성 점수 0.2/0.8은 아직 검증하지 않은 시연용 임계값**이다. 해당 기준만으로 운영 PC에서 자동 종료하지 않는다.

### 복구가 필요한 실험

사전에 존재한 VSS의 정확한 `snapshot_id`와 실제 시험 파일을 지정한 복구 입력 JSON을 생성한다. 예시는 `config/recovery_plan_lab_example.json`을 복사하여 경로·GUID·사고 시각·파일명을 VM에 맞게 고친다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard snapshot-inventory --volume-root 'C:\' --output C:\RG_Test\snapshots.json
```

이후 `respond-one ... --recovery-plan C:\RG_Test\plan.json`을 쓴다. 복구는 정확한 볼륨·사건 이전 시간·manifest 경로·사본 존재를 검증한다. 같은 C: 전체를 덮어쓰거나 새 스냅샷을 만들지 않는다.

## 5. Track B 후보에서 실제 응답까지 자동 연결 — 지정 시험 폴더만

`observe`는 기본적으로 절대 live 응답을 하지 않는다. 지정 NT 경로 안에서 생성 세대가 상관 확인된 고엔트로피 쓰기가 발생할 때만 Track B 후보를 대응기로 전달하도록 **명시적으로 켤 수 있다.**

```powershell
# --response-path-prefix는 환경에 맞게 바꿀 것.
# 로그에서 실제 '\Device\HarddiskVolumeN\...' 경로를 먼저 확인한다.
.\.venv\Scripts\python.exe -m ransomguard observe `
  --config .\config\example.json --db C:\RG_Test\rc2-events.sqlite3 --ui `
  --live-track-b --response-state-db C:\RG_Test\firewall-holds.sqlite3 `
  --response-path-prefix '\Device\HarddiskVolume3\RG_Test\rc2_event_test' `
  --response-manifest-template C:\RG_Test\approved-manifest.json `
  --authorize-live --confirm-isolated-vm
```

manifest는 `config/recovery_manifest_lab_example.json` 형식을 참고한다. 사본은 실제 프로세스 **종료 확인 후** 사건 시각을 기준으로 선택한다. 이 고정 파일 목록은 완전한 피해 목록이 아니라 실험자가 선택한 시험 파일 목록이다. 해당 목록 밖의 파일이나 미완료 I/O까지 자동 복구하지 않는다.

파일 복구가 필요 없는, 종료만 확인할 실험일 때에만 `--response-manifest-template` 대신 `--response-no-recovery-required`를 사용한다. 두 옵션을 동시에 지정하거나 둘 다 생략하면 거부한다.

## 6. 오류로 hold가 유지된 경우

```powershell
.\.venv\Scripts\python.exe -m ransomguard firewall-status `
  --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3 `
  --query-daemon
```

남은 사건을 확인한 뒤, 수동으로 악성 프로세스 제거 및 필요한 복구를 확인했거나 오탐임을 검증했다면 **한 사건만** 명시적으로 정리할 수 있다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard firewall-review-release `
  --config .\config\example.json --state-db C:\RG_Test\firewall-holds.sqlite3 `
  --db C:\RG_Test\rc2-events.sqlite3 --incident-id '사건-UUID' `
  --reason lab_cleanup_confirmed `
  --authorize-live --confirm-isolated-vm --operator-verified-safe
```

이 명령은 확인된 한 사건만 해제한다. 마지막 hold일 때만 데몬에 `off`를 요청한다. 이전과 다른 **외부 정책**이 켜져 있거나 정책 상태가 맞지 않으면 임의로 끄지 않는다. 모든 조건이 불명확할 경우 팀장과 데몬 상태를 함께 확인하고 VM 스냅샷 복원 등의 시험환경 절차를 사용한다.

## 7. 이번 RC의 검증 범위와 다음 단계

- Linux/Python 3.12에서 `unittest` 모의 외부 IPC/진행 상태/전역 hold/예외 처리 및 기존 VSS·JEV·UI·관측 회귀 시험 수행. 실제 결과는 패키지 생성 시점의 `docs/RC2_TEST_RESULTS.txt` 참고.
- 실제 Windows 데몬 `on/get/off` 통신, 관리 권한, WFP 적용, 인바운드/기존 세션, DNS/53 처리, 차단 중 JEV 연결, 종료·복구 결과, UI 표시 통합은 **아직 VM 실행 증거 없음**.
- 다음은 VM에서 **읽기 전용 연결 확인 → 명시적 네트워크 차단/해제 → JEV·커널 종료·VSS 복구 → UI/대시보드** 순서로 결과를 수집한다. 기존 제한 3가지는 팀장 합의에 따라 이후 개선 목록에 둔다.
