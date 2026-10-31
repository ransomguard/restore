# RansomGuard v0.6.1 구현 상태 — 2026-10-31

**표기 기준:** ‘코드 있음’은 구현을 소스에서 확인했다는 뜻이다. ‘로컬 시험 통과’는 Linux의 Python 단위/통합 시험 범위다. Windows 드라이버/VSS/API까지 실행 검증한 ‘전체 완성’과 구분한다. 사용자 본인이 원본으로 메모장 내용을 복구한 성공 이력은 인정하며, 새 버전의 Windows 실행 성공으로 바꾸어 말하지 않는다.

## 프로젝트의 최종 동작

- Track A: 확실한 악성 증거 → JEV를 기다리지 않고 종료 요청 → 실제 프로세스 종료 확인 → 필요한 파일 복구 → 결과 기록.
- Track B: 의심 행위(고엔트로피 포함) → 해당 프로세스 통신 제한 및 파일 피해 억제 → 별도 정상 엔진이 JEV에 질의 → 판정에 따라 종료·복구 또는 정상 해제.
- 스냅샷은 1시간 정기 생성만 사용한다. 복구는 판정·위협 통제 뒤 기존 사건 이전 사본으로 수행하므로 다음 정시까지 기다릴 필요가 없다.
- 중앙 대시보드에는 요청·적용·실패·확인, 프로세스/사건 식별, JEV 결과, 복구 결과를 구분해 전달한다.

네트워크 범위는 사용자가 선택한 **의심 프로세스 단위**다. 의심 프로세스는 JEV에도 직접 통신하지 않고 별도 엔진이 질의한다. 정상 엔진의 통신을 유지하는 것과 PC 전체 인터넷을 끊고 JEV만 허용하는 정책은 다른 구성이다. 현재 버전의 실제 WFP 적용은 미구현이다.

## 1. knel 저장소

| 필요한 기능 | 소스 / 구체 구현 | 상태와 남은 부분 |
| --- | --- | --- |
| 프로세스 감시 | `Anti_Ransom_Driver/ProcessMonitor.c`, `ArwProcessNotifyRoutineEx` | 생성·종료·규칙 관측 코드 있음. Windows 검증 필요 |
| 명확한 공격 패턴 fast path | `ProcessMonitor.c`, `ArwpEvaluateFastPath` | 규칙과 BLOCK 생성 거부 코드 있음. 새 설치 기본 AUDIT; 악성 본체 종료와는 별도 |
| 스냅샷 삭제·복구 방해 관측 | `ProcessMonitor.c`의 명령행 규칙 / `Shared/Common.h`의 VSS 보고 IOCTL 선언 | **부분 구현.** 명령행 패턴은 있으나 COM/VSS API 가로채기와 `IOCTL_RG_REPORT_VSS_ATTEMPT` 수신 처리는 미구현 |
| 파일 행위 감시 | `Anti_Ransom_FsFilter/FsFilter.c`, `ArwPreWrite`, `ArwPreSetInformation` | 일부 쓰기·rename의 시도 관측 있음. 성공 결과, 삭제/잘라내기, mapped/paging 등 전체 경로와 보호 폴더 정책의 커널 강제 적용 미완성 |
| 고엔트로피 관측 | `EntropyDetect.c`, `ArwEntropyQ8`; `FsFilter.c`, `ARW_FILE_FLAG_HIGH_ENTROPY` | 계산·플래그 전달 있음. v0.6.1에서 store의 Track B 후보에 연결. 단독 kill 없음 |
| 커널→엔진 이벤트 전달 | `Eventqueue.c`, `Communication.c`, `Shared/Common.h` | IOCTL·큐·등록 엔진 인증 코드 있음. 큐/발신 제한에 따른 유실, 시작 전 프로세스와 재연결 검증 필요 |
| 대상 종료 | `ResponseEngine.c`, `ArwTerminateRansomwareProcess`; `Kernel_test`의 `RequestTerminate` | PID+생성 시간 검증과 수동 종료/종료 확인 코드 있음. 자동 Track A/B 실행 연결 미완성 |
| 엔진 자기 보호 | `SelfProtect.c` | 등록 프로세스 핸들 권한 제한 코드 있음. 실제 공격/우회 범위 VM 검증 필요 |
| 프로세스 통신 차단·해제 | 필요한 WFP 실행 백엔드 | **미구현.** IPv4/IPv6, 이미 열린 연결, UDP/QUIC, 소유 규칙 해제와 후손 프로세스 포함 검증 필요 |
| 판정 대기 중 파일 보호 | 필요한 minifilter 쓰기 제한 / 동시 변경 제어 | **미구현.** 인터넷만 차단해도 로컬 암호화는 계속될 수 있음 |
| 안정적인 사건 식별 | 프로세스 이벤트 generation / 파일 이벤트 연계 | **부분 구현.** 파일 이벤트는 PID뿐이라 단순 매핑을 kill 권한으로 쓰면 안 됨 |
| Windows 배포 | `.sln`, `.props`, `.vcxproj`, INF, `BUILD_NOTES.md` | 프로젝트 파일 있음. 실제 MSVC/WDK 빌드·서명·로드·Driver Verifier 미검증 |

## 2. store 저장소 — 복구/JEV와 사용자 모드 연결

| 필요한 기능 | 소스 / 구체 구현 | 상태와 남은 부분 |
| --- | --- | --- |
| 실제 VSS 생성 | `ransomguard/snapshots.py`와 `create_snapshot.py` | **이번 누락 복원.** CIM 생성, 반환 코드/사본 ID/볼륨 확인. Windows 실제 생성은 VM 검증 필요 |
| 1시간 자동 생성 | `scheduling.py`, `Install-SnapshotTask.ps1`, CLI `snapshot-run` | **이번 추가.** 다음 정시 시작, 매시간, 영속 시간 제한·동시 실행 방지. 등록/실행은 VM에서 해야 함 |
| 불명확한 생성 결과 처리 | `HourlySnapshotCoordinator`, CLI `snapshot-reconcile` | 타임아웃/중단을 성공으로 처리하지 않고 같은 볼륨의 추가 시도 보류. 확인 후 명시적 정리 |
| 기존 사본 조회·선택 | `recovery.py`, `enumerate_snapshots`, `select_snapshot` | 볼륨과 사건 이전 시간 기준으로 선택. 적절한 사본이 없으면 복구 불가 |
| 실제 파일 복구 | `recovery.py`, `RecoveryEngine.execute`; `vss_recovery.py` 호환 진입점 | 파일별 복사·해시 검증·교체 코드 있음. 부분 실패 처리. 전체 OS/ACL/ADS/EFS 복원은 범위 밖 |
| 원본 복구/JEV 진입점 | `create_snapshot.py`, `vss_recovery.py`, `core/jev_client.py` | 별도 store 패키지에 복원·포함. 세부 호환 범위는 `SNAPSHOTS_KO.md` |
| 고엔트로피 Track B 분류 | `triage.py`, `TriageIntake.ingest`; `cli.py`, `_observe` | **이번 추가.** 실제 이벤트 수신 경로에서 후보/식별 보류 로그. 반복 후보 제한, 쓰기/rename 증거 집계. 자동 질의·차단 실행은 아직 없음 |
| 실제 JEV 질의 | `jev.py`, `JevClient.evaluate`; 원본 `core/jev_client.py` | SDK 호출 코드 있음. 0~1 점수·요청 ID 검증. 실제 계정/응답과 자동 대응 연결 미검증 |
| Track A/B 상태 조정 | `incidents.py`, `IncidentController` | **모의 구현.** 정상/악성/타임아웃/늦은 응답/복구 실패/중첩 사건 시험. 실제 OS 실행기와 영속 사건 복원 미구현 |
| 프로세스 단위 격리 계획 | `network_policy.py`, `make_plan` | 기존 호스트 범위 오류를 프로세스 범위로 수정. 계획만 출력; 실시간 차단은 없음 |
| 파일 복구 목록 자동 작성 | 커널의 파일 식별/최종 결과에 기반한 manifest 생성 | **미구현.** 현재는 명시적으로 지정한 목록을 사용. rename 잔재/새 악성 파일 자동 정리도 남음 |
| 중앙 로그 기록·전송 | `outbox.py`, `dashboard.py`, CLI `send-events` | SQLite 영속 저장·HTTPS 배치·개별 ACK 코드/모의 시험 있음. 실제 대시보드 계약 연동 미검증 |
| 로그·스냅샷 보존/용량 관리 | 후속 정책과 정리 기능 | **미완성.** 이 버전은 기존 VSS/로그를 자동 삭제하지 않음. 시간 간격만으로 저장량 상한이 생기지는 않음 |
| 서비스 운영/재시작 | 시간 제한 상태 DB와 로그 DB는 영속 | 사건/네트워크 규칙/kill/복구 중단을 통합 복구하는 Windows 서비스는 미구현 |

## 3. 중앙 대시보드

사용자 설명상 UI는 완성이다. 이번 작업에 실제 백엔드 명세/코드가 없으므로 RansomGuard 로그가 해당 UI에 표시되는 통합 완료 여부는 확인하지 않았다. 필요한 다음 자료는 로그 수신 API 경로, 인증 방식, 요청/ACK 예시 또는 그 라우터 코드다. API 키/비밀 토큰은 필요 없다.

## 4. 이번 버전에서 바뀐 것

1. 원본에 있던 실제 생성 기능을 복원하고 WMIC 호출 대신 CIM 제공자에 연결했다.
2. 3600초 정책을 코드·작업 스케줄러·영속 중복 방지에 연결했다. 감지/JEV/복구/시작 시 추가 생성하지 않는다.
3. 고엔트로피 신호가 `kernel_event`로만 끝나지 않고 `track_b_candidate` 또는 `track_b_deferred`로 남는다.
4. 프로세스 단위 격리 요구에 맞춰 계획·모의 상태 전이·설정을 수정했다. 서로 다른 프로세스/세대의 격리 상태를 섞지 않는다.
5. 커널과 복구/JEV를 각각 `knel`, `store` 업로드 단위로 분리하고 코드/모의/미검증 상태를 명시했다.

커널 바이너리를 새로 빌드했다고 주장하지 않으며, 전체 자동 방어가 완성됐다고 주장하지 않는다. 이번 수정의 검증 근거와 남은 VM 시험은 `VALIDATION.md`에 있다.

## 5. 다음 검증 순서

1. Windows 11 VM에 store를 설치하고 환경 정보를 수집한다.
2. 정기 생성 작업을 등록하고 첫 VSS ID/볼륨/시각과 결과 로그를 확인한다.
3. 해당 사본 이후 시험 폴더의 텍스트 파일만 수정하여 복구 내용·해시를 확인한다. 생성 주기는 그대로 둔다.
4. knel 빌드·로드 후 무해한 시험 파일 쓰기에서 커널 이벤트와 Track B 후보 로그를 확인한다.
5. 실제 WFP/파일 피해 억제/자동 종료 실행기를 구현·검증한 뒤 JEV와 복구를 잇는다.
6. 실제 대시보드 수신 계약에 맞춰 전송과 중복/재전송을 검증한다.

검증에서는 VSS와 VM 스냅샷을 구분한다. VSS는 프로젝트의 파일 복구 입력이고, VM 스냅샷은 시험 환경 전체를 되돌리는 별도 도구다. 1시간 사본보다 나중에 저장한 정상 내용은 복구 시 잃을 수 있고, 실패/오염된 사본이면 손실 구간은 더 길 수 있다.
