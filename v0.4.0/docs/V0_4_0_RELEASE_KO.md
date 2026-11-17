# RansomGuard Recovery/JEV v0.4.0 — 2026-11-16

## 기준과 호환성

- 이전 담당자로부터 받은 `v0.3.1.zip`의 소스 **그대로를 기초**로 변경했다.
- 기존 커널 ABI v1의 EventType 1~5, IOCTL/구조체 크기를 변경하지 않았다.
  커널 v0.8.0의 이벤트와 호환된다.
- 기존 `Ransom0_UI`, `Ransom0_Firewall` 네임드 파이프 및 별도 방화벽
  데몬의 요청 형식을 변경하지 않았다.
- 기존 `events` outbox 테이블을 변경하지 않고,
  `--live-track-b` 사용 시에만 `live_response_attempts` 테이블을 추가한다.
  최신 DB는 복사/백업한 뒤 한 프로세스에서 사용한다.

## v0.4.0 실제 변경

| 부분 | 이전 | 현재 |
|---|---|---|
| Track A 사전 차단 | `kernel_event`에 혼재 | `track_a_command_preempted`로 별도 감사 이벤트. 실제 자식 프로세스 생성 거부이며 부모 kill 아님 |
| 간접 PowerShell VSS 위험 | 일반 프로세스 감사 이벤트에만 기록 | 규칙 1009의 `track_a_command_audit_only` 별도 기록 (자동 차단·kill 없음) |
| Track B 중복 응답 | 메모리 LRU 2,048개만 기억 | 동일 PID+커널 생성 FILETIME에 대한 SQLite 영속 예약으로 재시작 후 중복 자동 대응 차단 |
| 응답 중 크래시 | 재시작 시 중복 요청 가능 | `RESERVED` 사건을 남기고 자동 재시도 금지·수동 검토 필요 |
| 복구 대상 목록 | 운영자가 정적으로 작성 | 저장된 관측 데이터를 근거로 **검토용 후보** 자동 추출; 쓰기 성공/악성은 미확정 |

실행 흐름은 기존 `--live-track-b`의
`전체 PC outbound 차단 요청 → JEV 판정 → PID 생성시간 검사 후 종료 → 승인된 VSS 복구 → 안전 시 해제`
코드를 유지한다. 기존 임계값은 보정되지 않은 데모 설정이다.

## 복구 후보 제안 명령 (읽기 전용, 인터넷/방화벽/파일 변경 없음)

1. v0.4.0을 설치한 다음 정상 관측 `observe`로 이벤트를 기록한다.
2. `kernel_event`의 `process_create_time`에서 **실제 관측된 해당 PID 세대**를 확인한다.
3. 다음의 PID·생성시간·승인 경로를 실제 값으로 바꿔 실행한다.

```powershell
cd C:\RG_Test\v0.4.0
.\.venv\Scripts\python.exe -m ransomguard propose-recovery `
  --db "C:\ProgramData\RansomGuard\events.sqlite3" `
  --pid <검증한_PID> --create-time <정확한_커널_FILETIME> `
  --path-prefix "\Device\HarddiskVolume3\RG_Test" `
  --output "C:\RG_Test\proposed_recovery.json"
```

위 명령은 **라이브 사고 대응이나 복구 명령이 아니다**. 결과 JSON의
`manifest`는 기존 승인 템플릿에 넣을 *수 있는* 후보일 뿐이다.
`file_damage_confirmed=false`, `auto_restore_authorized=false`,
`complete_event_coverage=false`는 항상 유지된다. 정상 변경이나 실패한
쓰기 시도도 포함될 수 있으므로, 스냅샷·피해 시각·대상 파일을
확인한 뒤 기존 `respond-one --recovery-plan` 절차에서 따로 승인해야 한다.

동일 PID가 재사용됐을 때 다른 세대의 경로를 합치지 않으며,
프로세스 생성 이벤트를 놓치면 후보를 추측하지 않는다.
rename은 최종 파일 경로를 알 수 없어 복구 매니페스트에 자동 포함하지 않는다.
최대 파일 수를 초과하면 불완전한 목록을 내는 대신 오류를 낸다.

관측 프로그램 재시작 후 처리 중단된 사고 여부는 아래 명령으로
**읽기 전용** 확인한다. `RESERVED` 항목은 중도 종료됐을 수 있으므로
자동 재시도하지 않고 방화벽 데몬 상태와 프로세스·복구 상태를 직접 확인한다.

```powershell
.\.venv\Scripts\python.exe -m ransomguard response-status `
  --db "C:\ProgramData\RansomGuard\events.sqlite3"
```

## 기존 테스트와 미완료 항목

- Python 테스트 **200/200 통과**: 기존 189개 + v0.4.0 신규 11개.
- 코드 단위로 실제 파일 시스템/방화벽/프로세스를 변경하는 테스트 없음.
- Windows VM에서 v0.4.0 새 wheel 설치 후 
  `python -m ransomguard capabilities`, `observe --limit 20`,
  `propose-recovery`를 **무해한 테스트 폴더**부터 재검증할 것.
- 실제 JEV 호출/전역 WFP 차단/프로세스 종료/VSS 복구 종단 시험은
  여전히 별도 필요하다.
- **중요 미완료:** 미니필터 PRE-OP는 쓰기 성공을 증명하지 않음;
  파일 쓰기 자체를 hold하는 기능 없음; 복구 후보가 실제 피해인지
  자동 확정할 수 없음; 자동 Track A 부모 kill은 구현하지 않음;
  v0.4.0 observer의 실시간 응답은 여전히 동기식이라 외부 호출 중
  드라이버 큐에 이벤트가 쌓일 수 있음.
- **다음 협업 작업:** 커널 후속 버전에서 파일 쓰기 억제 및 post-op
  결과/프로세스 생성시간 ABI를 안전하게 제공하고, 분석엔진에서는
  종료 후 검사와 매니페스트 자동 검증을 통합한다.

## 보안 기본값

기본 `observe`는 항상 관측만 한다. `--live-track-b`,
`--authorize-live`, `--confirm-isolated-vm`, 승인 경로·복구 매니페스트
설정을 갖춰야만 실제 PC 전체 차단이 가능하다. 방화벽 데몬의 ACK는
WFP 필터 적용의 실제 검증이 아니며, 애매하거나 오류가 난 응답의
네트워크 차단은 수동 검토 전 자동 해제하지 않는다.
