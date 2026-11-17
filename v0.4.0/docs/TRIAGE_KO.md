# 고엔트로피 관측을 Track B 후보로 연결하는 intake

`ransomguard/triage.py`는 커널 파일 이벤트를 받아 **고엔트로피 쓰기 관측을 Track B 후보로 분류**한다. 플래그를 로그에만 남기는 단계에서 사용자 모드의 명시적인 후보/보류 레코드 생성으로 연결한 것이다.

이 모듈은 모의 커널 이벤트에도, Windows 관측기가 디코딩한 실제 이벤트에도 같은 API로 사용할 수 있다. Windows 드라이버의 실행 검증이 완료됐다는 의미는 아니다. 커널 ABI와 고엔트로피 계산 기준은 변경하지 않는다.

## 판정과 실행의 경계

- `FILE_FLAG_HIGH_ENTROPY`가 설정된 **write 이벤트 한 건**이면 Track B 대상으로 분류한다. 여러 번의 고엔트로피 관측도 이 모듈에서 Track A로 승격하지 않는다.
- 수명 이벤트로 상관관계가 확인되면 `track_b_candidate`를 만든다. PID 생성 시각이 없거나 수명 정보가 무효화됐으면 `track_b_deferred`를 만든다.
- 두 종류 모두 `track="B"`, `identity_authorization=false`, `complete_event_coverage=false`다. 파일 ABI에는 프로세스 생성 시간이 없으므로 상관관계만으로 종료·복구 등을 승인하지 않는다.
- 후보 생성은 네트워크 격리, 파일 쓰기 제한, JEV 질의, 종료, 복구가 아니다. 해당 실행 기능을 호출하지 않으며 `containment_confirmed`, `jev_requested`, `termination_requested`, `restore_requested`, `automatic_response`는 모두 `false`다.
- 라이브 대응으로 이어가려면 프로세스 실제 신원과 격리 적용을 확인하는 실행 계층이 필요하다. 후보를 만들었다는 이유로 보호·격리 완료로 표시하면 안 된다.

## 통합 API

```python
from ransomguard.protocol import ProcessRegistry
from ransomguard.triage import TriageConfig, TriageIntake

registry = ProcessRegistry()
triage = TriageIntake(TriageConfig())

# lifecycle 이벤트도 빠짐없이 이 경로에 넣는다.
registry.update(event)
for record in triage.ingest(
    event,
    correlated_create_time=registry.generation_for(event.pid),
):
    outbox.append(record.kind, record.payload)
```

원본 `kernel_event`도 별도로 기록한다. 프로토콜 디코딩 오류, 드라이버 유실 카운터 증가, 연결 재수립처럼 수명 정보가 불완전해지는 경계에서는 다음 레코드를 기록한다.

```python
record = triage.reset(reason="driver_drop_counter_increased")
outbox.append(record.kind, record.payload)
```

`reset()`은 내부 수명·집계·쿨다운을 모두 비운다. 외부 `ProcessRegistry`에 오래된 PID 생성 시각이 남아 있어도 새 process-create 관측 없이는 후보의 신원을 확인된 것으로 되살리지 않는다. 이벤트 sequence의 공백·중복·역전도 같은 무효화를 자동 수행한다. sequence가 연속이라고 관측이 완전하다는 뜻은 아니므로 발신 측 유실도 별도로 처리해야 한다.

## 집계와 제한

다음 값은 초기 구현 기본값이며, 악성 확정 임계값이나 사용자 환경에서 보정된 성능 값이 아니다.

| 설정 | 기본값 | 의미 |
| --- | ---: | --- |
| `window_seconds` | 10초 | 수신한 write/rename/고엔트로피 write를 집계하는 창 |
| `cooldown_seconds` | 30초 | 같은 유지 중인 프로세스 instance의 후보 재발행 간격 |
| `max_processes` | 1024 | 수명 정보와 파일 집계가 들어가는 전체 PID 상태 수 상한 |
| `max_events_per_process` | 256 | 프로세스별 보관하는 관측 수 상한 |
| `max_paths_per_process` | 8 | 프로세스별 최근 원본 경로 예시 수 상한 |

시간 창과 쿨다운은 `time.monotonic()`의 **수신 시점** 기준이다. 커널의 FILETIME이나 시스템 시계 변경으로 재발행 시점이 달라지지 않는다. 따라서 큐에서 지연되어 전달된 관측의 실제 발생 시간 간격과 동일하다고 해석하면 안 된다.

쿨다운 안에서도 관측과 횟수는 갱신한다. 새 후보 레코드만 억제하며, `stats()`와 다음 후보의 `suppressed_since_last_emit`에 억제 수를 남긴다. 신원 미확정 상태의 반복 신호도 PID 단위로 제한한다. process-create, 해당 instance의 종료, 수명 상관관계 소실은 이전 집계와 쿨다운을 제거한다. 다른 생성 시각의 프로세스로 이전 횟수를 넘기지 않는다.

관측 수 상한 때문에 시간 창 안의 데이터를 버리면 `window_truncated_by_capacity=true`를 기록한다. `counts_scope="retained_observations_in_window"`인 횟수는 보관 중인 관측의 횟수이며 전체 파일 변경 수가 아니다. 예시 경로 역시 전체 피해 파일 목록이 아니다. 경로는 최대 1024문자로 제한하고, rename의 경로는 변경 전 경로다. 최종 변경 성공이나 새 전체 경로를 추정하지 않는다.

전체 PID 상태 상한에 도달하면 최근에 사용하지 않은 상태를 제거하고 `triage_state_evicted`를 남긴다. 이때 해당 수명 정보와 쿨다운도 잃으므로, 이후에는 새 수명 관측 전까지 신원 보류 상태가 된다. 관측기 시작 전 실행된 프로세스, 유실 이후 계속 실행 중인 프로세스의 신원을 별도 OS 조회로 복원하는 기능은 이 모듈에 포함되지 않는다.

## 레코드와 검증

| 레코드 | 의미 |
| --- | --- |
| `track_b_candidate` | 고엔트로피 쓰기 증거와 수명 상관관계가 있는 Track B 후보 |
| `track_b_deferred` | 고엔트로피 쓰기는 보였으나 프로세스 instance 신원이 미확정 |
| `triage_reset` | sequence 이상 또는 호출자가 알린 관측 유실로 모든 내부 상태 무효화 |
| `triage_identity_reset` | 특정 PID의 수명 변경·종료·상관관계 소실로 이전 상태 무효화 |
| `triage_state_evicted` | 메모리 상한으로 특정 PID의 내부 상태 제거 |

후보에는 고유 `candidate_id`, PID·상관 생성 시각, 원본 sequence·FILETIME, 근거 코드, 창 안의 관측 횟수, 일부 경로와 플래그, 대응 미실행 상태가 포함된다. 내부 상태는 메모리에만 존재한다. outbox에 보존된 레코드와 실행 중인 triage 상태의 영속성은 별개다.

`tests/test_triage.py`는 단일 신호의 Track B 라우팅, 신호 반복 시 재발행 제한, 창 만료, rename 맥락 집계, PID 재사용, 종료, 신원 누락, sequence·외부 유실 초기화, 상태·경로·관측 상한, 고엔트로피만으로 Track A 승격 금지, 잘못된 시간 설정을 검증한다. 이 테스트는 실제 JEV·WFP·파일 차단·Windows 드라이버 동작 검증을 대신하지 않는다.
