# 사용자 모드 모듈과 대시보드 연결

## CLI 범위

| 명령 | 효과 |
| --- | --- |
| capabilities | 구현/미구현 상태 출력 |
| replay | 모의 사건과 로컬 로그 |
| observe | Windows 드라이버 이벤트와 고엔트로피 Track B 후보/보류의 로컬 저장 |
| export-events | SQLite 로그를 JSONL로 내보내기 |
| send-events | 지정 HTTPS 서버로 실제 로그 한 묶음 전송 |
| plan-network | 계획 출력. --resolve만 실제 DNS 조회 |
| snapshot-inventory | Windows 지정 볼륨의 기존 VSS 조회 |
| snapshot-run | 공통 영속 시간 제한을 거친 실제 Windows VSS 생성 시도 |
| snapshot-task | 다음 정시부터 1시간 주기의 작업 XML 생성; 설치/생성은 하지 않음 |
| snapshot-reconcile | 기존 생성 시도가 끝났는지 확인한 후 불명확한 결과의 기록 정리 |

observe에서 JEV·복구를 자동 실행하는 루프는 없다. 불완전한 관측을 악성 확정이나 복구 대상 목록으로 쓰지 않도록 단계별 연결을 남겨두었다.

## JEV API

SDK는 호출할 때 로드한다. 아래 evaluate는 실제 API에 데이터를 전송한다. 키는 실행 환경의 TYPESAFE_API_KEY로 공급한다.

~~~python
from ransomguard.jev import JevClient, JevConfig

client = JevClient(JevConfig(
    base_url="https://api.typesafe.ai",
    model="jev-latest",
    timeout_seconds=10,
    max_retries=0,
))
# 합성 예시이며 실제 탐지 증거나 운영 판정 기준이 아니다.
result = client.evaluate({
    "source": "manual_lab_example",
    "time_window_seconds": 5,
    "file_write_attempts": 3,
    "high_entropy_observations": 0,
    "notes": "Harmless synthetic API integration example",
})
print(result)  # score, model, request_id
~~~

SDK timeout과 전체 사건 마감시간은 다르다. 실제 조정기는 사건·요청 ID, 상태 버전, 프로세스 생성 시간, 전체 마감시간을 관리해야 한다. 모의 조정기는 늦은 응답 처리를 검증하지만 실제 비동기 SDK 루프는 아니다.

프롬프트는 텔레메트리를 명령이 아닌 데이터로 다루도록 요청한다. 이 문구만으로 모델 오판이나 입력 오염을 방지한다고 가정하지 않는다. 유효한 점수도 검증한 프로젝트 정책과 연결해야 한다.

## 복구 API

정확한 볼륨, 신뢰할 사건 이전 사본, 명시한 파일 목록을 사용한다. incident_at은 단순 메시지 수신 시각보다 알려진 가장 이른 피해 시점을 기준으로 정해야 한다.

스냅샷 생성 정책은 1시간 간격으로 확정했다. 이 복구 API는 사본을 생성하지 않고 이미 존재하는 사본만 선택한다. 탐지·JEV·복구 시작 시 추가 생성하지 않으며, 적합한 사건 이전 사본이 없으면 select_snapshot이 오류를 반환한다. 조정기는 이를 복구 불가로 기록해야 하며 성공이나 현재 상태의 새 사본으로 대체하면 안 된다. 주기 생성기는 v0.6.1의 `snapshots.py`, `scheduling.py`, `Install-SnapshotTask.ps1`로 구현했다. 설치/첫 실행 확인 절차는 `README.md`를 따른다.

~~~python
from datetime import datetime, timezone
from ransomguard.recovery import (
    RecoveryEngine, enumerate_snapshots, select_snapshot, volume_id_for_root,
)

volume_root = "C:\\"
protected_root = r"C:\RansomGuardLab\Protected"
# 실험에서 기록한 실제 사건 시작 시각으로 대체한다.
incident_at = datetime(2026, 10, 29, 10, 55, tzinfo=timezone.utc)
volume_id = volume_id_for_root(volume_root)
inventory = enumerate_snapshots(volume_id)
snapshot = select_snapshot(
    inventory, volume_id=volume_id, incident_at=incident_at,
    # snapshot_id="{실제 GUID}"를 지정하면 그 사본만 허용한다.
)
engine = RecoveryEngine()
plan = engine.plan(
    snapshot, volume_root=volume_root, protected_root=protected_root,
    manifest=["note.txt", r"subfolder\document.txt"],
    incident_at=incident_at,
)
print(plan.to_dict())  # 아직 복구 쓰기 없음
~~~

실제 복구 API는 engine.execute(plan, allow_live=True, containment_confirmed=True)다. 두 플래그는 호출자의 전제 확인이며 OS 격리를 측정하지 않는다. 현재 자동 조정기는 이 API를 호출하지 않는다. 실제 쓰기 프로세스가 통제된 VM 실험에서 계획을 검토하고 연결해야 한다.

VSS 파일을 직접 읽어 대상 디렉터리의 임시 파일로 저장하고, 해시 확인 후 파일별 교체·재검증을 한다. 전체 작업의 원자성을 보장하지는 않는다.

- verified: 명시한 모든 파일 내용 검증 완료.
- partial: 일부 파일만 검증 완료.
- failed: 검증 완료 파일 없음.
- 목록 밖 파일을 자동으로 덮거나 삭제하지 않는다.
- 상위/절대 경로, ADS, 예약 이름, 중복 경로, 재분석 지점 등을 거부한다.
- ACL·ADS·EFS·전체 시스템 상태는 복원하지 않는다.
- 공격자가 디렉터리를 계속 바꾸는 경합을 경로 검사만으로 제거할 수 없다.

동일 파일 복구 작업 직렬화, 복구 중 사본 삭제·공간 부족·파일 잠금 처리도 운영 정책에 포함해야 한다.

## 대시보드 제안 계약

기존 백엔드 명세가 없어 아래는 **제안 계약**이다. 실제 서버와 호환성은 검증하지 않았다. UI 완성과 로그 수신 API 완성은 별도 확인이 필요하다.

send-events는 최대 100개를 HTTPS POST 한다.

~~~json
{
  "schema_version": 1,
  "events": [
    {
      "schema_version": 1,
      "sequence": 1,
      "event_id": "actual-event-uuid",
      "incident_id": "actual-incident-uuid",
      "occurred_at_utc": "2026-10-29T10:55:00+00:00",
      "event_type": "quarantine_requested",
      "data": {
        "execution_mode": "simulation",
        "track": "B",
        "state": "CONTAINMENT_REQUESTED",
        "state_version": 1,
        "pid": 4100,
        "process_create_time": 133000000000000001,
        "scope": "process"
      }
    }
  ]
}
~~~

서버는 저장이 완료된 ID만 응답한다.

~~~json
{"acknowledged_event_ids": ["actual-event-uuid"]}
~~~

event_id는 중복 제거 키다. HTTP 오류, 리다이렉트, 잘못된 JSON/ACK, 알 수 없는 ID는 미확인 로그를 삭제하지 않는다. 일부 ACK면 나머지는 다음 대상으로 남는다. HTTP 성공만으로 일괄 전달 완료 처리하지 않는다.

sequence는 각 SQLite 파일 내부 순서다. 여러 단말 구분을 위해 인증된 에이전트 신원/agent_id와 정책 버전을 실제 계약에 맞춰 추가해야 한다. 임의 호스트 이름을 인증으로 취급하지 않는다.

모의 사건은 탐지, 격리 요청/적용/실패, JEV 요청/응답/실패, 종료 요청/확인, 복구 시작/검증/실패, 해제 요청/완료, 검토 필요를 기록한다. 모의 데이터는 execution_mode=simulation, 관측은 observation, 실제 스냅샷 작업 로그는 live_snapshot이다. 고엔트로피 후보는 격리 완료가 아니고 requires_reconciliation인 사본 시도는 해결된 성공이 아니다. 대시보드도 이를 구분해야 한다.

실제 계약 확인 후 store 디렉터리에서 다음을 사용할 수 있다.

~~~powershell
python -m ransomguard send-events --db observation.sqlite3 --endpoint https://YOUR-DASHBOARD/api/events
~~~

이 명령은 실제 외부 전송이다. 주소는 승인된 수신 서버로 바꾼다. 토큰은 RANSOMGUARD_DASHBOARD_TOKEN에서 읽는다. 인증 헤더가 다른 목적지로 따라가지 않도록 리다이렉트를 거부한다.

## 중단·보존 한계

SQLite WAL과 개별 ACK는 전달 실패 시 로그를 보존한다. 미확인 이벤트 한도는 기본 100,000개이며 넘으면 기존 이벤트를 버리지 않고 오류로 중단한다. 디스크 고장·삭제를 해결하는 외부 백업은 아니다.

ACK된 이벤트도 현재 DB에 남는다. 장기 보존·용량 정리는 후속 구현이다. 사건 상태·격리 소유권은 메모리에 있으므로 outbox만으로 서비스 재시작 복구가 완성되지 않는다.

관측 IOCTL은 초기 timeout 뒤 취소를 요청하지만 메모리 수명을 지키기 위해 실제 취소 완료까지 기다린다. 고장 난 드라이버에서는 전체 대기가 초기 timeout을 초과할 수 있다.

## v0.6.1 스냅샷 명령 결과

`snapshot-run` 종료 코드 0은 생성 완료 또는 정상적인 시간 제한 skip이다. 1은 실패, 2는 결과 불명확/이전 시도 확인 필요다. `status`, `created`, `reason`을 함께 확인해야 하며 skip을 신규 생성으로 집계하지 않는다. 최초 설치는 다음 정시를 기다린다. 상세 생성/호환 API는 `SNAPSHOTS_KO.md`에 있다.
