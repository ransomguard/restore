# 실제 VSS 생성과 1시간 간격 제한

## 구현한 기능과 VM에서 확인할 부분

`ransomguard/snapshots.py`는 Windows의 실제 `Win32_ShadowCopy.Create`를 호출한다. WMIC 실행 파일은 사용하지 않는다. Windows 시스템 디렉터리의 PowerShell에 고정 스크립트를 전달하고, 볼륨 GUID는 표준 입력 JSON으로 전달한다. 관리자 권한을 확인하며 `shell=True`나 입력값을 붙여 만든 명령문을 사용하지 않는다.

생성 결과는 `ReturnValue == 0`만으로 성공으로 처리하지 않는다. 반환된 ShadowID, 조회한 사본의 ID·볼륨 GUID·장치 경로·생성 시각까지 확인해야 `status=created`를 반환한다. 생성 시각은 시도 시각부터 확인 시각까지에 5초의 시각 정밀도 여유를 더한 범위를 검사한다. 실제 Windows 공급자·권한·디스크 여유 공간·PowerShell 실행 정책에서의 성공은 대상 VM에서 확인해야 한다. 오프라인 시험 통과가 Windows VSS 실증을 대신하지는 않는다.

사용하는 컨텍스트는 원본과 같은 `ClientAccessible`이다. 애플리케이션 writer가 참여한 데이터베이스 일관성까지 보장한다고 해석하지 않는다. 사본 삭제나 용량 확보를 위한 자동 정리는 구현하지 않는다. 생성 실패를 반환하고 보존 정책은 별도로 정한다.

Microsoft 공식 근거: [Win32_ShadowCopy.Create의 Volume·Context·ShadowID·반환 코드](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/create-method-in-class-win32-shadowcopy), [Invoke-CimMethod의 로컬 CIM 정적 메서드 호출](https://learn.microsoft.com/en-us/powershell/module/cimcmdlets/invoke-cimmethod), [VSS 스냅샷 컨텍스트와 writer 참여](https://learn.microsoft.com/en-us/windows/win32/api/vss/ne-vss-vss_snapshot_context).

## 시간당 1회 정책

생성 계기는 `hourly_schedule` 하나다. 탐지·JEV·복구·프로그램 시작·설치 시 생성하지 않는다. import와 객체 생성도 사본을 만들지 않는다. 예약 작업 설치는 첫 다음 정각부터 실행하며, 놓친 시각을 연속 생성으로 보충하지 않는다.

모든 생성 진입점은 **동일한 SQLite 상태 파일**을 사용해야 한다. 기본 위치는 `%ProgramData%\RansomGuard\snapshots.sqlite3`이다. 원본의 호환 함수도 이 파일과 같은 제한을 사용한다. 상태 파일은 로컬 디스크의 관리자 관리 경로에 두며, 다른 파일로 바꾸거나 삭제하면 이전 시도 기록도 사라지므로 재설정 수단으로 사용하면 안 된다.

볼륨 GUID별로 `BEGIN IMMEDIATE` 트랜잭션에서 먼저 생성 시도를 기록하고 커밋한 다음 VSS를 호출한다. 드라이브 문자 별칭, 동시 실행, 정상 재시작에도 같은 볼륨은 마지막 **시도**부터 3600초 전에는 다시 호출하지 않는다. 실패한 시도도 시간을 소비한다. 시계가 뒤로 이동하면 생성을 보류한다. 시스템 시계는 신뢰 가능한 상태로 유지해야 한다.

정각 예약이 실행 지연으로 늦게 시작하면 다음 정각에는 아직 3600초가 지나지 않았을 수 있다. 모듈은 `status=skipped`, `reason=hourly_cooldown`, 정확한 `next_eligible_at`을 반환한다. 상위 예약 호출부가 짧은 지연 후 미시도 예약을 다시 확인할 수 있지만, VSS가 이미 시도된 실패·불명 상태를 재시도하면 안 된다. 장시간 지연되거나 빠진 회차는 다음 예약으로 넘어갈 수 있으며, 생성 횟수를 맞추기 위해 몰아서 실행하지 않는다.

## 시간 초과와 중단

PowerShell 시간 초과는 VSS 공급자 작업이 실제로 끝났다는 증거가 아니다. `unknown`으로 기록하고, 프로세스 중단으로 남은 `in_progress`와 함께 **1시간이 지나도 다음 생성을 막는다**. 성공한 사본이 존재하는지 확인하고 이전 작업이 종료되었는지를 확인한 뒤에만 명시적으로 정리한다.

```python
coordinator.reconcile(
    "C:\\", operation_finished=True,
    snapshot_id="{확인한 실제 사본 GUID}",
)
# 생성되지 않았고 이전 작업도 종료됐음을 실제 확인한 경우만:
coordinator.reconcile(
    "C:\\", operation_finished=True, confirm_no_snapshot=True,
)
```

정리는 사본을 생성·삭제하지 않으며 원래 시도의 3600초 제한을 유지한다. 원래 작업이 ID를 반환했다면 다른 사본 ID로 대체할 수 없다. 불확실하다는 이유만으로 `confirm_no_snapshot=True`를 사용하지 않는다.

CLI에서는 예약 작업에 지정한 것과 동일한 상태 DB와 로그 DB 경로를 사용한다. 아래 변수에 그 경로를 지정하고, 실제 확인한 ID를 넣는다. 이 명령도 생성 명령이 아니라 이전 결과를 확인하는 명령이다.

```powershell
python -m ransomguard snapshot-reconcile --config .\config\example.json `
  --state-db $RansomGuardStateDb --db $RansomGuardOutboxDb `
  --operation-finished --snapshot-id '{확인한 실제 사본 GUID}'
```

확인 결과 사본이 없을 때만 `--snapshot-id` 대신 `--confirm-no-snapshot`을 쓴다. `--operation-finished`는 프로그램이 작업 종료를 검증했다는 표시가 아니라 운영자가 실제 확인했다는 진술이다. 호환 생성 스크립트도 결과 불명 또는 미확인 이전 작업으로 보류한 경우 종료 코드 2를 반환한다.

## 원본 API 호환 범위

| 원본 API | 현재 동작 |
|---|---|
| `create_snapshot.check_admin()` | 관리자 권한 확인, 실패 시 종료 |
| `create_vss_snapshot("C:")` | 동일한 시간 제한을 거친 명시적 생성 호출. 실제 생성·검증에 성공한 경우만 `True` |
| `VssRecoveryEngine.create_snapshot()` | 같은 생성 경로. 반환형은 문자열 유지, 내용은 상태를 명시한 JSON |
| `get_latest_shadow_volume()` | 정확한 볼륨의 기존 사본만 조회. 사본을 만들지 않음 |
| `recover(...)` | 파일별 검증 복구. 모두 성공하면 기존처럼 `None`, 일부 실패도 예외 발생 |
| `recover_async(..., callback=...)` | `Thread` 반환, 콜백은 `success, error` |
| `recover_executor(..., callback=...)` | `Future` 반환, 모두 검증된 성공만 결과 `True` |

호환 생성 함수는 예약 호출용이며, 복구·시작 코드에 넣지 않는다. `create_snapshot.py`를 단독 실행해도 `--scheduled` 없이는 생성하지 않는다. 문자열 `ReturnValue = 0;`을 검사하던 호출부는 JSON의 `status`를 사용하도록 변경해야 한다. `skipped`는 신규 생성 성공이 아니다.

복구 쓰기는 `allow_live=True, containment_confirmed=True`를 명시해야 한다. 자동 사건 대응에는 실제 사건 시작 시각과 피해 파일 목록을 전달한다. 시각을 생략한 기존 수동 실험 API는 호출 시각 이전 최신 사본을 사용하므로, 자동 대응의 사건 시각을 대신할 수 없다.

`containment_confirmed=True`는 호출자가 실제 쓰기 중단을 확인했다는 조건이지 이 호환 모듈이 프로세스를 종료하거나 중단했다는 증거가 아니다. 사용자가 이미 성공시킨 메모장 파일 변경 후 복원 실험은 실제 기능 시험이며, 같은 실험을 기존 사본과 명시적 복구 인수로 계속 수행할 수 있다. 커널 자동 탐지·차단까지 시험한 것으로 확대하지 않는다.

`mount_point` 인수는 기존 호출 호환을 위해 받지만 사용하거나 삭제하지 않는다. 원본 위치와 관계없는 폴더로의 복사는 허용하지 않는다. `manifest`를 생략한 수동 폴더 복구는 선택한 사본의 해당 폴더를 검사하여 파일 목록을 만들고 하나씩 복구한다. 이 모드는 정상 변경도 과거 내용으로 바꿀 수 있으므로 자동 사건 처리에는 명시적인 피해 목록을 사용한다. 추가 암호화 파일·미지정 파일은 삭제하지 않는다.

전체 복구 결과는 `last_recovery_result`에서 확인한다. 파일 내용 일치는 확인하지만, ACL/ADS/EFS·reparse 복구, 악성코드 제거, 전체 manifest의 단일 트랜잭션은 보장하지 않는다. 파일별 staging은 복구 중 교체를 위한 것으로, 매 쓰기마다 원본을 별도 저장하는 백업 기능이 아니다.

## 오프라인 검증

`python -m unittest discover -s tests -p test_snapshots.py -v`로 확인한다. 실제 SQLite에서 동시 예약·재시작·시간 제한·불명 결과를 검사하고, 임시 디렉터리에서 실제 파일 복사·교체 및 호환 비동기 API를 검사한다. Windows 관리자 검사와 PowerShell/CIM 생성 응답은 모의 처리하며 실제 VSS/API 요청은 하지 않는다.
