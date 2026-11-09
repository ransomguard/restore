# restore v0.3.1 — Observer Hotfix 및 실제 JEV 연동 검증

작성: 2026-11-09 (KST) · 저장소: `ransomguard/restore` · 대상: 격리 Windows 11 VM

## 변경 사항

- `v0.3.0` 전체 복구/JEV 소스에 `RansomGuard_v0.3.0_Observer_Hotfix_20261109.zip`의 수정사항을 적용했다.
- `ransomguard/observer_filter.py` 신규: Observer 프로세스 **자신의 PID**가 정확히 자신의 SQLite outbox DB, `-wal`, `-shm`, `-journal`에 접근하는 파일 이벤트만 구분한다. DOS/NT 경로를 대응하며 일반 파일 쓰기와 다른 PID의 DB 쓰기는 유지한다.
- `ransomguard/cli.py`, `ransomguard/triage.py`: 필터 적용, 시퀀스 일관성 유지, 종료 시 관측·저장 카운터 수집 경로를 반영했다.
- `tests/test_observer_filter.py`, `tests/test_cli_integration.py` 및 `tools/observer_hotfix_check.py`: 회귀 테스트·검증 도구 포함.
- `pyproject.toml`, `ransomguard/__init__.py`, `capabilities.version`: `0.3.1` 표기. 커널 ABI v1은 그대로다.

## Windows 11 VM에서 확인된 범위 (2026-11-09)

1. QueueFix 메인 드라이버와 미니필터가 `RUNNING`, 실제 이벤트 수집 확인.
2. SQLite DB `observe_trackb_sync_20261109.sqlite3`에 실제 `kernel_event` 473건 및 `track_b_candidate` 1건 저장 확인.
3. 후보의 커널 시퀀스 `2421`을 **수동** `JevClient.evaluate()`로 실서비스에 전송하여 `jev-1.14.0`, `score=0.21`, `request_id` 수신 확인. 재현 과정에서 사용한 파일 쓰기는 악성코드가 아닌 합성 실험 데이터지만 이벤트 자체는 실제 커널 관측값이다.
4. `tests/test_live_response.py`: 모의 드라이버/방화벽/JEV로 11/11 통과. 실제 방화벽 차단·커널 종료·VSS 복구가 수행됐다는 의미는 아니다.
5. 실제 API 통신을 위해 임시 NAT 연결 후 테스트 종료 시 VM 네트워크를 다시 `Disconnected`로 복원했다.

## 현재 한계와 안전 정책

- 임시 판정 문턱값 `benign <=0.20`, `malicious >=0.80`; `0.21`은 애매함(`REVIEW_REQUIRED`)이다. 임계값은 아직 검증되지 않은 **시연값**이다.
- live 코드의 네트워크 격리는 `host_outbound` **PC 전체 차단**이고, 의도한 PID/프로세스별 격리가 구현된 것으로 주장할 수 없다. 애매한 점수에서는 전체 차단이 유지될 수 있으므로 `--live-track-b`, `--authorize-live`, `respond-one`은 검증 전 실행하지 않는다.
- `observer_stopped`에 새 저장/필터링 카운터가 모두 표시되는지는 실측 근거가 충분하지 않다. 추가 시험 필요.
- 1시간 VSS 스케줄 작업은 VM에서 `NOT_INSTALLED`로 확인됐다. VSS snapshot-inventory는 별개로 확인했다.
- 프로젝트 소스·실험 기록에 API 키나 private key를 넣지 않는다. JEV 실통신 시 `TYPESAFE_API_KEY`는 해당 PowerShell **프로세스 환경 변수**로만 전달한다.
- 이번 변경은 JEV 클라이언트의 네트워크/종료/복구 호출을 새로 켜지 않는다. 외부 `firewall-manager`와 UI IPC receiver 저장소는 수정하지 않는다.

## 설치 및 검증 (기존 폴더는 유지)

### 새 버전의 로컬 검사

- 2026-11-09 Linux: `python3 -m unittest discover -s tests` → **189/189 PASS**. 포함된 모의 응답 테스트는 실제 WFP나 VSS 검증을 대체하지 않는다.
- `python3 -m pip wheel --no-index --no-deps --no-build-isolation . -w dist`로 **`ransomguard_integration-0.3.1-py3-none-any.whl`** 생성 확인. `observer_filter.py` 포함 확인.

새 폴더 `C:\RG_Test\v0.3.1`에 압축 해제하고 기존 데이터베이스·`.venv`·스크립트·VM 스냅샷을 삭제하지 않는다. 새로운 버전 소스 또는 동봉된 `0.3.1` wheel을 사용하는 경우 다음을 실행한다.

```powershell
cd C:\RG_Test\v0.3.1
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --no-deps .\dist\ransomguard_integration-0.3.1-py3-none-any.whl
.\.venv\Scripts\python.exe -m ransomguard capabilities
.\.venv\Scripts\python.exe -m unittest discover -s .\tests -v
```

`capabilities.version`은 `0.3.1`, 커널 호환성은 `v0.7.0-rc2/v0.7.1 ABI v1`로 표시된다. 기존 VM의 `0.3.0`을 지우거나 덮어쓰지 않는다. **사용자가 새 바이너리/패키지로 자동 대응을 시험한 것이 아니므로** 위의 실행은 새로운 검증 단계다.
