# v0.6.1 실제 수행한 검증 — 2026-10-31

## 검증 환경과 결과

검증 환경은 **Linux x86_64 / Python 3.12**다. 실제 Windows VSS, WDK 빌드, 드라이버 로드, JEV 서버, 대시보드 서버를 실행한 결과는 포함하지 않는다.

```text
python -m unittest discover -s tests -v
Ran 135 tests
OK
```

전체 시험 출력은 같은 폴더의 `TEST_RESULTS.txt`에 포함했다. 실패를 확인하는 테스트에서 의도한 오류 로그가 출력되더라도 최종 결과는 위와 같이 135개 통과다.

| 검증 영역 | 실제로 확인한 것 | 대체/미수행 영역 |
| --- | --- | --- |
| 시간당 생성 제한 | 실제 SQLite에서 3600초 경계, 재시작·볼륨 별칭·동시 8개 실행, 생성 실패·시계 역행·상태 저장 실패 | VSS 생성 함수는 주입한 시험 함수 |
| VSS 결과 처리 | 고정 CIM 호출 구성, stdin JSON, 반환 코드·ID·볼륨 검증, 타임아웃·불명 결과·명시적 reconciliation | Windows 관리자 검사와 PowerShell 실행 응답 모의 |
| 작업 스케줄 | XML 단일 미래 시간 트리거·1시간 간격, 시작/로그인/설치/수동 실행·밀린 작업 재시도 없음, 사용자 SID/경로 검증 | Windows 작업 등록·실제 정기 실행 미수행 |
| 일정 지연 처리 | 정상 시간 제한 skip일 때만 최대 60초 대기 후 예약 재검사 1회; 불명 상태 재시도 금지 | 시간 대기는 모의 처리 |
| 파일 복구 | 임시 디렉터리에서 실제 복사·해시·교체, 누락/부분 실패, 경로 이탈·심볼릭 링크 방어, 지정 목록 밖 보존 | Windows VSS 원본 읽기·ACL·ADS·EFS 검증 아님 |
| 기존 진입점 | create bool/JSON 결과, VssRecoveryEngine 동기·Thread·Future·콜백 계약, 복구에서 사본을 만들지 않음 | 원본 WMIC 출력 문자열·무인수 live 복구와 완전한 호출 호환은 아님 |
| 고엔트로피 Track B | 단일 신호 분류, 반복 억제, 시간 창·상한, rename 맥락, PID 재사용·종료·유실 후 보류 | 악성 여부 정확도·Windows 이벤트 누락률 검증 아님 |
| 관측 CLI 통합 | 실제 바이너리 디코더→분류기→SQLite outbox 경로에서 후보 1개 기록, 대응 적용 로그 없음 | 드라이버 전송만 가짜 reader |
| 프로세스 격리 상태 | 같은 instance의 사건 참조, 다른 프로세스/재사용 PID와의 독립성, 실패·해제 순서 | `SimulationEffects`이며 WFP·kill·파일 보호는 실행하지 않음 |
| JEV·대시보드 | 잘못된 점수·요청 ID·ACK·HTTP 오류·재전송 보존 처리 | SDK/HTTP 응답 모의; 실제 서버 연동 미수행 |

## CLI 실행 7개

각 시나리오는 별도 임시 SQLite DB에서 실행했다. 모의 상태 전이가 기대한 결과인지 확인한 시험이다.

| 시나리오 | 결과 |
| --- | --- |
| `benign` | RELEASED, 종료·복구 호출 없음 |
| `malicious` | RELEASED, 모의 종료 확인→복구 검증→해제 |
| `timeout` | REVIEW_REQUIRED, 정상 판정으로 바꾸지 않음 |
| `track-a` | RELEASED, JEV 없이 모의 종료·복구 |
| `shared-process` | 동일 프로세스 사건 하나는 RELEASED, 다른 하나 REVIEW_REQUIRED; 해당 hold 유지 |
| `late-response` | Track A 승격 뒤 늦은 정상 응답 무시 |
| `restore-failure` | REVIEW_REQUIRED, 복구 실패를 성공으로 표시하지 않음 |

`shared-host`는 이전 CLI 이름의 호환 별칭이며 실제 동작은 `shared-process`와 같다. 호스트 전체 차단 기능을 의미하지 않는다.

설정으로 실행한 `plan-network`의 `scope=process`, `network_changed=false`를 확인했다. Linux에서 `snapshot-inventory`는 Windows 필요 오류를 내며 사본을 조회한 것처럼 꾸미지 않는다.

## 설치 패키지 확인

`pip wheel --no-deps --no-build-isolation`로 `ransomguard_integration-0.6.1-py3-none-any.whl`을 만들고 별도 가상환경에 설치했다. 프로젝트 폴더 밖에서 `python -I`로 다음을 확인했다.

- `ransomguard`, `create_snapshot`, `vss_recovery`를 가져올 수 있고 버전은 0.6.1.
- wheel에 `core/jev_client.py`, `snapshots.py`, `triage.py`, `scheduling.py`와 기존 진입점 포함.
- 설치된 `python -I -m ransomguard capabilities` 실행 성공.

선택 의존성의 실제 JEV 연결 성공을 확인한 시험은 아니다. Windows 예약 작업은 동일하게 설치된 Python 인터프리터로 실행하도록 구성했다.

## 커널 검증의 한계

이번 v0.6.1에서 커널 C/C++/헤더/프로젝트 파일은 v0.6.0 기준선과 동일하다. 기존 고엔트로피 플래그를 받는 사용자 모드 연결을 추가했다. 소스·ABI·프로젝트 참조 검토와 코드 비교는 수행했지만 MSVC/WDK 컴파일, INF 검증, 서명, 드라이버 로드와 충돌 시험은 수행하지 않았다.

## 다음 Windows VM 검증

1. 환경 정보 수집과 Python 패키지 설치.
2. 관리자 계정으로 예약 작업 등록 후 첫 정기 VSS 생성의 ID·볼륨·시각·로그 확인.
3. 동일 상태 DB의 중복 생성 억제, 실패 상태, 두 번째 정기 실행 확인.
4. 정기 사본 이후 시험 폴더의 무해한 파일을 수정하고 실제 파일 내용·해시 복구 확인.
5. 커널 빌드·서명·로드 후 실제 이벤트 수신과 고엔트로피 후보/보류 로그 확인.
6. 미구현 WFP/파일 억제/자동 종료 실행 계층을 구현한 뒤 실제 JEV·복구·대시보드까지 통합 시험.

이 결과로 ‘135개 테스트 통과’를 말할 수 있지만 ‘Windows에서 전체 안티 랜섬웨어가 구동·방어에 성공했다’고 말할 수는 없다.
