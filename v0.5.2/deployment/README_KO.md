> 현재 버전은 v0.5.2입니다. 통합 EXE 및 현재 제한사항은 상위 RELEASE_V0.5.2_KO.md를 먼저 확인하세요. 아래는 기존 소스 직접 설치 경로입니다.

# RansomGuard 네 구성요소 통합 실행 — v0.5.0

이 배포는 **통합 소스 개발판**입니다. 네 저장소를 받는 것만으로 서명된 백신이 설치되지는 않습니다.
구성요소를 빌드·설치한 다음 아래 설정 도구에 실행 파일 경로를 지정하면 파이프와 상태 DB를 함께 연결합니다.
설정 도구는 드라이버·방화벽·예약 작업·프로그램을 실행하지 않으며 암호나 네트워크를 변경하지 않습니다.

## 받을 버전

- `ransomguard/Kernel`: `v0.9.0/`
- `ransomguard/restore`: 현재 `v0.5.0/`
- `ransomguard/ui`, `ransomguard/firewall-manager`: `components.lock.json`에 기록한 정확한 커밋

UI/방화벽 후속 PR이 main에 병합되기 전에는 main ZIP에 이번 변경이 없습니다.
`components.lock.json`의 `archive` 링크로 받거나 `git checkout <commit>`으로 고정하세요.
restore 저장소의 과거 버전 전체를 설치할 필요는 없습니다.

## 연결 구조

```text
Windows 커널 드라이버 ─ IOCTL ─ Python 수집/분석/복구
                                  ├─ SQLite outbox/응답 ledger
                                  ├─ 로컬 파이프 Ransom0_UI ─ Electron ─ UI SQLite
                                  ├─ 로컬 파이프 Ransom0_Firewall ─ WFP 데몬
                                  └─ JevBridge ─ HTTPS ─ 실제 JEV
```

UI·Python·방화벽 데몬은 **같은 Windows VM**에서 실행합니다. UI는 호스트 웹 서버나 URL API에 의존하지 않습니다.
원본 outbox와 화면 기록 DB는 별개이며, 전달/처리가 끝난 원본만 정리합니다. 분석·검토·복구 실패 사건은 남깁니다.

## 빌드 준비

인터넷이 필요한 개발 도구/의존성 준비는 개발 PC에서 하고 결과물을 시험 VM으로 옮길 수 있습니다.
이 가이드는 VM의 전체 인터넷 연결을 켜도록 요구하지 않습니다.

1. **Kernel:** Windows x64, VS/MSVC와 프로젝트에 맞는 SDK/WDK로 `v0.9.0/RansomGuard.sln` 빌드.
   [커널 빌드 안내](https://github.com/ransomguard/Kernel/blob/main/v0.9.0/BUILD_NOTES.md)를 참고해 시험 VM에 서명/설치합니다.
   서비스 이름은 `Anti_Ransom_Driver`, `Anti_Ransom_FsFilter`입니다. 시험 인증서/개인 키는 배포하지 않습니다.
2. **UI:** 해당 커밋에서 `bun install --frozen-lockfile`, `bun run build`.
   빌드 결과의 `ransom0-ui.exe`와 **전체 앱 폴더**를 VM에 배치하거나 생성된 설치 파일로 설치합니다.
   exe 하나만 복사하면 Electron 리소스가 빠집니다.
3. **방화벽:** 저장소 루트에서 `cmake -S . -B build -A x64`, `cmake --build build --config Release`로
   빌드한 `bin/r0-fw-daemon.exe`를 배치합니다. Windows C++ 빌드 도구가 필요합니다.
4. **복구:** VM에 Python 3.10 이상과 `v0.5.0` 폴더 전체를 배치합니다.
   폴더 안에서 `py -3 -m venv .venv`를 실행합니다. 핵심 코드에는 추가 pip 의존성이 없으며 시작 도구가 소스 폴더를 작업 경로로 사용합니다.
   `config/`, `ransomguard/`, `core/`, `integration/`을 생략하지 마세요.

## 경로 지정과 실행

다음은 **새 시험 VM** 예시입니다. 경로는 자신의 배치 위치로 바꿉니다.
이미 쓰던 VM의 DB 경로를 바꿔 새 DB로 시작하면 기록/hold가 분리되므로 이 도구를 기존 VM 업그레이드 용도로 쓰지 마세요.

```powershell
Set-Location 'C:\RansomGuard\restore\v0.5.0'
py -3 -m venv .venv
& .\.venv\Scripts\python.exe .\deployment\configure.py `
  --runtime 'C:\RansomGuard\runtime' `
  --python 'C:\RansomGuard\restore\v0.5.0\.venv\Scripts\python.exe' `
  --ui 'C:\RansomGuard\dashboard\ransom0-ui.exe' `
  --firewall 'C:\RansomGuard\firewall\r0-fw-daemon.exe' --check
# 검사에 통과하면 위 명령의 --check만 빼고 실행합니다.
```

설정 이후 **VM 안의 로그인된 사용자 관리자 PowerShell**에서:

```powershell
& 'C:\RansomGuard\runtime\Start-RansomGuard.ps1'
```

시작 도구가 메인 드라이버 → 방화벽 데몬/UI → 수집기 준비 확인 → 파일 필터 순서로 실행합니다.
`runtime.json`, `observer-ready.json`, `*.stderr.log`로 결과를 확인하세요.
UI는 동일한 `holds.sqlite3` 경로를 환경 변수로 전달받아 대응 중 정책 변경을 조정합니다.

기본 상태는 **observe-only + test 표시**입니다. 기본 설정만으로 자동 강제 종료/복구가 켜지지 않습니다.
시험 표시를 제거해 제품 판정으로 둔갑시키지 않습니다.

수동 실행 성공 후 필요하면 `runtime\Install-RansomGuardSupervisor.ps1`을 관리자 권한으로 실행해
로그온 시작/상태 확인 작업을 등록할 수 있습니다. 기존 같은 이름의 작업은 덮어쓰지 않습니다.
이 작업은 **사용자 로그온 이후**에 실행하며, Windows 자동 로그인이나 암호 설정은 변경하지 않습니다.
이번 새 경로 설정 도구/작업 등록 템플릿은 로컬 검사 대상이며 다른 PC의 첫 설치까지 실증한 것은 아닙니다.

## 실제 JEV와 자동 대응

- JEV 키는 각자 준비합니다. 소스/명령 인자/커밋에 넣지 않습니다.
- `integration/windows/JevBridge.cs`를 대상 환경에 빌드하고 `--import-key`의 표준 입력으로 비공개 등록합니다.
  DPAPI 키 파일은 머신에 묶이므로 기존 PC/VM의 파일을 다른 Windows 설치로 복사해 재사용하지 않습니다.
- `runtime/jev-transport.json` 형식은
  `{"endpoint":"https://api.typesafe.ai","bridge":"C:\\RansomGuard\\JevBridge\\JevBridge.exe"}`입니다.
- 네트워크 예외는 해당 브리지의 JEV HTTPS 전송에만 한정하는 별도 배포 정책이 필요합니다.
  방화벽 데몬의 도메인 허용만으로 모든 프로그램의 통신이 JEV API로 한정되는 것은 아닙니다.
  기본 설치 도구는 JEV 예외를 열지 않습니다. 기존 VM의 IP·MAC·호스트 경로가 들어 있는 네트워크 절차는 배포에서 제외했습니다.
- `ransomguard/live_profile.py`의 검증을 통과하는 **유한 승인 NT 경로, 복구 manifest, 사건 이전 VSS**를 준비한 뒤
  `runtime/live-response-profile.json`으로 명시적으로 활성화합니다. 기존 VM의 snapshot ID/manifest/시험 경로를 복사하지 마세요.
- JEV 0.2/0.8 임계값은 보정 전 시험 값입니다. 대표 정상/악성 자료의 오탐·미탐 평가와 장시간 검증은 별도 작업입니다.

## 기존 설치 업데이트

현재 수집기가 실행 중일 때 이 설정 도구로 실행 파일/경로/DB를 덮어쓰지 마세요.
기존 runtime·UI DB·hold·카운터를 보존하고, 사용자 모드 변경은 `ransomguard/resident.py`의 준비 확인/인계 절차,
드라이버 변경은 `ransomguard/driver_upgrade.py`의 정지·drain·계수/coverage gap 기록 절차로 수행합니다.
다운로드 도구와 첫 설치 설정 도구는 무중단 업그레이드 도구가 아닙니다.

## 검증 범위

VM에서 실제 Track A/B 종료·각 12개 파일 VSS 해시 복구·UI 저장 ACK·재부팅 복귀를 확인했습니다.
12만 write 호출 시험의 추가 커널 유실/큐 비움은 0이었지만 과거 51,879건은 유지했습니다.
이 수치는 무제한 부하나 모든 랜섬웨어에 대해 유실 0/완전 복구를 보증하지 않습니다.
상세한 차이와 출처는 [릴리스 노트](../docs/V0_5_0_RELEASE_KO.md)를 참고하세요.
