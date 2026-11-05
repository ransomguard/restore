# Windows 11 실험 환경과 복구 범위

## Windows 11 사용

Windows 11 **x64**를 첫 대상으로 진행할 수 있다. 특정 빌드에서 드라이버 로드까지 검증된 상태는 아니므로 OS 버전·빌드와 도구 버전을 기록한다.

프로젝트는 VS2022/v143과 빌드 번호 26100의 SDK/WDK 조합을 기준으로 재구성했다. ARM64는 별도 대상이다. 드라이버 서명과 VM의 코드 무결성 정책도 확인한다. 테스트 모드라는 이유만으로 서명 없는 드라이버가 HVCI 환경에서 허용되지는 않는다. [WDK 설치](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk), [테스트 서명 코드 로드](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).

원본 복구 코드는 wmic에 의존했다. v0.6.1 생성·조회 모듈은 PowerShell CIM을 사용하므로 WMIC 실행 파일을 요구하지 않는다. 해당 VM의 클래스·공급자·권한은 실제로 확인해야 한다. [WMIC 변경](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic).

## 호스트 PC와 VM

| 배치 | 확인할 버전 | 호스트 역할 |
| --- | --- | --- |
| VM에서 편집·빌드·실행 | VM의 Windows, VS, SDK/WDK, Python, SDK 패키지 | VirtualBox 지원 OS/CPU, 가상화, 자원 |
| 호스트 빌드, VM 실행 | 호스트 빌드 도구와 VM 실행 환경 각각 | 실제 컴파일 환경 |
| 호스트에서 편집만 수행 | 컴파일·실행하는 쪽의 버전 | 편집기 자체는 커널 호환성을 결정하지 않음 |

첫 단계에는 자원이 충분하다면 도구까지 VM에 설치하면 환경 차이를 줄일 수 있다. 별도 커널 디버거가 필요해지면 개발·실행 VM을 나눌 수 있다.

VirtualBox의 x86_64/Arm64 호스트·게스트 조합은 다르다. ARM PC에서 이 x64 빌드를 당연히 실행할 수 있다고 가정하지 않는다. [Oracle 지원 표](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/Introduction.html).

실험 파일은 VM의 가상 디스크에 둔다. 호스트 공유 폴더를 복구 대상으로 지정하지 않는다. NAT도 외부 통신을 허용할 수 있으므로 VM 실행과 인터넷 차단은 별도로 검증한다.

## 버전 한 번에 확인

VM의 PowerShell에서 프로젝트 루트를 기준으로 실행한다.

~~~powershell
.\scripts\Collect-Environment.ps1 -OutputPath .\environment.json
~~~

진단은 읽기 전용이다. OS 빌드, VS 설치, SDK/WDK 제품·헤더 디렉터리, 현재 Python, SDK 버전을 기록한다. API 키·프록시 주소는 출력하지 않고 환경변수 존재 여부만 기록한다.

PowerShell 실행 정책으로 거부되면 아래 개별 조회 명령을 사용해도 된다. 보호 설정을 일괄 해제할 필요는 없다. 가상 환경이 활성화되지 않은 셸에서는 시스템 Python이 수집될 수 있으므로 실행 경로를 확인한다.

### Windows

winver 또는 다음 명령을 사용한다.

~~~powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture
~~~

### Visual Studio

메뉴 **도움말 → Microsoft Visual Studio 정보**, 또는 Visual Studio Installer의 설치 항목을 확인한다.

~~~powershell
& (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Microsoft Visual Studio\Installer\vswhere.exe') -all -products '*' -format json
~~~

### SDK와 WDK

Windows **설정 → 앱 → 설치된 앱**에서 Windows Software Development Kit, Windows Driver Kit 제품 버전을 확인한다. 헤더 빌드는 다음으로 본다.

~~~powershell
Get-ChildItem (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Windows Kits\10\Include') -Directory
~~~

10.0.26100.0 디렉터리는 설치된 전체 QFE 버전과 다를 수 있다. 폴더 이름, 설치 제품 버전, 프로젝트 대상 버전을 구분한다. SDK/WDK 빌드 번호는 맞아야 한다. 선택 기준은 별도 knel 압축파일의 BUILD_NOTES.md에 있다.

### Python과 typesafe-sdk

~~~powershell
python --version
python -c "import sys; print(sys.executable)"
python -m pip show typesafe-sdk
~~~

pip 없이도 설치된 패키지 메타데이터를 확인할 수 있다.

~~~powershell
python -c "import importlib.metadata as m; print(m.version('typesafe-sdk'))"
~~~

패키지 미발견은 해당 Python 환경에 없다는 뜻이다. 다른 Python에 설치됐을 수 있으므로 실행 경로도 확인한다. py 런처가 있다면 py -0p로 목록을 본다.

프로젝트 가상 환경은 직접 지정할 수 있다.

~~~powershell
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip show typesafe-sdk
~~~

오프라인 테스트에는 외부 패키지가 필요 없다. 실제 JEV 호출 준비 시 store 디렉터리에서 선택 의존성을 설치한다.

~~~powershell
.\.venv\Scripts\python.exe -m pip install -e ".[jev]"
~~~

## JEV 주소, 프록시, 정상 응답

원본 restore-main/core/jev_client.py는 TypeSafeClient()를 호출하며 URL을 지정하지 않는다. 새 모듈은 SDK 기본 API 루트 https://api.typesafe.ai 와 jev-latest를 명시했다. 정책 계획의 요청 목적지는 https://api.typesafe.ai/v1/systemone 이다. SDK 생성자에는 전체 요청 경로가 아닌 API 루트를 전달한다. [공식 SDK 기본값](https://github.com/typesafe-ai/typesafe-sdk-python/blob/main/src/typesafe_sdk/constants.py).

기존 환경에 TYPESAFE_BASE_URL 같은 설정이 있었다면 실제 목적지는 달랐을 수 있다. 새 모듈은 명시한 base_url을 사용한다.

프록시는 **미확인**으로 기록한다. 환경변수 존재 여부만으로 시스템 프록시·실제 SDK 경로를 확정할 수 없다. 격리 시험에서는 API 서버 직통인지 프록시 경유인지 확인해야 한다.

정상 응답 예시 없이도 모의 응답으로 진행할 수 있다. 새 모듈은 answers["is_ransomware"], type="noul", 유한한 0~1 숫자, 모델·요청 ID를 검사한다. API 키를 채팅이나 저장소에 넣을 필요는 없다. SDK 값은 모델의 질문 응답이며 프로젝트에서 실증한 오탐률을 뜻하지 않는다. [응답 타입](https://docs.typesafe.ai/sdk/python/api/types/responses/).

## C: 볼륨과 보호 폴더

| 항목 | 첫 실험 제안 |
| --- | --- |
| VSS 원본 볼륨 | VM의 C:\ |
| 파일 복구 폴더 | C:\RansomGuardLab\Protected |
| 복구 대상 | 사건별로 지정한 상대 파일 경로 목록 |
| 초기 시험 | 새 텍스트 파일 몇 개의 내용 수정·복구 |
| 전체 Windows 롤백 | 이 파일 복구 모듈의 범위 밖 |

볼륨 단위 사본에서 특정 파일만 읽어 복구할 수 있다. C: 사본이 있다고 실행 중인 C: 전체를 덮어쓰는 구조로 만들지 않는다.

VSS 시스템 공급자의 copy-on-write와 프로젝트 미니필터의 변경 직전 파일 백업은 별개다. 이번 미니필터에는 자체 per-write 원본 보존이 없다. 같은 저장장치의 VSS와 독립된 외부 백업도 구분한다. [VSS 개요](https://learn.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service).

VMware/VirtualBox의 VM 스냅샷은 실험 VM을 되돌리는 기준점이다. VSS 스냅샷은 VM 안에서 파일 복구 기능에 주는 입력이다.

## 확정: 스냅샷은 1시간 간격으로만 생성

사용자가 프로그램 부담을 줄이기 위해 1시간 간격으로만 생성하기로 확정했다. 탐지·JEV 질의·복구 시작·서비스 시작 시 추가 사본을 만들지 않는다. 첫 복구 시험도 정기 사본이 생성된 후 시작하며, 실험 직전 별도 생성은 요구하지 않는다.

정기 생성이 모두 성공하더라도 복원하는 파일의 최근 약 1시간 정상 변경을 잃을 수 있다. 10:00 사본, 10:40 정상 수정, 10:55 피해라면 10:00으로 복원하면서 10:40 수정도 사라진다. 생성 실패나 정상 사본 부족으로 더 오래된 버전을 선택하면 손실 구간은 더 길어질 수 있다.

생성 주기와 복구 실행 시점은 다르다. 복구는 판정·종료 확인 등 조건이 충족되면 동일 볼륨의 기존 사건 이전 사본으로 수행한다. 적합한 사본이 없으면 복구 불가를 기록하고 현재 상태로 새 사본을 만들어 대체하지 않는다. 감지 직전 사본이 공격 시작 이전 사본인 것은 아니므로 정상 시점의 근거가 필요하다.

config/example.json의 snapshot_interval_seconds=3600은 확정값이고 생성 계기는 hourly_schedule 하나다. v0.6.1에 CIM 생성기와 예약 작업 등록 스크립트를 구현했다. README의 VM 설치 절차에서 직접 등록한다. 설치 시 생성하지 않고 다음 정시부터 매시간 실행한다. 로그인한 관리자 세션과 실행·깨어 있는 VM이 필요하며, 누락 시간을 몰아서 생성하지 않는다. 3600초 영속 제한으로 중복을 억제하고 불명확한 생성 결과는 후속 생성을 보류한다. 보존 기간·용량 상한과 자동 정리는 남아 있다.

기존 사본 조회는 store 디렉터리에서 실행한다.

~~~powershell
.\.venv\Scripts\python.exe -m ransomguard snapshot-inventory --volume-root 'C:\' --output snapshots.json
~~~

## 메모장 복구 시험의 의미

기존 성공은 그 파일·환경에서 내용을 되돌리는 기본 경로의 근거다. 여러 파일, 이름 변경·삭제, 열린 파일, 용량 부족, 중간 실패, 사건 중첩까지 검증한 결과는 아니다.

다음에는 VM 지정 폴더에서 파일 하나의 내용·해시를 확인하고, 여러 지정 파일을 복구하되 목록 밖 파일이 유지되는지 확인한다. 일부 실패가 전체 성공으로 표시되지 않는지도 시험한다. 그 다음 검증된 격리·종료 절차를 연결한다.

새 모듈의 verified는 명시한 파일 내용이 선택한 사본과 일치했다는 뜻이다. ACL·대체 데이터 스트림·EFS·전체 OS 상태·애플리케이션 일관성·암호화 잔여 파일 삭제까지 복원하지는 않는다.

## 다음에 필요한 자료

별도 최신 프로젝트나 통합 프로그램을 다시 찾을 필요는 없다. 저장소 밖 파일은 없다는 전제를 반영했다.

- VM의 environment.json 또는 위 조회 결과.
- 첫 Windows 빌드 오류가 있으면 오류 전문과 빌드 로그.
- 대시보드 로그 수신 URL 경로·인증·요청/응답 스키마. 명세가 없으면 관련 백엔드 코드.

API 키나 실제 토큰은 필요 없다. JEV 실제 응답은 나중에 VM에서 무해한 입력으로 호출한 뒤 민감값을 제거하면 된다.
