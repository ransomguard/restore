# Restore v0.5.3 — Ransom0 설정·스냅샷·수집 안정화

- 보호 폴더/API 키 설정, 수동 복구, 소유 스냅샷 보관·보호, 프로그램 경로+해시 예외, 원본 콘솔 스트림을 포함합니다.
- 이벤트 intake는 최대 131072건 / 원본 384MiB로 제한하며 버리지 않고 대기합니다. 수동 표기 초기화와 원본 누적 계수는 구별합니다.
- 저장 배치는 최대256건/50ms, 상태의 건수 간격512(시간 기반 갱신 유지)입니다. 폭주 흡수를 위한 상한이며 지속적으로 생산이 소비를 넘으면 유실될 수 있습니다.
- Windows native/rg_intake.dll은 소스 배포에서 제외됩니다. integration/windows/intake_io.c와 통합 installer의 build_intake.py로 생성합니다. 설치 EXE에는 포함됩니다.
- 이 공개 폴더는 버전을0.5.3으로 명시합니다. preview.15 내장 pyproject의0.5.2는 이전 메타데이터이며 실제 파일은 installer payload-manifest.json으로 식별합니다.
- 기존 docs의 완료/제한 설명은 역사 기록입니다. 최신 검증과 제한은 아래 설치 릴리스를 우선합니다.

통합 EXE·VM/호스트 가이드·독립 시험 도구: https://github.com/ransomguard/installer/releases/tag/v0.6.0-preview.15
