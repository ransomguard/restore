# RansomGuard restore/JEV v0.5.1

복구 카탈로그·스냅샷 유효기간 검증, 소유 VSS 보관/자동 정리와 복구 중 보호를 추가한 통합 소스 패치입니다.

- [설치와 네 구성요소 연결](deployment/README_KO.md)
- [변경 사항·실제 VM 검증·제한](docs/V0_5_1_RELEASE_KO.md)
- [스냅샷 보관 정책과 예약 작업](docs/SNAPSHOT_RETENTION.md)
- UI/방화벽은 `deployment/components.lock.json`의 정확한 커밋을 사용하세요. UI는 기존 통합 PR의 최신 안정화 패치입니다.

기본 설치는 관측 전용이며 자동 대응은 승인 경로/복구 manifest가 필요합니다. 대표 정상·악성 자료에 대한 JEV 판정 보정이나 전체 PC 복구를 보증하지 않습니다. 통합 설치 파일과 드라이버 서명 배포는 별도입니다.
이 소스에는 개인 API 키, DPAPI 비밀, VM 이미지, 사용자 기록 DB 또는 서명용 개인 키가 없습니다. 이전 버전 폴더는 그대로 보존합니다.
