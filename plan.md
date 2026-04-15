# PII Guard TDD Plan

## Rust 단위 테스트
- [ ] detector: 주민등록번호 탐지
- [ ] detector: 전화번호 탐지
- [ ] detector: 이메일 탐지
- [ ] detector: 신용카드번호 탐지
- [ ] detector: 계좌번호 탐지
- [ ] detector: 여권번호 탐지
- [ ] detector: 정상 텍스트 false positive 없음
- [ ] config: TOML 설정 파일 로드
- [ ] config: 잘못된 정규식 패턴 스킵
- [ ] logger: 마스킹 함수
- [ ] logger: 파일 로그 기록
- [ ] lib: PyO3 scan 인터페이스
- [ ] lib: PyO3 load_config 인터페이스
- [ ] lib: PyO3 log 인터페이스

## Python 통합 테스트
- [ ] hook: PiiGuardFinder가 sys.meta_path에 등록됨
- [ ] hook: urllib3 임포트 시 urlopen 래핑됨
- [ ] hook: PII 포함 body → PiiBlockedError
- [ ] hook: PII 포함 header → PiiBlockedError
- [ ] hook: PII 없는 요청 → 정상 통과
- [ ] hook: 로그 파일에 차단 기록
- [ ] bootstrap: sitecustomize 로드 시 활성화
- [ ] bootstrap: PII_GUARD_DISABLE=1 → 비활성
