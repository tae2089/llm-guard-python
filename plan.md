# PII Guard TDD Plan

## Rust 단위 테스트
- [x] detector: 주민등록번호 탐지
- [x] detector: 전화번호 탐지
- [x] detector: 이메일 탐지
- [x] detector: 신용카드번호 탐지
- [x] detector: 계좌번호 탐지
- [x] detector: 여권번호 탐지
- [x] detector: 정상 텍스트 false positive 없음
- [x] config: TOML 설정 파일 로드
- [x] config: 잘못된 정규식 패턴 스킵
- [x] logger: 마스킹 함수
- [x] logger: 파일 로그 기록
- [x] lib: PyO3 scan 인터페이스
- [x] lib: PyO3 load_config 인터페이스
- [x] lib: PyO3 log 인터페이스

## Python 통합 테스트
- [x] hook: PiiGuardFinder가 sys.meta_path에 등록됨
- [x] hook: urllib3 임포트 시 urlopen 래핑됨
- [x] hook: PII 포함 body → PiiBlockedError
- [x] hook: PII 포함 header → PiiBlockedError
- [x] hook: PII 없는 요청 → 정상 통과
- [x] hook: 로그 파일에 차단 기록
- [x] bootstrap: sitecustomize 로드 시 활성화
- [x] bootstrap: PII_GUARD_DISABLE=1 → 비활성

## Semantic Layer 테스트
- [x] vectordb: DB 생성 + 삽입 + 검색
- [x] vectordb: 임계값 이하 → None
- [x] vectordb: 빈 DB → None
- [x] semantic: injection 탐지
- [x] semantic: jailbreak 탐지
- [x] semantic: 정상 텍스트 → Safe
- [x] semantic: 한국어 injection 탐지
- [x] semantic: 시딩 중복 스킵
- [x] config: semantic 설정 파싱
- [x] config: semantic disabled → None
- [x] config: semantic 섹션 없음 → None
- [x] config: 시드 벡터 로드
- [x] lib: PyO3 init_semantic
- [x] lib: PyO3 analyze
- [x] lib: PyO3 get_semantic_config
- [x] hook: injection → InjectionBlockedError
- [x] hook: jailbreak → 경고만
- [x] e2e: injection 차단
- [x] e2e: jailbreak 경고 + 통과
- [x] e2e: PII 여전히 차단 (회귀)
- [x] e2e: PII_GUARD_SEMANTIC=0 → 비활성
- [x] e2e: 한국어 injection 차단
