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

## Response Scanning 테스트
### Rust 단위 테스트
- [x] detector: mask() 모든 매치를 `[REDACTED:<name>]`로 치환
- [x] detector: mask() 매치 없으면 원문 + 빈 리스트
- [x] detector: mask() 여러 패턴/여러 매치 동시 치환
- [x] config: [response] 섹션 파싱 (enabled, action, max_body_bytes)
- [x] config: [response] 섹션 없음 → None (기본 비활성)
- [x] config: response disabled → None
- [x] lib: PyO3 mask 인터페이스 (masked_text, matches 튜플 반환)
- [x] lib: PyO3 get_response_config 인터페이스

### Python 통합 테스트 + E2E
- [x] e2e: 응답 body에 이메일 → 마스킹된 body 수신 (redact)
- [x] e2e: 응답 body에 PII + action=block → 예외
- [x] e2e: 바이너리 응답 (Content-Type=image/png) → 수정 없이 통과
- [x] e2e: [response] 섹션 없음 → 응답 PII 그대로 통과 (비활성)
- [x] e2e: 응답 스캔 활성 시에도 요청 PII 차단 유지 (회귀)
- [x] hook: action=warn → 로그만, body 그대로 (Phase 2)
- [x] hook: max_body_bytes 초과 시 skip (Phase 2)
- [x] hook: preload_content=False(streaming) (Phase 2)

## Streaming Response Scan (Phase 2)
### Rust 단위 테스트
- [x] config: [response] stream_enabled=false 파싱 → 필드 false
- [x] config: stream_lookback_bytes 기본값 256 (필드 없음)
- [x] config: stream_enabled 기본값 true (필드 없음, 하위호환)
- [x] config: stream_lookback_bytes 커스텀 값 파싱

### Python 단위 테스트 — StreamingScanner
- [x] scanner: 짧은 청크(< lookback) → feed는 b"" 리턴
- [x] scanner: 긴 청크 PII 없음 → buf[:-K]만큼 그대로 방출
- [x] scanner: 긴 청크 내부 PII → [REDACTED:이메일] 치환 방출
- [x] scanner: 청크 경계 PII (user@exa + mple.com) → 마스킹
- [x] scanner: flush()가 남은 버퍼 방출
- [x] scanner: UTF-8 한글 경계 (3바이트 절단) → 끊지 않고 hold
- [x] scanner: action=block → redact 다운그레이드 + stderr 경고 1회
- [x] scanner: action=warn → 원본 그대로 + 로그
- [x] scanner: action=redact, PII 없음 → 원본 그대로

### Python e2e
- [x] e2e: preload_content=False + resp.stream() → 마스킹된 청크
- [x] e2e: SSE text/event-stream + 다중 data: 줄 → 마스킹 + 포맷 보존
- [x] e2e: stream_enabled=false → 래핑 skip
- [x] e2e: 바이너리 스트림(image/png, preload=False) → 래핑 skip
- [x] e2e: 비스트리밍 경로 회귀 (Phase 1 동작 불변)
- [x] e2e: action=block + 스트림 → redact 다운그레이드

## Sentence Boundary Buffering (Phase 2 확장)
### Rust 단위 테스트
- [x] config: split_strategy 기본값 "lookback"
- [x] config: max_sentence_bytes 기본값 4096
- [x] config: split_strategy="word" → 에러
- [x] config: max_sentence_bytes=256 → 에러
- [x] config: split_strategy="sentence" + max_sentence_bytes=1024 → 정상

### Python 단위 테스트 — _find_sentence_boundary
- [x] fsb: \n\n → 직후 위치 반환
- [x] fsb: '. ' → 직후 위치 반환
- [x] fsb: '。' (U+3002) → 직후 위치 반환
- [x] fsb: 빈 버퍼 → -1
- [x] fsb: 종결 신호 없음 → -1
- [x] fsb: 단독 '.' (URL) → -1
- [x] fsb: '?\n' → 직후 위치 반환
- [x] fsb: '! ' → 직후 위치 반환
- [x] fsb: 여러 종결 신호 → 마지막 것
- [x] fsb: '？' (U+FF1F) → 직후 위치 반환
- [x] fsb: 버퍼 끝 '.' (뒤에 공백 없음) → -1

### Python 단위 테스트 — sentence 모드 feed
- [x] scanner: sentence 모드, \n\n 경계에서 방출
- [x] scanner: sentence 모드, 종결 신호 없으면 hold
- [x] scanner: sentence 모드, '. ' 경계에서 방출
- [x] scanner: sentence 모드, max_sentence_bytes 초과 → lookback 폴백
- [x] scanner: sentence 모드, 청크 경계 PII 탐지
- [x] scanner: sentence 모드, 한글 마침표(。) 경계에서 방출
- [x] scanner: sentence 모드, flush()는 남은 버퍼 전체 방출
- [x] scanner: _max_iters_for_wrapped_read sentence 모드 → max_sentence_bytes*2
- [x] scanner: _max_iters_for_wrapped_read lookback 모드 → lookback*2

### Python e2e
- [x] e2e: sentence 모드 스트리밍 PII 마스킹
- [x] e2e: sentence 모드 청크 경계 PII 탐지
- [x] e2e: sentence 모드 max_sentence_bytes 초과 → lookback 폴백

### response_api 테스트
- [x] api: split_strategy/max_sentence_bytes Python dict 노출
- [x] api: 기본값 노출 (lookback / 4096)
- [x] api: split_strategy="word" → RuntimeError
- [x] api: max_sentence_bytes=256 → RuntimeError

## Phase 2.5 — read_chunked 직접 호출 테스트
- [x] e2e: read_chunked() 직접 호출 → PII 마스킹
- [x] e2e: read_chunked() + 청크 경계 PII → 마스킹
- [x] e2e: read_chunked() stream_enabled=false → 래핑 skip

## GAP-1 / Phase 3 — httpx hook
### httpx 동기 클라이언트
- [x] hook: httpx.Client GET 요청 body PII → PiiBlockedError
- [x] hook: httpx.Client 응답 body PII → 마스킹 (non-streaming)
- [x] hook: httpx.Client streaming iter_bytes → 마스킹
- [x] hook: httpx.Client streaming 청크 경계 PII → 마스킹
- [x] hook: 바이너리 응답 (image/png) → 래핑 skip
- [x] hook: response_config 없음 → 응답 PII 그대로
### httpx 비동기 클라이언트
- [x] hook: httpx.AsyncClient GET 요청 PII → PiiBlockedError
- [x] hook: httpx.AsyncClient 응답 streaming → 마스킹
