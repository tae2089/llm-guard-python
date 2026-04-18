# GAP-5: 이 파일은 python/llm_guard_hook.py와 기능적으로 동일해야 합니다.
# 변경 시 두 파일을 반드시 함께 수정하세요.
import sys
import importlib
import importlib.abc
import importlib.util


class PiiBlockedError(Exception):
    """PII가 탐지되어 요청이 차단되었을 때 발생하는 예외"""
    pass


class InjectionBlockedError(Exception):
    """프롬프트 인젝션이 탐지되어 요청이 차단되었을 때 발생하는 예외"""
    pass


class _WrappingLoader(importlib.abc.Loader):
    """원본 로더를 감싸서 모듈 실행 후 urlopen을 래핑"""

    def __init__(self, loader):
        self._loader = loader

    def create_module(self, spec):
        create = getattr(self._loader, "create_module", None)
        return create(spec) if create else None

    def exec_module(self, module):
        self._loader.exec_module(module)
        _wrap_urlopen(module)
        LlmGuardFinder._hooked = True


class LlmGuardFinder:
    """urllib3.connectionpool 임포트를 가로채서 urlopen을 래핑하는 커스텀 Finder"""

    _hooked = False

    def find_spec(self, fullname, path, target=None):
        """Python 3.12+ 임포트 훅 — 원본 spec 로더를 래핑"""
        if fullname == "urllib3.connectionpool" and not LlmGuardFinder._hooked:
            for finder in sys.meta_path:
                if finder is self:
                    continue
                find_spec_fn = getattr(finder, "find_spec", None)
                if find_spec_fn is None:
                    continue
                spec = find_spec_fn(fullname, path, target)
                if spec is not None:
                    spec.loader = _WrappingLoader(spec.loader)
                    return spec
        return None

    def find_module(self, fullname, path=None):
        """Python < 3.12 레거시 폴백"""
        if fullname == "urllib3.connectionpool" and not LlmGuardFinder._hooked:
            return self
        return None

    def load_module(self, fullname):
        """Python < 3.12 레거시 폴백"""
        sys.meta_path.remove(self)
        try:
            module = importlib.import_module(fullname)
            sys.modules[fullname] = module
            _wrap_urlopen(module)
            LlmGuardFinder._hooked = True
        finally:
            sys.meta_path.insert(0, self)
        return module


def wrap_urllib3_if_available():
    """urllib3가 이미 설치되어 있으면 즉시 래핑 (import hook 불필요)"""
    if LlmGuardFinder._hooked:
        return True
    try:
        import urllib3.connectionpool as cp
        _wrap_urlopen(cp)
        LlmGuardFinder._hooked = True
        return True
    except ImportError:
        return False


_TEXT_CONTENT_TYPES = ("application/json", "text/", "application/xml", "application/x-www-form-urlencoded")


def _is_text_content_type(ct):
    if not ct:
        return False
    ct_lower = ct.lower()
    return any(ct_lower.startswith(t) for t in _TEXT_CONTENT_TYPES)


def _attach_streaming_scanner(resp, method, url, response_config):
    """preload_content=False 응답에 StreamingScanner를 붙여 resp.read를 래핑."""
    from llm_guard._streaming import StreamingScanner

    if getattr(resp, "__llm_guard_streaming__", False):
        return
    headers = getattr(resp, "headers", None)
    content_type = headers.get("Content-Type", "") if headers else ""
    if not _is_text_content_type(content_type):
        return

    if not response_config.get("stream_enabled", True):
        return

    # HIGH-1: race condition 방지를 위해 래핑 전에 플래그 먼저 세팅
    resp.__llm_guard_streaming__ = True

    scanner = StreamingScanner(
        action=response_config.get("action", "redact"),
        lookback_bytes=response_config.get("stream_lookback_bytes", 256),
        method=method,
        url=str(url),
    )
    original_read = resp.read
    original_read_chunked = getattr(resp, "read_chunked", None)

    def wrapped_read(amt=None, *args, **kwargs):
        # CRITICAL-1: 재귀 대신 while 루프 — 작은 청크 연속 시 스택 오버플로 방지
        # GAP-6: 극소 청크 연속 시 무한 루프 방지 — lookback*2 반복 후 강제 flush
        _max_iters = scanner._lookback * 2
        for _ in range(_max_iters):
            chunk = original_read(amt, *args, **kwargs)
            if not chunk:
                tail = scanner.flush()
                return tail if tail else chunk
            processed = scanner.feed(chunk)
            if processed:
                return processed
        # 상한 초과: 버퍼에 쌓인 데이터 강제 방출
        return scanner.flush() or b""

    resp.read = wrapped_read

    if original_read_chunked is not None:
        def wrapped_read_chunked(amt=None, decode_content=None):
            for raw in original_read_chunked(amt, decode_content=decode_content):
                processed = scanner.feed(raw)
                if processed:
                    yield processed
            tail = scanner.flush()
            if tail:
                yield tail

        resp.read_chunked = wrapped_read_chunked


def _scan_response(resp, method, url, response_config):
    """응답 body를 스캔. action에 따라 마스킹/차단/경고."""
    from llm_guard._guard import mask, scan, log_block

    body = getattr(resp, "_body", None)
    if body is None:
        _attach_streaming_scanner(resp, method, url, response_config)
        return

    headers = getattr(resp, "headers", None)
    content_type = headers.get("Content-Type", "") if headers else ""
    if not _is_text_content_type(content_type):
        return

    max_bytes = response_config.get("max_body_bytes", 1048576)
    if len(body) > max_bytes:
        return

    try:
        text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
    except UnicodeDecodeError:
        return

    action = response_config.get("action", "redact")

    if action == "block":
        result = scan(text)
        if result:
            log_block(method, str(url), f"response:{result.pattern_name}", result.matched_value)
            raise PiiBlockedError(
                f"[LLM_GUARD] 응답 차단: {method} {url} - {result.pattern_name} 발견"
            )
        return

    masked_text, matches = mask(text)
    if not matches:
        return

    for m in matches:
        log_block(method, str(url), f"response:{m.pattern_name}", m.matched_value)

    if action == "warn":
        print(
            f"[LLM_GUARD] 응답 경고: {method} {url} - {len(matches)}개 PII 감지",
            file=sys.stderr,
        )
        return

    resp._body = masked_text.encode("utf-8")
    print(
        f"[LLM_GUARD] 응답 마스킹: {method} {url} - {len(matches)}개 PII 치환",
        file=sys.stderr,
    )


def _wrap_urlopen(connectionpool_module):
    """HTTPConnectionPool.urlopen을 래핑"""
    original = connectionpool_module.HTTPConnectionPool.urlopen

    def wrapped_urlopen(self, method, url, body=None, headers=None, **kwargs):
        from llm_guard._guard import scan, analyze, get_response_config

        # HIGH-2: 매 요청마다 평가 — load_config 재호출 시에도 최신 설정 반영
        response_config = get_response_config()

        # --- Layer 1: PII 정규식 ---
        if headers:
            items = headers.items() if hasattr(headers, "items") else []
            for key, value in items:
                result = scan(f"{key}: {value}")
                if result:
                    _block_pii(method, url, result)

        if body:
            if isinstance(body, bytes):
                text = body.decode("utf-8", errors="ignore")
            elif isinstance(body, str):
                text = body
            else:
                text = str(body)

            result = scan(text)
            if result:
                _block_pii(method, url, result)

            # --- Layer 2: 의미론적 분석 ---
            try:
                semantic = analyze(text)
                if semantic:
                    if semantic.category == "injection":
                        _block_semantic(method, url, semantic)
                    elif semantic.category == "jailbreak":
                        _warn_semantic(method, url, semantic)
            except (PiiBlockedError, InjectionBlockedError):
                raise
            except Exception as e:
                print(f"[LLM_GUARD] Layer 2 분석 오류: {e}", file=sys.stderr)

        resp = original(self, method, url, body=body, headers=headers, **kwargs)

        if response_config is not None:
            _scan_response(resp, method, url, response_config)

        return resp

    wrapped_urlopen.__llm_guard_wrapped__ = True
    connectionpool_module.HTTPConnectionPool.urlopen = wrapped_urlopen


def _block_pii(method, url, scan_result):
    """PII 차단: 로그 + stderr + 예외"""
    from llm_guard._guard import log_block
    log_block(method, str(url), scan_result.pattern_name, scan_result.matched_value)
    raise PiiBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {scan_result.pattern_name} 발견"
    )


def _block_semantic(method, url, result):
    """인젝션 차단: 로그 + stderr + 예외"""
    from llm_guard._guard import log_block
    log_block(method, str(url), result.category, result.matched_text)
    raise InjectionBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    )


def _warn_semantic(method, url, result):
    """탈옥 경고: 로그 + stderr, 요청은 통과"""
    from llm_guard._guard import log_block
    msg = f"[LLM_GUARD] 경고: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    log_block(method, str(url), result.category, result.matched_text)
    print(msg, file=sys.stderr)
