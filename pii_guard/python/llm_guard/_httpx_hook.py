# @index httpx.Client/AsyncClient 요청·응답을 monkey-patch해 PII·injection을 탐지·차단하는 훅.
"""httpx hook — PII Guard for httpx.Client / httpx.AsyncClient (GAP-1)
GAP-5: pii_guard/python/llm_guard/_httpx_hook.py와 기능적으로 동일해야 합니다.
"""
import sys
import os


def activate():
    """llm_guard 설정 로드 + httpx 클라이언트 래핑."""
    if os.environ.get("LLM_GUARD_DISABLE", "").lower() in ("1", "true"):
        return
    import llm_guard
    config_path = os.environ.get(
        "LLM_GUARD_CONFIG",
        os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml"),
    )
    try:
        llm_guard.load_config(config_path)
    except RuntimeError as e:
        print(f"[LLM_GUARD] httpx hook 설정 로드 실패(무시하고 진행): {e}", file=sys.stderr)
    wrap_httpx_if_available()


def wrap_httpx_if_available() -> bool:
    """httpx가 설치되어 있으면 Client/AsyncClient.send를 래핑."""
    try:
        import httpx
    except ImportError:
        return False
    if getattr(httpx.Client.send, "__llm_guard_wrapped__", False):
        return True
    _patch_sync_client(httpx)
    _patch_async_client(httpx)
    return True


# ─── Text content-type 판별 ──────────────────────────────────────────────────

_TEXT_PREFIXES = (
    "application/json",
    "text/",
    "application/xml",
    "application/x-www-form-urlencoded",
)


def _is_text(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return any(ct.startswith(p) for p in _TEXT_PREFIXES)


# ─── 요청 body 스캔 ──────────────────────────────────────────────────────────

# @intent httpx 요청 헤더와 body에서 PII(Layer 1)와 injection/jailbreak(Layer 2)를 검사해 서버 전송 전에 차단
# @domainRule 헤더 값에 PII 발견 시 즉시 PiiBlockedError — body 검사보다 선행
# @domainRule streaming body는 스캔 불가, 경고만 출력 후 통과
def _scan_request(request) -> None:
    """요청 헤더·body에 PII/Semantic이 있으면 PiiBlockedError/InjectionBlockedError 발생."""
    from llm_guard._guard import scan, analyze
    from llm_guard._hook import PiiBlockedError, InjectionBlockedError
    method = request.method
    url = str(request.url)

    # 헤더 스캔 (urllib3 훅과 동일 의미론)
    for key, value in request.headers.items():
        result = scan(f"{key}: {value}")
        if result:
            _block_pii(method, url, result)

    # body 스캔
    try:
        body = request.content
    except Exception:
        # streaming request body — 스캔 불가, 경고만 출력
        print(
            f"[LLM_GUARD] 경고: {method} {url} - streaming 요청 body는 스캔되지 않습니다",
            file=sys.stderr,
        )
        return
    if not body:
        return
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return

    # Layer 1: PII 정규식
    result = scan(text)
    if result:
        _block_pii(method, url, result)

    # Layer 2: 의미론적 분석 (urllib3 훅과 동일 의미론)
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


# ─── 응답 스캔 (non-streaming) ───────────────────────────────────────────────

# @intent httpx 버퍼드 응답 body의 PII를 스캔하고 action에 따라 차단·마스킹·경고 처리
# @domainRule Content-Length가 max_body_bytes 초과 시 스캔을 건너뛴다
# @mutates response._content, response.headers["content-length"]
def _scan_buffered_response(response, method: str, url: str, response_config: dict) -> None:
    """response._content PII 스캔 / 마스킹."""
    from llm_guard._guard import mask, scan, log_block

    content_type = response.headers.get("content-type", "")
    if not _is_text(content_type):
        return

    body = getattr(response, "_content", None)
    if not body:
        return

    max_bytes = response_config.get("max_body_bytes", 1048576)
    if len(body) > max_bytes:
        return

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return

    action = response_config.get("action", "redact")

    if action == "block":
        result = scan(text)
        if result:
            log_block(method, url, f"response:{result.pattern_name}", result.matched_value)
            from llm_guard._hook import PiiBlockedError
            raise PiiBlockedError(
                f"[LLM_GUARD] 응답 차단: {method} {url} - {result.pattern_name} 발견"
            )
        return

    masked_text, matches = mask(text)
    if not matches:
        return
    for m in matches:
        log_block(method, url, f"response:{m.pattern_name}", m.matched_value)
    if action == "warn":
        print(f"[LLM_GUARD] 응답 경고: {method} {url} - {len(matches)}개 PII 감지",
              file=sys.stderr)
        return
    new_body = masked_text.encode("utf-8")
    response._content = new_body
    # Content-Length가 변경된 경우 헤더 갱신 (마스킹 후 길이 달라질 수 있음)
    if "content-length" in response.headers:
        response.headers["content-length"] = str(len(new_body))


# ─── 스트리밍 래퍼 ──────────────────────────────────────────────────────────
# httpx 내부에서 isinstance(stream, SyncByteStream) 체크를 하므로 반드시 서브클래스여야 함

def _make_sync_scanner_stream(httpx, original_stream, scanner):
    """httpx.SyncByteStream을 상속한 스캐닝 스트림 인스턴스를 반환."""
    class _ScanningByteStream(httpx.SyncByteStream):
        def __iter__(self):
            for chunk in original_stream:
                processed = scanner.feed(chunk)
                if processed:
                    yield processed
            tail = scanner.flush()
            if tail:
                yield tail

        def close(self):
            close_fn = getattr(original_stream, "close", None)
            if close_fn:
                close_fn()

    return _ScanningByteStream()


def _make_async_scanner_stream(httpx, original_stream, scanner):
    """httpx.AsyncByteStream을 상속한 스캐닝 스트림 인스턴스를 반환."""
    class _AsyncScanningByteStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            async for chunk in original_stream:
                processed = scanner.feed(chunk)
                if processed:
                    yield processed
            tail = scanner.flush()
            if tail:
                yield tail

        async def aclose(self):
            aclose_fn = getattr(original_stream, "aclose", None)
            if aclose_fn:
                await aclose_fn()

    return _AsyncScanningByteStream()


def _attach_stream_scanner(httpx, response, method: str, url: str, response_config: dict) -> None:
    """sync streaming response에 StreamingScanner를 붙인다."""
    from llm_guard._streaming import StreamingScanner

    content_type = response.headers.get("content-type", "")
    if not _is_text(content_type):
        return
    if not response_config.get("stream_enabled", True):
        return
    if getattr(response, "__llm_guard_streaming__", False):
        return

    scanner = StreamingScanner(
        action=response_config.get("action", "redact"),
        lookback_bytes=response_config.get("stream_lookback_bytes", 256),
        split_strategy=response_config.get("split_strategy", "lookback"),
        max_sentence_bytes=response_config.get("max_sentence_bytes", 4096),
        method=method,
        url=url,
    )
    response.stream = _make_sync_scanner_stream(httpx, response.stream, scanner)
    response.__llm_guard_streaming__ = True


def _attach_async_stream_scanner(httpx, response, method: str, url: str, response_config: dict) -> None:
    """async streaming response에 StreamingScanner를 붙인다."""
    from llm_guard._streaming import StreamingScanner

    content_type = response.headers.get("content-type", "")
    if not _is_text(content_type):
        return
    if not response_config.get("stream_enabled", True):
        return
    if getattr(response, "__llm_guard_streaming__", False):
        return

    scanner = StreamingScanner(
        action=response_config.get("action", "redact"),
        lookback_bytes=response_config.get("stream_lookback_bytes", 256),
        split_strategy=response_config.get("split_strategy", "lookback"),
        max_sentence_bytes=response_config.get("max_sentence_bytes", 4096),
        method=method,
        url=url,
    )
    response.stream = _make_async_scanner_stream(httpx, response.stream, scanner)
    response.__llm_guard_streaming__ = True


# ─── Client 패치 ─────────────────────────────────────────────────────────────

# @intent httpx.Client.send를 래핑해 모든 동기 HTTP 요청/응답에 PII 가드를 적용
# @domainRule stream=True인 경우 응답에 StreamingScanner를 붙이고, 버퍼드 응답은 직접 스캔
# @sideEffect httpx.Client.send 클래스 메서드를 전역 교체
# @mutates httpx.Client.send
def _patch_sync_client(httpx) -> None:
    original_send = httpx.Client.send

    def wrapped_send(self, request, *args, **kwargs):
        from llm_guard._guard import get_response_config
        stream = kwargs.get("stream", False)

        _scan_request(request)
        response = original_send(self, request, *args, **kwargs)

        response_config = get_response_config()
        if response_config is not None:
            if stream:
                _attach_stream_scanner(httpx, response, request.method, str(request.url), response_config)
            else:
                _scan_buffered_response(response, request.method, str(request.url), response_config)

        return response

    wrapped_send.__llm_guard_wrapped__ = True
    httpx.Client.send = wrapped_send


# @intent httpx.AsyncClient.send를 래핑해 모든 비동기 HTTP 요청/응답에 PII 가드를 적용
# @sideEffect httpx.AsyncClient.send 클래스 메서드를 전역 교체
# @mutates httpx.AsyncClient.send
def _patch_async_client(httpx) -> None:
    original_send = httpx.AsyncClient.send

    async def wrapped_send(self, request, *args, **kwargs):
        from llm_guard._guard import get_response_config
        stream = kwargs.get("stream", False)

        _scan_request(request)
        response = await original_send(self, request, *args, **kwargs)

        response_config = get_response_config()
        if response_config is not None:
            if stream:
                _attach_async_stream_scanner(httpx, response, request.method, str(request.url), response_config)
            else:
                _scan_buffered_response(response, request.method, str(request.url), response_config)

        return response

    wrapped_send.__llm_guard_wrapped__ = True
    httpx.AsyncClient.send = wrapped_send


# ─── 공통 헬퍼 ───────────────────────────────────────────────────────────────

def _block_pii(method: str, url: str, scan_result) -> None:
    from llm_guard._guard import log_block
    from llm_guard._hook import PiiBlockedError
    log_block(method, url, scan_result.pattern_name, scan_result.matched_value)
    raise PiiBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {scan_result.pattern_name} 발견"
    )


def _block_semantic(method: str, url: str, result) -> None:
    from llm_guard._guard import log_block
    from llm_guard._hook import InjectionBlockedError
    log_block(method, url, result.category, result.matched_text)
    raise InjectionBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    )


def _warn_semantic(method: str, url: str, result) -> None:
    from llm_guard._guard import log_block
    msg = f"[LLM_GUARD] 경고: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    log_block(method, url, result.category, result.matched_text)
    print(msg, file=sys.stderr)
