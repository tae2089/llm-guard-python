import sys
import importlib


class PiiBlockedError(Exception):
    """PII가 탐지되어 요청이 차단되었을 때 발생하는 예외"""
    pass


class InjectionBlockedError(Exception):
    """프롬프트 인젝션이 탐지되어 요청이 차단되었을 때 발생하는 예외"""
    pass


class LlmGuardFinder:
    """urllib3.connectionpool 임포트를 가로채서 urlopen을 래핑하는 커스텀 Finder"""

    _hooked = False

    def find_module(self, fullname, path=None):
        if fullname == "urllib3.connectionpool" and not LlmGuardFinder._hooked:
            return self
        return None

    def load_module(self, fullname):
        sys.meta_path.remove(self)
        try:
            module = importlib.import_module(fullname)
            sys.modules[fullname] = module
            _wrap_urlopen(module)
            LlmGuardFinder._hooked = True
        finally:
            sys.meta_path.insert(0, self)
        return module


def _wrap_urlopen(connectionpool_module):
    """HTTPConnectionPool.urlopen을 래핑"""
    original = connectionpool_module.HTTPConnectionPool.urlopen

    def wrapped_urlopen(self, method, url, body=None, headers=None, **kwargs):
        import llm_guard

        # --- Layer 1: PII 정규식 ---
        if headers:
            items = headers.items() if hasattr(headers, "items") else []
            for key, value in items:
                result = llm_guard.scan(f"{key}: {value}")
                if result:
                    _block_pii(method, url, result)

        if body:
            if isinstance(body, bytes):
                text = body.decode("utf-8", errors="ignore")
            elif isinstance(body, str):
                text = body
            else:
                text = str(body)

            result = llm_guard.scan(text)
            if result:
                _block_pii(method, url, result)

            # --- Layer 2: 의미론적 분석 ---
            try:
                semantic = llm_guard.analyze(text)
                if semantic:
                    if semantic.category == "injection":
                        _block_semantic(method, url, semantic)
                    elif semantic.category == "jailbreak":
                        _warn_semantic(method, url, semantic)
            except (PiiBlockedError, InjectionBlockedError):
                raise
            except Exception as e:
                print(f"[LLM_GUARD] Layer 2 분석 오류: {e}", file=sys.stderr)

        return original(self, method, url, body=body, headers=headers, **kwargs)

    wrapped_urlopen.__llm_guard_wrapped__ = True
    connectionpool_module.HTTPConnectionPool.urlopen = wrapped_urlopen


def _block_pii(method, url, scan_result):
    """PII 차단: 로그 + stderr + 예외"""
    import llm_guard
    llm_guard.log_block(method, str(url), scan_result.pattern_name, scan_result.matched_value)
    raise PiiBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {scan_result.pattern_name} 발견"
    )


def _block_semantic(method, url, result):
    """인젝션 차단: 로그 + stderr + 예외"""
    import llm_guard
    llm_guard.log_block(method, str(url), result.category, result.matched_text)
    raise InjectionBlockedError(
        f"[LLM_GUARD] 차단: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    )


def _warn_semantic(method, url, result):
    """탈옥 경고: 로그 + stderr, 요청은 통과"""
    import llm_guard
    msg = f"[LLM_GUARD] 경고: {method} {url} - {result.category} 감지 (score={result.score:.2f})"
    llm_guard.log_block(method, str(url), result.category, result.matched_text)
    print(msg, file=sys.stderr)
