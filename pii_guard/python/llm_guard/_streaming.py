# @index 스트리밍 HTTP 응답에서 청크 경계에 걸친 PII를 실시간으로 탐지·마스킹하는 lookback 스캐너.
"""Streaming response PII scanner (Phase 2)."""
import sys
from llm_guard._guard import mask as _mask
from llm_guard._guard import log_block as _log_block


class StreamingScanner:
    """청크 경계 PII를 잡기 위한 lookback window 스캐너."""

    def __init__(self, action: str = "redact", lookback_bytes: int = 256,
                 split_strategy: str = "lookback", max_sentence_bytes: int = 4096,
                 method: str = "GET", url: str = ""):
        self._buf = bytearray()
        self._lookback = lookback_bytes
        self._action = action
        self._block_warned = False
        self._method = method
        self._url = url
        self._split_strategy = split_strategy
        self._max_sentence_bytes = max_sentence_bytes
        self.match_count = 0

    @property
    def _max_iters_for_wrapped_read(self) -> int:
        if self._split_strategy == "sentence":
            return self._max_sentence_bytes * 2
        return self._lookback * 2

    # @intent 새 청크를 버퍼에 누적하고 lookback/sentence 전략에 따라 안전하게 방출 가능한 바이트를 반환
    # @domainRule 버퍼 크기가 lookback 이하이면 b""를 반환해 청크 경계 PII 누락을 방지
    # @mutates self._buf
    def feed(self, chunk: bytes) -> bytes:
        """새 청크를 받아 방출 가능한 바이트를 리턴."""
        self._buf.extend(chunk)
        if self._split_strategy == "sentence":
            return self._feed_sentence()
        return self._feed_lookback()

    def _feed_lookback(self) -> bytes:
        if len(self._buf) <= self._lookback:
            return b""
        split = _safe_utf8_split(self._buf, len(self._buf) - self._lookback)
        if split == 0:
            return b""
        scan_area = bytes(self._buf[:split])
        self._buf = bytearray(self._buf[split:])
        return self._process(scan_area)

    def _feed_sentence(self) -> bytes:
        boundary = _find_sentence_boundary(bytes(self._buf))
        if boundary > 0:
            scan_area = bytes(self._buf[:boundary])
            self._buf = bytearray(self._buf[boundary:])
            return self._process(scan_area)
        if len(self._buf) >= self._max_sentence_bytes:
            # max 초과 시 lookback 폴백
            split = _safe_utf8_split(self._buf, len(self._buf) - self._lookback)
            if split == 0:
                return b""
            scan_area = bytes(self._buf[:split])
            self._buf = bytearray(self._buf[split:])
            return self._process(scan_area)
        return b""

    # @intent 스트림 EOF 시 버퍼에 남은 모든 바이트를 스캔·마스킹 후 방출
    # @sideEffect match_count > 0이면 스캔 완료 통계를 stderr에 출력
    # @mutates self._buf
    def flush(self) -> bytes:
        remaining = bytes(self._buf)
        self._buf = bytearray()
        result = self._process(remaining) if remaining else b""
        if self.match_count > 0:
            print(
                f"[LLM_GUARD] 스트리밍 응답 스캔 완료: {self._method} {self._url}"
                f" - 총 {self.match_count}개 PII 감지",
                file=sys.stderr,
            )
        return result

    def _process(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            print(f"[LLM_GUARD] UTF-8 디코딩 실패, 원본 전달: {e}", file=sys.stderr)
            return data
        masked, matches = _mask(text)
        self.match_count += len(matches)
        if not matches:
            return data
        for m in matches:
            _log_block(self._method, self._url, f"response:{m.pattern_name}", m.matched_value)
        if self._action == "warn":
            print(
                f"[LLM_GUARD] 응답 경고(스트림): {self._method} {self._url}"
                f" - {len(matches)}개 PII 감지",
                file=sys.stderr,
            )
            return data
        if self._action == "block" and not self._block_warned:
            print(
                "[LLM_GUARD] 경고: 스트리밍 응답에서 action=block은 redact로 다운그레이드됩니다.",
                file=sys.stderr,
            )
            self._block_warned = True
        return masked.encode("utf-8")


_SENTENCE_TERMINATORS = [
    b"\n\n",
    b"\n",
    b". ",
    b".\n",
    b"? ",
    b"?\n",
    b"! ",
    b"!\n",
    "。".encode("utf-8"),  # U+3002
    "？".encode("utf-8"),  # U+FF1F
    "！".encode("utf-8"),  # U+FF01
]


# @intent sentence 모드에서 버퍼를 최대한 크게 방출하기 위해 마지막 문장 종결 위치를 탐지
# @domainRule CJK 종결 부호(。？！)는 뒤에 공백 없이도 문장 끝으로 인정
# @domainRule 단독 ASCII ./!/?는 URL·소수점·이메일 false positive 방지를 위해 무시
def _find_sentence_boundary(buf: bytes) -> int:
    """버퍼 내 마지막 문장 종결 신호 직후 위치 반환. 없으면 -1.

    설계 결정:
    - rfind(마지막 경계) 사용: 버퍼 내 여러 문장을 한 번에 방출해 처리 효율을 높임.
    - CJK 종결 부호(。？！)는 뒤에 공백/개행 없이도 문장 끝으로 인정
      (CJK 텍스트는 공백 없이 연속됨).
    - 단독 ASCII ./?/! (공백/개행 미동반)는 URL/소수점/이메일 false positive 방지용 제외.
    """
    best = -1
    for term in _SENTENCE_TERMINATORS:
        idx = buf.rfind(term)
        if idx != -1:
            end = idx + len(term)
            if end > best:
                best = end
    return best


def _safe_utf8_split(buf: bytes, pos: int) -> int:
    """pos 위치가 UTF-8 codepoint 중간이면 codepoint 시작까지 backtrack."""
    if pos <= 0 or pos >= len(buf):
        return pos
    # UTF-8 continuation byte는 10xxxxxx (0x80-0xBF)
    # Start byte는 0xxxxxxx 또는 11xxxxxx
    while pos > 0 and (buf[pos] & 0xC0) == 0x80:
        pos -= 1
    return pos
