"""Streaming response PII scanner (Phase 2)."""
import sys
from llm_guard._guard import mask as _mask
from llm_guard._guard import log_block as _log_block


class StreamingScanner:
    """청크 경계 PII를 잡기 위한 lookback window 스캐너."""

    def __init__(self, action: str = "redact", lookback_bytes: int = 256,
                 method: str = "GET", url: str = ""):
        self._buf = bytearray()
        self._lookback = lookback_bytes
        self._action = action
        self._block_warned = False
        self._method = method
        self._url = url
        self.match_count = 0

    def feed(self, chunk: bytes) -> bytes:
        """새 청크를 받아 방출 가능한 바이트를 리턴."""
        self._buf.extend(chunk)
        if len(self._buf) <= self._lookback:
            return b""

        split = len(self._buf) - self._lookback
        split = _safe_utf8_split(self._buf, split)
        if split == 0:
            return b""

        scan_area = bytes(self._buf[:split])
        held = self._buf[split:]
        self._buf = bytearray(held)
        return self._process(scan_area)

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


def _safe_utf8_split(buf: bytes, pos: int) -> int:
    """pos 위치가 UTF-8 codepoint 중간이면 codepoint 시작까지 backtrack."""
    if pos <= 0 or pos >= len(buf):
        return pos
    # UTF-8 continuation byte는 10xxxxxx (0x80-0xBF)
    # Start byte는 0xxxxxxx 또는 11xxxxxx
    while pos > 0 and (buf[pos] & 0xC0) == 0x80:
        pos -= 1
    return pos
