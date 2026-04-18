"""StreamingScanner 단위 테스트 (Phase 2 response streaming)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "pii_guard", "python"))
os.environ.setdefault("LLM_GUARD_CONFIG", os.path.join(ROOT, "config", "pii_patterns.toml"))

import llm_guard
try:
    llm_guard.load_config(os.environ["LLM_GUARD_CONFIG"])
except RuntimeError:
    pass  # 이미 다른 테스트에서 로드됨

from llm_guard._streaming import StreamingScanner


def test_short_chunk_below_lookback_returns_empty():
    """lookback(128) 미만 청크는 전부 버퍼에 hold → feed는 b"" 리턴."""
    scanner = StreamingScanner(action="redact", lookback_bytes=128)
    out = scanner.feed(b"hello world")
    assert out == b"", f"expected empty, got {out!r}"


def test_long_chunk_without_pii_emits_beyond_lookback():
    """lookback 초과분은 원문 그대로 방출, 끝 K바이트는 hold."""
    scanner = StreamingScanner(action="redact", lookback_bytes=16)
    payload = b"A" * 100  # no PII
    out = scanner.feed(payload)
    # 100 - 16 = 84 bytes should be emitted
    assert len(out) == 84, f"expected 84 bytes emitted, got {len(out)}"
    assert out == b"A" * 84


def test_flush_returns_remaining_buffer():
    scanner = StreamingScanner(action="redact", lookback_bytes=16)
    scanner.feed(b"hello")
    out = scanner.flush()
    assert out == b"hello"


def test_redact_masks_pii_in_emitted_chunk():
    """PII가 scan area에 들어오면 [REDACTED:이메일]으로 마스킹 방출."""
    scanner = StreamingScanner(action="redact", lookback_bytes=8)
    # 이메일을 scan area에 위치시키기 위해 lookback(8)보다 충분히 앞에
    payload = b"contact user@example.com and call later"
    out = scanner.feed(payload)
    assert b"user@example.com" not in out, f"raw PII leaked: {out!r}"
    assert b"[REDACTED:" in out, f"no redaction marker in {out!r}"


def test_redact_clean_text_passthrough():
    scanner = StreamingScanner(action="redact", lookback_bytes=8)
    payload = b"just a normal message no secrets here"
    out = scanner.feed(payload)
    # 원문 그대로 (끝 8바이트만 hold)
    assert out == payload[:-8]


def test_utf8_boundary_still_masks_korean_payload_with_pii():
    """한글 텍스트 + PII가 경계 근처에 있어도 reconstruct 시 마스킹되어야."""
    scanner = StreamingScanner(action="redact", lookback_bytes=8)
    payload = "담당자 연락처는 hello@example.com 입니다".encode("utf-8")
    out = scanner.feed(payload)
    tail = scanner.flush()
    full = out + tail
    decoded = full.decode("utf-8")
    assert "hello@example.com" not in decoded, f"PII leaked: {decoded!r}"
    assert "[REDACTED:" in decoded


def test_utf8_boundary_does_not_break_korean():
    """한글(3바이트)이 scan area 경계에서 절단되어도 깨지지 않아야 함."""
    scanner = StreamingScanner(action="redact", lookback_bytes=4)
    # '가'=0xEAB080, '나'=0xEB8298 each 3 bytes
    # 길이 조작해서 scan_area 끝이 UTF-8 중간 바이트에 걸리도록
    payload = ("안녕하세요 반갑습니다 테스트중입니다").encode("utf-8")
    out = scanner.feed(payload)
    tail = scanner.flush()
    # 합치면 원문 복원되어야 함
    assert (out + tail).decode("utf-8") == "안녕하세요 반갑습니다 테스트중입니다"


def test_warn_action_passes_through_raw_bytes(capsys):
    """action=warn → 원본 그대로 방출, match_count는 증가, stderr 경고 출력."""
    scanner = StreamingScanner(action="warn", lookback_bytes=8,
                                method="GET", url="http://test/")
    payload = b"email user@example.com and more padding padding padding"
    out = scanner.feed(payload)
    tail = scanner.flush()
    full = out + tail
    assert b"user@example.com" in full, "warn 모드는 원본 보존해야"
    assert b"[REDACTED:" not in full
    assert scanner.match_count >= 1, "match_count가 기록되어야"
    captured = capsys.readouterr()
    assert "경고" in captured.err or "warn" in captured.err.lower(), \
        f"warn 액션 시 stderr 경고가 출력되어야: {captured.err!r}"


def test_block_action_downgrades_to_redact_with_warning(capsys):
    """action=block은 스트리밍에서 redact로 다운그레이드 + stderr 경고 1회."""
    scanner = StreamingScanner(action="block", lookback_bytes=8)
    payload = b"email user@example.com and more padding padding padding"
    out = scanner.feed(payload)
    tail = scanner.flush()
    full = out + tail
    assert b"user@example.com" not in full, "block→redact 다운그레이드로 마스킹되어야"
    assert b"[REDACTED:" in full
    captured = capsys.readouterr()
    assert "block" in captured.err.lower() or "redact" in captured.err.lower(), \
        f"다운그레이드 경고가 stderr에 찍혀야: {captured.err!r}"


def test_pii_split_across_chunks_is_detected():
    """청크 경계에 걸친 PII도 lookback 윈도우로 잡아야 함."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32)
    # 청크1: 'user@exa' 뒤에 충분한 padding → 이메일 완성 전 일부만 보임
    # 청크2: 'mple.com' 으로 이메일 완성
    part1 = b"please contact user@exa"
    part2 = b"mple.com immediately for details padding padding padding padding"
    out1 = scanner.feed(part1)
    out2 = scanner.feed(part2)
    tail = scanner.flush()
    full = out1 + out2 + tail
    assert b"user@example.com" not in full, f"PII leaked: {full!r}"
    assert b"[REDACTED:" in full, f"no redaction in {full!r}"
