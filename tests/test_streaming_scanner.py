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

from llm_guard._streaming import StreamingScanner, _find_sentence_boundary


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
    part1 = b"please contact user@exa"
    part2 = b"mple.com immediately for details padding padding padding padding"
    out1 = scanner.feed(part1)
    out2 = scanner.feed(part2)
    tail = scanner.flush()
    full = out1 + out2 + tail
    assert b"user@example.com" not in full, f"PII leaked: {full!r}"
    assert b"[REDACTED:" in full, f"no redaction in {full!r}"


# ── _find_sentence_boundary 직접 테스트 (T6-T16) ──────────────────────────────

def test_fsb_double_newline():
    """\\n\\n → 그 직후 위치 반환."""
    buf = b"hello world\n\nmore text"
    pos = _find_sentence_boundary(buf)
    assert pos == 13, f"expected 13, got {pos}"  # len("hello world\n\n")


def test_fsb_period_space():
    """'. ' → 그 직후 위치 반환."""
    buf = b"End of sentence. Next sentence starts here"
    pos = _find_sentence_boundary(buf)
    assert pos == 17, f"expected 17, got {pos}"  # len("End of sentence. ")


def test_fsb_cjk_period():
    """'。' (U+3002, 3바이트) → 그 직후 위치 반환."""
    buf = "문장 끝입니다。다음 문장".encode("utf-8")
    cjk_period = "。".encode("utf-8")
    prefix = "문장 끝입니다".encode("utf-8")
    expected = len(prefix) + len(cjk_period)
    pos = _find_sentence_boundary(buf)
    assert pos == expected, f"expected {expected}, got {pos}"


def test_fsb_empty_buffer():
    """빈 버퍼 → -1."""
    assert _find_sentence_boundary(b"") == -1


def test_fsb_no_terminator():
    """종결 신호 없으면 -1."""
    buf = b"no sentence boundary here at all"
    assert _find_sentence_boundary(buf) == -1


def test_fsb_standalone_period_no_space():
    """단독 '.' (뒤에 공백/개행 없음) → -1 (URL/소수점 false positive 방지)."""
    buf = b"http://example.com/path.html"
    assert _find_sentence_boundary(buf) == -1


def test_fsb_question_newline():
    """'?\\n' → 그 직후 위치 반환."""
    buf = b"Is this right?\nYes it is."
    pos = _find_sentence_boundary(buf)
    # '?' 위치 13, '\n' 위치 14, 직후는 15
    assert pos == 15, f"expected 15, got {pos}"


def test_fsb_exclaim_space():
    """'! ' → 그 직후 위치 반환."""
    buf = b"Watch out! Something happened."
    pos = _find_sentence_boundary(buf)
    assert pos == 11, f"expected 11, got {pos}"  # len("Watch out! ")


def test_fsb_multiple_terminators_returns_last():
    """여러 종결 신호 → 마지막 것의 직후 위치 반환."""
    buf = b"First sentence. Second sentence. Third"
    pos = _find_sentence_boundary(buf)
    assert pos == 33, f"expected 33, got {pos}"  # len("First sentence. Second sentence. ")


def test_fsb_cjk_question_mark():
    """'？' (U+FF1F) → 그 직후 위치 반환."""
    buf = "정말인가？다음 내용".encode("utf-8")
    cjk_q = "？".encode("utf-8")
    prefix = "정말인가".encode("utf-8")
    expected = len(prefix) + len(cjk_q)
    pos = _find_sentence_boundary(buf)
    assert pos == expected, f"expected {expected}, got {pos}"


def test_fsb_period_at_end_no_space():
    """버퍼 끝이 '.'으로 끝나고 뒤에 아무것도 없으면 → -1."""
    buf = b"This is the end."
    assert _find_sentence_boundary(buf) == -1


# ── sentence 모드 feed/flush 동작 테스트 (T17-T25) ────────────────────────────

def test_sentence_mode_splits_at_double_newline():
    """sentence 모드: \\n\\n 경계에서 방출."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    data = b"First paragraph.\n\nSecond paragraph starts here padding padding"
    out = scanner.feed(data)
    # \n\n 이후까지 방출되어야 함
    assert b"\n\n" in out or out.endswith(b"\n\n") or b"First paragraph" in out, \
        f"sentence boundary not respected: {out!r}"
    assert len(out) > 0, "sentence 경계에서 방출이 없음"


def test_sentence_mode_holds_without_boundary():
    """sentence 모드: 종결 신호 없으면 전부 hold."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    data = b"no sentence boundary here at all"
    out = scanner.feed(data)
    assert out == b"", f"종결 신호 없으면 hold해야: {out!r}"


def test_sentence_mode_splits_at_period_space():
    """sentence 모드: '. ' 경계에서 방출."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    data = b"This is a sentence. And this is another one that keeps going on"
    out = scanner.feed(data)
    assert b"This is a sentence." in out, f"'. ' 경계까지 방출되어야: {out!r}"


def test_sentence_mode_fallback_on_max_exceeded():
    """sentence 모드: max_sentence_bytes 초과 시 lookback 폴백."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    # 종결 신호 없이 600바이트 → max 초과 → lookback 폴백으로 방출
    data = b"X" * 600
    out = scanner.feed(data)
    assert len(out) > 0, "max_sentence_bytes 초과 시 강제 방출되어야"
    assert len(out) == 600 - 32, f"lookback 폴백: 600-32=568 예상, got {len(out)}"


def test_sentence_mode_pii_across_chunks():
    """sentence 모드에서도 청크 경계 PII가 마스킹되어야."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    part1 = b"contact user@exa"
    part2 = b"mple.com for details. More text here padding padding padding"
    out1 = scanner.feed(part1)
    out2 = scanner.feed(part2)
    tail = scanner.flush()
    full = out1 + out2 + tail
    assert b"user@example.com" not in full, f"PII leaked in sentence mode: {full!r}"
    assert b"[REDACTED:" in full, f"no redaction in sentence mode: {full!r}"


def test_sentence_mode_cjk_period():
    """sentence 모드: 한글 마침표(。) 경계에서 방출."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    data = "첫 번째 문장입니다。두 번째 문장이 계속됩니다 패딩 패딩 패딩".encode("utf-8")
    out = scanner.feed(data)
    assert "。".encode("utf-8") in out or "첫 번째".encode("utf-8") in out, \
        f"CJK 마침표 경계 방출 실패: {out!r}"


def test_sentence_mode_flush_emits_all():
    """sentence 모드: flush()는 남은 버퍼 전체 방출."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=512)
    data = b"incomplete sentence without boundary"
    scanner.feed(data)
    tail = scanner.flush()
    assert tail == data, f"flush가 버퍼 전체 방출해야: {tail!r}"


def test_max_iters_sentence_mode():
    """`_max_iters_for_wrapped_read` sentence 모드에서 max_sentence_bytes*2."""
    scanner = StreamingScanner(action="redact", lookback_bytes=32,
                                split_strategy="sentence", max_sentence_bytes=1024)
    assert scanner._max_iters_for_wrapped_read == 2048, \
        f"expected 2048, got {scanner._max_iters_for_wrapped_read}"


def test_max_iters_lookback_mode():
    """`_max_iters_for_wrapped_read` lookback 모드에서 lookback*2."""
    scanner = StreamingScanner(action="redact", lookback_bytes=256,
                                split_strategy="lookback")
    assert scanner._max_iters_for_wrapped_read == 512, \
        f"expected 512, got {scanner._max_iters_for_wrapped_read}"
