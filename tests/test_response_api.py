"""PyO3 mask + get_response_config 인터페이스 테스트"""
import subprocess
import os
import textwrap
import tempfile

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml")


def run_python(code, config_path=None):
    result = subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True,
    )
    return result


def test_mask_returns_tuple_of_text_and_matches():
    r = run_python(f"""
        import llm_guard
        llm_guard.load_config("{CONFIG_PATH}")
        masked, matches = llm_guard.mask("메일 user@example.com 전송")
        assert "[REDACTED:이메일]" in masked
        assert "user@example.com" not in masked
        assert len(matches) == 1
        assert matches[0].pattern_name == "이메일"
        assert matches[0].matched_value == "user@example.com"
    """)
    assert r.returncode == 0, r.stderr


def test_mask_clean_text_returns_original():
    r = run_python(f"""
        import llm_guard
        llm_guard.load_config("{CONFIG_PATH}")
        masked, matches = llm_guard.mask("안녕하세요")
        assert masked == "안녕하세요"
        assert matches == []
    """)
    assert r.returncode == 0, r.stderr


def test_get_response_config_returns_dict_when_enabled():
    """[response] 섹션이 있는 임시 설정 파일로 테스트"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write("""
[patterns]
[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'

[response]
enabled = true
action = "redact"
max_body_bytes = 524288
""")
        path = f.name

    try:
        r = run_python(f"""
            import llm_guard
            llm_guard.load_config("{path}")
            cfg = llm_guard.get_response_config()
            assert cfg is not None
            assert cfg["action"] == "redact"
            assert cfg["max_body_bytes"] == 524288
        """)
        assert r.returncode == 0, r.stderr
    finally:
        os.unlink(path)


def test_get_response_config_exposes_stream_fields():
    """[response]의 stream_enabled / stream_lookback_bytes 노출 (하위호환 기본값 포함)"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write("""
[patterns]
[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'

[response]
enabled = true
action = "redact"
max_body_bytes = 524288
""")
        path = f.name

    try:
        r = run_python(f"""
            import llm_guard
            llm_guard.load_config("{path}")
            cfg = llm_guard.get_response_config()
            assert cfg["stream_enabled"] is True, f"default stream_enabled should be True, got {{cfg.get('stream_enabled')!r}}"
            assert cfg["stream_lookback_bytes"] == 256, f"default lookback should be 256, got {{cfg.get('stream_lookback_bytes')!r}}"
        """)
        assert r.returncode == 0, r.stderr
    finally:
        os.unlink(path)


def test_get_response_config_returns_none_when_absent():
    """[response] 섹션 없는 임시 설정 파일로 테스트"""
    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        f.write("""
[patterns]
[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'
""")
        path = f.name

    try:
        r = run_python(f"""
            import llm_guard
            llm_guard.load_config("{path}")
            cfg = llm_guard.get_response_config()
            assert cfg is None
        """)
        assert r.returncode == 0, r.stderr
    finally:
        os.unlink(path)
