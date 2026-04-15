import subprocess
import sys
import os
import textwrap

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml")


def run_python(code):
    """각 테스트를 별도 프로세스로 실행 (OnceLock 초기화 문제 회피)"""
    result = subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True,
    )
    return result


def test_scan_returns_none_for_clean_text():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")
        result = pii_guard.scan("안녕하세요")
        assert result is None
    """)
    assert r.returncode == 0, r.stderr


def test_scan_detects_email():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")
        result = pii_guard.scan("메일은 user@example.com 입니다")
        assert result is not None
        assert result.pattern_name == "이메일"
        assert result.matched_value == "user@example.com"
    """)
    assert r.returncode == 0, r.stderr


def test_scan_detects_pii_in_phone():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")
        result = pii_guard.scan("전화번호 010-1234-5678")
        assert result is not None
        assert hasattr(result, "pattern_name")
        assert hasattr(result, "matched_value")
    """)
    assert r.returncode == 0, r.stderr


def test_scan_without_load_config_raises():
    r = run_python("""
        import pii_guard
        try:
            pii_guard.scan("test")
            assert False, "should have raised"
        except RuntimeError:
            pass
    """)
    assert r.returncode == 0, r.stderr
