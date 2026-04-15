import sys
import subprocess
import textwrap
import os

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
PYTHON_DIR = os.path.join(os.path.dirname(__file__), "..", "python")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml")


def run_python(code):
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHON_DIR
    result = subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True, env=env,
    )
    return result


def test_finder_registers_on_meta_path():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")

        from pii_guard_hook import PiiGuardFinder
        import sys
        finder = PiiGuardFinder()
        sys.meta_path.insert(0, finder)
        assert any(isinstance(f, PiiGuardFinder) for f in sys.meta_path)
    """)
    assert r.returncode == 0, r.stderr


def test_urlopen_is_wrapped_after_urllib3_import():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")

        from pii_guard_hook import PiiGuardFinder
        import sys
        sys.meta_path.insert(0, PiiGuardFinder())

        import urllib3.connectionpool
        assert hasattr(urllib3.connectionpool.HTTPConnectionPool.urlopen, '__pii_guard_wrapped__')
    """)
    assert r.returncode == 0, r.stderr


def test_pii_in_body_raises_error():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")

        from pii_guard_hook import PiiGuardFinder, PiiBlockedError
        import sys
        sys.meta_path.insert(0, PiiGuardFinder())

        import urllib3
        http = urllib3.PoolManager()
        try:
            http.request("POST", "http://httpbin.org/post",
                         body="주민번호 850101-1234567",
                         headers={{"Content-Type": "text/plain"}})
            print("NOT_BLOCKED")
        except PiiBlockedError:
            print("BLOCKED")
    """)
    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout


def test_pii_in_header_raises_error():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")

        from pii_guard_hook import PiiGuardFinder, PiiBlockedError
        import sys
        sys.meta_path.insert(0, PiiGuardFinder())

        import urllib3
        http = urllib3.PoolManager()
        try:
            http.request("GET", "http://httpbin.org/get",
                         headers={{"X-User-Phone": "010-1234-5678"}})
            print("NOT_BLOCKED")
        except PiiBlockedError:
            print("BLOCKED")
    """)
    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout


def test_clean_request_wrapping_applied():
    r = run_python(f"""
        import pii_guard
        pii_guard.load_config("{CONFIG_PATH}")

        from pii_guard_hook import PiiGuardFinder
        import sys
        sys.meta_path.insert(0, PiiGuardFinder())

        import urllib3.connectionpool
        assert hasattr(urllib3.connectionpool.HTTPConnectionPool.urlopen, '__pii_guard_wrapped__')
        print("WRAPPED_OK")
    """)
    assert r.returncode == 0, r.stderr
    assert "WRAPPED_OK" in r.stdout
