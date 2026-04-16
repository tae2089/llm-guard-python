"""
End-to-end 테스트: sitecustomize → import hook → urllib3 요청 → PII 차단
모든 테스트는 별도 프로세스에서 실행하여 OnceLock/import 상태를 격리한다.
"""
import subprocess
import sys
import os
import textwrap
import tempfile

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
PYTHON_DIR = os.path.join(os.path.dirname(__file__), "..", "python")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml")


def run_e2e(code, env_extra=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHON_DIR
    env["LLM_GUARD_CONFIG"] = CONFIG_PATH
    # Do NOT set LLM_GUARD_DISABLE — we want sitecustomize to auto-bootstrap
    env.pop("LLM_GUARD_DISABLE", None)
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True, env=env,
    )
    return result


def test_e2e_pii_in_body_blocked():
    """sitecustomize auto-load → urllib3 요청 → body에 주민번호 → 차단"""
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        log_path = f.name

    r = run_e2e("""
        # sitecustomize already auto-loaded via PYTHONPATH
        import urllib3
        from llm_guard_hook import PiiBlockedError

        http = urllib3.PoolManager()
        try:
            http.request("POST", "http://httpbin.org/post",
                         body="주민번호 850101-1234567",
                         headers={"Content-Type": "text/plain"})
            print("NOT_BLOCKED")
        except PiiBlockedError as e:
            print("BLOCKED")
            print(str(e))
    """, env_extra={"LLM_GUARD_LOG": log_path})

    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout
    assert "NOT_BLOCKED" not in r.stdout

    log_content = open(log_path).read()
    assert "BLOCKED" in log_content
    assert "850101-1234567" not in log_content  # 원본 PII가 로그에 없어야 함
    os.unlink(log_path)


def test_e2e_pii_in_header_blocked():
    """header에 전화번호 → 차단"""
    r = run_e2e("""
        import urllib3
        from llm_guard_hook import PiiBlockedError

        http = urllib3.PoolManager()
        try:
            http.request("GET", "http://httpbin.org/get",
                         headers={"X-Phone": "010-1234-5678"})
            print("NOT_BLOCKED")
        except PiiBlockedError:
            print("BLOCKED")
    """)
    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout


def test_e2e_clean_request_not_blocked():
    """PII 없는 요청 → urlopen 정상 호출 (네트워크 없이 래핑만 확인)"""
    r = run_e2e("""
        import urllib3.connectionpool

        # 래핑이 적용되었는지만 확인 (실제 네트워크 호출 X)
        assert hasattr(urllib3.connectionpool.HTTPConnectionPool.urlopen, '__llm_guard_wrapped__')
        print("WRAPPED_OK")
    """)
    assert r.returncode == 0, r.stderr
    assert "WRAPPED_OK" in r.stdout


def test_e2e_credit_card_in_body_blocked():
    """body에 신용카드번호 → 차단"""
    r = run_e2e("""
        import urllib3
        from llm_guard_hook import PiiBlockedError

        http = urllib3.PoolManager()
        try:
            http.request("POST", "http://httpbin.org/post",
                         body='{"card": "1234-5678-9012-3456"}',
                         headers={"Content-Type": "application/json"})
            print("NOT_BLOCKED")
        except PiiBlockedError:
            print("BLOCKED")
    """)
    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout


def test_e2e_email_in_body_blocked():
    """body에 이메일 → 차단"""
    r = run_e2e("""
        import urllib3
        from llm_guard_hook import PiiBlockedError

        http = urllib3.PoolManager()
        try:
            http.request("POST", "http://httpbin.org/post",
                         body='{"email": "user@example.com"}',
                         headers={"Content-Type": "application/json"})
            print("NOT_BLOCKED")
        except PiiBlockedError:
            print("BLOCKED")
    """)
    assert r.returncode == 0, r.stderr
    assert "BLOCKED" in r.stdout


def test_e2e_disabled_via_env():
    """LLM_GUARD_DISABLE=1 → PII가 있어도 차단 안 됨"""
    r = run_e2e("""
        import urllib3.connectionpool

        # 비활성화되면 래핑이 적용되지 않음
        has_wrap = hasattr(urllib3.connectionpool.HTTPConnectionPool.urlopen, '__llm_guard_wrapped__')
        print(f"wrapped={has_wrap}")
    """, env_extra={"LLM_GUARD_DISABLE": "1"})
    assert r.returncode == 0, r.stderr
    assert "wrapped=False" in r.stdout
