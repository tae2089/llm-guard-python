import subprocess
import sys
import os
import textwrap

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
PYTHON_DIR = os.path.join(os.path.dirname(__file__), "..", "python")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml")


def run_with_sitecustomize(code, env_extra=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHON_DIR
    env["LLM_GUARD_CONFIG"] = CONFIG_PATH
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True, env=env,
    )
    return result


def test_sitecustomize_activates():
    r = run_with_sitecustomize("""
        import sitecustomize
        import sys
        from llm_guard_hook import LlmGuardFinder
        assert any(isinstance(f, LlmGuardFinder) for f in sys.meta_path)
    """)
    assert r.returncode == 0, r.stderr
    assert "[LLM_GUARD] 활성화됨" in r.stderr


def test_sitecustomize_disabled():
    r = run_with_sitecustomize("""
        import sitecustomize
        import sys
        from llm_guard_hook import LlmGuardFinder
        assert not any(isinstance(f, LlmGuardFinder) for f in sys.meta_path)
    """, env_extra={"LLM_GUARD_DISABLE": "1"})
    assert r.returncode == 0, r.stderr
    assert "[LLM_GUARD] 활성화됨" not in r.stderr


def test_sitecustomize_bad_config_does_not_crash():
    r = run_with_sitecustomize("""
        print("python started ok")
    """, env_extra={"LLM_GUARD_CONFIG": "/nonexistent/path.toml"})
    assert r.returncode == 0, r.stderr
    assert "[LLM_GUARD] 초기화 실패" in r.stderr
