"""
llm-guard-run 전용 sitecustomize.py

Python 시작 시 자동 실행되어 LLM Guard를 부트스트랩합니다.
다른 sitecustomize.py가 있으면 체이닝합니다 (Datadog 방식).
"""
import os
import sys


def _chain_load_sitecustomize():
    """우리 경로를 제외하고 다른 sitecustomize.py가 있으면 실행"""
    our_dir = os.path.abspath(os.path.dirname(__file__))

    saved = sys.modules.pop("sitecustomize", None)
    original_path = sys.path[:]
    sys.path = [p for p in sys.path if os.path.abspath(p) != our_dir]

    try:
        import importlib.util

        spec = importlib.util.find_spec("sitecustomize")
        if spec and spec.origin:
            other_dir = os.path.abspath(os.path.dirname(spec.origin))
            if other_dir != our_dir:
                print(f"[LLM_GUARD] 체이닝: {spec.origin} 로드", file=sys.stderr)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
    except Exception as e:
        print(f"[LLM_GUARD] sitecustomize 체이닝 실패 (무시): {e}", file=sys.stderr)
    finally:
        sys.path = original_path
        if saved is not None:
            sys.modules["sitecustomize"] = saved


def _bootstrap():
    if os.environ.get("LLM_GUARD_DISABLE", "").lower() in ("1", "true"):
        return

    import llm_guard

    config_path = os.environ.get("LLM_GUARD_CONFIG")
    if config_path:
        llm_guard.install(config_path)
    else:
        print("[LLM_GUARD] LLM_GUARD_CONFIG 환경변수가 없어 비활성화됨", file=sys.stderr)


try:
    _bootstrap()
except Exception as e:
    print(f"[LLM_GUARD] 초기화 실패: {e}", file=sys.stderr)

_chain_load_sitecustomize()
