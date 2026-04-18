# @index Python 인터프리터 시작 시 LLM Guard를 자동 활성화하는 부트스트랩 진입점.
import os
import sys


# @intent 기존 sitecustomize.py와 공존하기 위해 다른 sitecustomize를 체이닝 실행
# @domainRule LLM Guard 초기화 실패와 무관하게 항상 체이닝을 시도한다
# @sideEffect sys.modules["sitecustomize"]를 임시로 제거했다가 복원
def _chain_load_sitecustomize():
    """우리 경로를 제외하고 다른 sitecustomize.py가 있으면 실행"""
    our_dir = os.path.abspath(os.path.dirname(__file__))

    # 현재 모듈 캐시 제거
    saved = sys.modules.pop("sitecustomize", None)

    # 우리 경로를 임시 제거
    original_path = sys.path[:]
    sys.path = [p for p in sys.path if os.path.abspath(p) != our_dir]

    try:
        import importlib.util

        spec = importlib.util.find_spec("sitecustomize")
        if spec and spec.origin:
            other_dir = os.path.abspath(os.path.dirname(spec.origin))
            if other_dir != our_dir:
                print(
                    f"[LLM_GUARD] 체이닝: {spec.origin} 로드",
                    file=sys.stderr,
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
    except Exception as e:
        print(
            f"[LLM_GUARD] sitecustomize 체이닝 실패 (무시): {e}",
            file=sys.stderr,
        )
    finally:
        sys.path = original_path
        # 우리 모듈을 다시 등록
        if saved is not None:
            sys.modules["sitecustomize"] = saved


# @intent 설정 로드, urllib3 패치, Layer 2 semantic 초기화를 순서대로 수행해 LLM Guard를 활성화
# @domainRule LLM_GUARD_DISABLE=1 환경변수가 있으면 아무것도 하지 않는다
# @domainRule Layer 2 초기화 실패는 경고만 출력하고 Layer 1(PII 정규식)은 계속 동작한다
# @sideEffect sys.meta_path에 LlmGuardFinder를 삽입; urllib3.HTTPConnectionPool.urlopen 패치
# --- LLM Guard 부트스트랩 ---
def _bootstrap_llm_guard():
    if os.environ.get("LLM_GUARD_DISABLE", "").lower() in ("1", "true"):
        return

    import llm_guard

    config_path = os.environ.get(
        "LLM_GUARD_CONFIG",
        os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml"),
    )
    llm_guard.load_config(config_path)

    from llm_guard_hook import LlmGuardFinder, wrap_urllib3_if_available

    # urllib3가 이미 설치되어 있으면 즉시 래핑 (Python 3.12+ 호환)
    if not wrap_urllib3_if_available():
        # 아직 임포트 안 된 경우 finder로 지연 래핑
        sys.meta_path.insert(0, LlmGuardFinder())

    print("[LLM_GUARD] 활성화됨", file=sys.stderr)

    # --- Layer 2: 의미론적 분석 초기화 ---
    try:
        semantic_config = llm_guard.get_semantic_config()
        if semantic_config:
            config_dir = os.path.dirname(config_path)
            db_path = os.path.join(config_dir, semantic_config["db_path"])
            seed_path = os.path.join(config_dir, semantic_config["seed_path"])
            llm_guard.init_semantic(
                db_path,
                seed_path,
                semantic_config["injection_threshold"],
                semantic_config["jailbreak_threshold"],
            )
            print("[LLM_GUARD] 의미론적 분석 활성화됨", file=sys.stderr)
    except Exception as e:
        print(f"[LLM_GUARD] 의미론적 분석 초기화 실패 (Layer 1은 정상): {e}", file=sys.stderr)


# --- 실행 ---
try:
    _bootstrap_llm_guard()
except Exception as e:
    print(f"[LLM_GUARD] 초기화 실패: {e}", file=sys.stderr)

# 항상 체이닝 시도 (LLM Guard 실패해도 다른 도구는 실행)
_chain_load_sitecustomize()
