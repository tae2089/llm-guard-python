"""
LLM Guard - PII 탐지 및 프롬프트 인젝션 차단 라이브러리

사용법:
    import llm_guard
    llm_guard.install("/path/to/config.toml")
    # 이후 모든 urllib3 HTTP 요청 자동 감시
"""
from llm_guard._guard import (
    load_config,
    scan,
    mask,
    log_block,
    get_semantic_config,
    get_response_config,
    init_semantic,
    analyze,
    ScanResult,
    SemanticMatchResult,
)
from llm_guard._hook import (
    PiiBlockedError,
    InjectionBlockedError,
)

__all__ = [
    "load_config",
    "scan",
    "mask",
    "log_block",
    "get_semantic_config",
    "get_response_config",
    "init_semantic",
    "analyze",
    "ScanResult",
    "SemanticMatchResult",
    "PiiBlockedError",
    "InjectionBlockedError",
    "install",
]


def install(config_path=None):
    """LLM Guard를 설치하여 모든 urllib3 HTTP 요청을 자동으로 감시합니다.

    Args:
        config_path: PII 패턴 설정 파일 경로. None이면 LLM_GUARD_CONFIG 환경변수 사용.
    """
    import os
    import sys

    if os.environ.get("LLM_GUARD_DISABLE", "").lower() in ("1", "true"):
        return

    # 설정 로딩
    if config_path is None:
        config_path = os.environ.get("LLM_GUARD_CONFIG")
    if config_path is None:
        raise ValueError(
            "config_path를 지정하거나 LLM_GUARD_CONFIG 환경변수를 설정하세요"
        )

    load_config(config_path)

    # urllib3 후킹
    from llm_guard._hook import LlmGuardFinder, wrap_urllib3_if_available

    if not wrap_urllib3_if_available():
        sys.meta_path.insert(0, LlmGuardFinder())

    print("[LLM_GUARD] 활성화됨", file=sys.stderr)

    # Layer 2: 의미론적 분석 초기화
    try:
        semantic_config = get_semantic_config()
        if semantic_config:
            config_dir = os.path.dirname(config_path)
            db_path = os.path.join(config_dir, semantic_config["db_path"])
            seed_path = os.path.join(config_dir, semantic_config["seed_path"])
            init_semantic(
                db_path,
                seed_path,
                semantic_config["injection_threshold"],
                semantic_config["jailbreak_threshold"],
            )
            print("[LLM_GUARD] 의미론적 분석 활성화됨", file=sys.stderr)
    except Exception as e:
        print(
            f"[LLM_GUARD] 의미론적 분석 초기화 실패 (Layer 1은 정상): {e}",
            file=sys.stderr,
        )
