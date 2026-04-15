import os
import sys


def _bootstrap_pii_guard():
    if os.environ.get("PII_GUARD_DISABLE", "").lower() in ("1", "true"):
        return

    import pii_guard

    config_path = os.environ.get(
        "PII_GUARD_CONFIG",
        os.path.join(os.path.dirname(__file__), "..", "config", "pii_patterns.toml"),
    )
    pii_guard.load_config(config_path)

    from pii_guard_hook import PiiGuardFinder

    sys.meta_path.insert(0, PiiGuardFinder())

    print("[PII_GUARD] 활성화됨", file=sys.stderr)

    # --- Layer 2: 의미론적 분석 초기화 ---
    try:
        semantic_config = pii_guard.get_semantic_config()
        if semantic_config:
            config_dir = os.path.dirname(config_path)
            db_path = os.path.join(config_dir, semantic_config["db_path"])
            seed_path = os.path.join(config_dir, semantic_config["seed_path"])
            pii_guard.init_semantic(
                db_path,
                seed_path,
                semantic_config["injection_threshold"],
                semantic_config["jailbreak_threshold"],
            )
            print("[PII_GUARD] 의미론적 분석 활성화됨", file=sys.stderr)
    except Exception as e:
        print(f"[PII_GUARD] 의미론적 분석 초기화 실패 (Layer 1은 정상): {e}", file=sys.stderr)


try:
    _bootstrap_pii_guard()
except Exception as e:
    print(f"[PII_GUARD] 초기화 실패: {e}", file=sys.stderr)
