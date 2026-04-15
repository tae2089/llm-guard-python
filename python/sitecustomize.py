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


try:
    _bootstrap_pii_guard()
except Exception as e:
    print(f"[PII_GUARD] 초기화 실패: {e}", file=sys.stderr)
