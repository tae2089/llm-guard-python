# GAP-5 해소: 단일 소스(pii_guard/python/llm_guard/_httpx_hook.py)의 thin re-export.
# 이 파일을 직접 수정하지 말고 pii_guard/python/llm_guard/_httpx_hook.py를 수정하세요.
from llm_guard._httpx_hook import *  # noqa: F401, F403
from llm_guard._httpx_hook import (
    activate,
    wrap_httpx_if_available,
)
