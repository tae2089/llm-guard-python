"""
dd-trace-py 스타일 자동 후킹 데모

방법 1 (install API):
    import llm_guard
    llm_guard.install("/path/to/config.toml")

방법 2 (CLI 런처):
    llm-guard-run python this_script.py

이 데모는 방법 1을 사용합니다.
install() 한 줄로 모든 HTTP 요청이 자동 감시됩니다.
"""
import sys
import os

# --- 앱 코드에서 유일하게 필요한 셋업 ---
import llm_guard

config_path = os.environ.get("LLM_GUARD_CONFIG", "/app/config/pii_patterns.toml")
llm_guard.install(config_path)
# ----------------------------------------

import requests

print("=" * 60)
print(" 자동 후킹 데모 (install API)")
print(f" meta_path: {[type(m).__name__ for m in sys.meta_path]}")
print("=" * 60)


def try_request(name, content):
    print(f"\n[TEST] {name}")
    print(f"  body: {content[:60]}")
    try:
        requests.post(
            "http://127.0.0.1:19999/v1/chat/completions",
            headers={"Authorization": "Bearer sk-fake", "Content-Type": "application/json"},
            json={"model": "gpt-4", "messages": [{"role": "user", "content": content}]},
            timeout=1,
        )
        print("  -> 통과 (서버 도달)")
    except Exception as e:
        cname = type(e).__name__
        if "PiiBlocked" in cname:
            print(f"  -> [BLOCKED] PII 자동 차단: {e}")
        elif "InjectionBlocked" in cname:
            print(f"  -> [BLOCKED] 인젝션 자동 차단: {e}")
        elif "ConnectionError" in cname or "Timeout" in cname or "MaxRetry" in cname:
            print(f"  -> 통과 (PII 없음)")
        else:
            print(f"  -> 기타 오류: {cname}: {e}")


try_request("이메일 포함", "제 이메일은 user@example.com 입니다.")
try_request("전화번호 포함", "연락처: 010-1234-5678 로 전화주세요.")
try_request("주민번호 포함", "주민등록번호: 850101-1234567")
try_request("정상 텍스트", "오늘 날씨가 좋네요. 점심 메뉴 추천해주세요.")

print("\n" + "=" * 60)
print(" 데모 완료")
print("=" * 60)
