"""
K8s init container 데모 앱

이 스크립트에는 llm_guard 관련 코드가 전혀 없습니다.
init container가 주입한 sitecustomize.py가 Python 시작 시 자동으로 후킹합니다.
"""
import sys
import time

print("=" * 60)
print(" K8s Init Container 데모")
print(f" llm_guard loaded: {'llm_guard' in sys.modules}")
print(f" meta_path: {[type(m).__name__ for m in sys.meta_path]}")
print("=" * 60)

import requests


def try_request(name, content):
    print(f"\n[TEST] {name}")
    try:
        requests.post(
            "http://127.0.0.1:19999/v1/chat/completions",
            json={"messages": [{"role": "user", "content": content}]},
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
            print(f"  -> 기타: {cname}: {e}")


try_request("이메일 포함", "제 이메일은 user@example.com 입니다.")
try_request("전화번호 포함", "연락처: 010-1234-5678")
try_request("주민번호 포함", "주민등록번호: 850101-1234567")
try_request("정상 텍스트", "오늘 날씨가 좋네요.")

print("\n" + "=" * 60)
print(" 데모 완료")
print("=" * 60)
