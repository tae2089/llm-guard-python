"""llm-guard-python 스모크 테스트"""
import sys

import llm_guard

CONFIG = "/app/config/pii_patterns.toml"

llm_guard.load_config(CONFIG)

cases = [
    ("이메일", "user@example.com", True),
    ("전화번호", "010-1234-5678", True),
    ("주민번호", "850101-1234567", True),
    ("정상 텍스트", "안녕하세요, 오늘 날씨가 좋네요", False),
]

failed = 0
for name, text, should_detect in cases:
    result = llm_guard.scan(text)
    detected = result is not None
    ok = detected == should_detect
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {name}: {'탐지됨' if detected else '통과'}")
    if not ok:
        failed += 1

if failed:
    print(f"\n{failed}개 테스트 실패")
    sys.exit(1)
else:
    print("\n모든 스모크 테스트 통과!")
