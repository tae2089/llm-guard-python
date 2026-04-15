import sys
import os

# Rust 확장이 빌드된 경로를 추가
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
