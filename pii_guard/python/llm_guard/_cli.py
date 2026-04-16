"""
llm-guard-run CLI — dd-trace-py 스타일 자동 계측 런처

사용법:
    llm-guard-run python my_app.py
    llm-guard-run gunicorn my_app:app
"""
import os
import sys
import subprocess


def main():
    if len(sys.argv) < 2:
        print("사용법: llm-guard-run <command> [args...]", file=sys.stderr)
        print("예시:  llm-guard-run python my_app.py", file=sys.stderr)
        sys.exit(1)

    # sitecustomize.py 위치 = 이 패키지의 _boot 디렉토리
    boot_dir = os.path.join(os.path.dirname(__file__), "_boot")

    # PYTHONPATH 앞에 추가 (기존 sitecustomize.py 체이닝 지원)
    existing = os.environ.get("PYTHONPATH", "")
    if existing:
        os.environ["PYTHONPATH"] = f"{boot_dir}{os.pathsep}{existing}"
    else:
        os.environ["PYTHONPATH"] = boot_dir

    # 사용자 명령 실행
    result = subprocess.run(sys.argv[1:])
    sys.exit(result.returncode)


if __name__ == "__main__":
    main()
