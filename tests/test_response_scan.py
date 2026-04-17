"""응답 스캔 E2E: 로컬 HTTP 서버가 PII를 응답으로 보내고, 훅이 마스킹/차단하는지 검증"""
import http.server
import socket
import subprocess
import threading
import os
import textwrap
import tempfile

VENV_PYTHON = os.path.join(os.path.dirname(__file__), "..", ".venv", "bin", "python")
PYTHON_DIR = os.path.join(os.path.dirname(__file__), "..", "python")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_server(body: bytes, content_type: str = "application/json"):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args, **kwargs):
            pass

    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


def _write_config(response_section: str | None) -> str:
    pattern_block = r"""
[patterns]
[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

[patterns.phone]
name = "전화번호"
regex = '01[016789]-?\d{3,4}-?\d{4}'
"""
    content = pattern_block
    if response_section is not None:
        content += "\n" + response_section
    f = tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False)
    f.write(content)
    f.close()
    return f.name


def _run(code: str, config_path: str, env_extra=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHON_DIR
    env["LLM_GUARD_CONFIG"] = config_path
    env.pop("LLM_GUARD_DISABLE", None)
    env["LLM_GUARD_SEMANTIC"] = "0"  # 응답 스캔 테스트에서는 Layer 2 비활성
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True, text=True, env=env,
    )


def test_response_body_with_email_is_redacted():
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b'{"msg": "contact us at support@example.com"}')
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/")
            body = resp.data.decode("utf-8")
            print("BODY:" + body)
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "[REDACTED:이메일]" in r.stdout
        assert "support@example.com" not in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_response_disabled_leaves_body_intact():
    cfg = _write_config(None)  # no [response] section
    srv, port = _start_server(b'{"email": "user@example.com"}')
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/")
            print("BODY:" + resp.data.decode("utf-8"))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" in r.stdout
        assert "[REDACTED" not in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_response_block_action_raises_error():
    cfg = _write_config("""
[response]
enabled = true
action = "block"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b'{"email": "leaked@example.com"}')
    try:
        r = _run(f"""
            import urllib3
            from llm_guard_hook import PiiBlockedError
            http = urllib3.PoolManager()
            try:
                resp = http.request("GET", "http://127.0.0.1:{port}/")
                print("NOT_BLOCKED")
            except PiiBlockedError as e:
                print("BLOCKED:" + str(e))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "BLOCKED" in r.stdout
        assert "NOT_BLOCKED" not in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_binary_content_type_is_not_scanned():
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    # 바이너리 응답에 이메일 문자열이 섞여 있어도 스캔 skip
    srv, port = _start_server(
        b'\x89PNG\r\n\x1a\nuser@example.com rest', content_type="image/png"
    )
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/")
            print("LEN:" + str(len(resp.data)))
            print("HAS_EMAIL:" + str(b"user@example.com" in resp.data))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "HAS_EMAIL:True" in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def _start_chunked_server(chunks: list[bytes], content_type: str = "text/plain"):
    """Transfer-Encoding: chunked로 여러 청크를 전송하는 서버."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for c in chunks:
                self.wfile.write(f"{len(c):x}\r\n".encode())
                self.wfile.write(c)
                self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")

        def log_message(self, *args, **kwargs):
            pass

    port = _free_port()
    srv = http.server.HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def test_streaming_response_pii_is_redacted():
    """preload_content=False + resp.stream() 경로에서도 PII가 마스킹되어야."""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    # 기본 lookback(256) 사용. PII 뒤에 lookback 이상의 padding이 있어야 안전하게 스캔됨.
    padding = b" padding" * 40  # 320 bytes, well over lookback=256
    chunks = [
        b"Hello, the contact ",
        b"email is user@example.com",
        b" and phone 010-1234-5678",
        padding + b" end",
    ]
    srv, port = _start_chunked_server(chunks)
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/",
                                preload_content=False)
            received = b""
            for chunk in resp.stream(64):
                received += chunk
            resp.release_conn()
            text = received.decode("utf-8")
            print("BODY:" + text)
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" not in r.stdout, f"PII leaked: {r.stdout}"
        assert "010-1234-5678" not in r.stdout, f"phone leaked: {r.stdout}"
        assert "[REDACTED:" in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_streaming_disabled_leaves_body_intact():
    """stream_enabled=false면 스트리밍 경로 래핑 skip."""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
stream_enabled = false
""")
    chunks = [b"email user@example.com padding padding padding padding"]
    srv, port = _start_chunked_server(chunks)
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/",
                                preload_content=False)
            received = b""
            for chunk in resp.stream(64):
                received += chunk
            resp.release_conn()
            print("BODY:" + received.decode("utf-8"))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" in r.stdout
        assert "[REDACTED" not in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_streaming_binary_content_type_skipped():
    """이진 Content-Type 스트림은 래핑 skip."""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    chunks = [b"\x89PNG\r\n\x1a\nuser@example.com padding padding padding"]
    srv, port = _start_chunked_server(chunks, content_type="image/png")
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/",
                                preload_content=False)
            received = b""
            for chunk in resp.stream(64):
                received += chunk
            resp.release_conn()
            print("HAS_EMAIL:" + str(b"user@example.com" in received))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "HAS_EMAIL:True" in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_sse_stream_pii_is_redacted_and_format_preserved():
    """SSE text/event-stream 형식에서 PII 마스킹되고 'data: ' 구분자 보존."""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    padding = b" padding" * 40
    # SSE 포맷: 각 이벤트는 'data: ...\n\n'
    chunks = [
        b"data: Hello user\n\n",
        b"data: email is user@example.com\n\n",
        b"data: phone 010-1234-5678\n\n",
        padding + b"\n\n",
    ]
    srv, port = _start_chunked_server(chunks, content_type="text/event-stream")
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/",
                                preload_content=False)
            received = b""
            for chunk in resp.stream(64):
                received += chunk
            resp.release_conn()
            text = received.decode("utf-8")
            print("BODY_START")
            print(text)
            print("BODY_END")
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" not in r.stdout, f"PII leaked: {r.stdout}"
        assert "010-1234-5678" not in r.stdout
        assert "[REDACTED:" in r.stdout
        # SSE 포맷 보존 확인: 'data: ' 구분자가 유지됨
        assert "data: " in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_non_streaming_path_still_redacts_regression():
    """Phase 2 도입 후에도 Phase 1 비스트리밍 경로 동작 불변."""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b'{"msg": "ping user@example.com done"}')
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/")
            print("BODY:" + resp.data.decode("utf-8"))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" not in r.stdout
        assert "[REDACTED:이메일]" in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_streaming_block_action_downgrades_to_redact():
    """action=block + 스트리밍 → redact 다운그레이드, stderr 경고 출력."""
    cfg = _write_config("""
[response]
enabled = true
action = "block"
max_body_bytes = 1048576
""")
    padding = b" padding" * 40
    chunks = [
        b"leaked contact user@example.com ",
        padding + b" end",
    ]
    srv, port = _start_chunked_server(chunks)
    try:
        r = _run(f"""
            import urllib3
            http = urllib3.PoolManager()
            resp = http.request("GET", "http://127.0.0.1:{port}/",
                                preload_content=False)
            received = b""
            for chunk in resp.stream(64):
                received += chunk
            resp.release_conn()
            print("BODY:" + received.decode("utf-8"))
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "user@example.com" not in r.stdout, "block→redact 다운그레이드 마스킹 실패"
        assert "[REDACTED:" in r.stdout
        # stderr에 다운그레이드 경고 출력
        assert "block" in r.stderr.lower() or "redact" in r.stderr.lower(), \
            f"다운그레이드 경고 누락: {{r.stderr!r}}"
    finally:
        srv.shutdown()
        os.unlink(cfg)


def test_request_pii_still_blocked_regression():
    """응답 스캔 추가 후에도 요청 PII 차단은 유지"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b'{"ok": true}')
    try:
        r = _run(f"""
            import urllib3
            from llm_guard_hook import PiiBlockedError
            http = urllib3.PoolManager()
            try:
                http.request("POST", "http://127.0.0.1:{port}/",
                             body='{{"email": "user@example.com"}}',
                             headers={{"Content-Type": "application/json"}})
                print("NOT_BLOCKED")
            except PiiBlockedError:
                print("BLOCKED")
        """, cfg)
        assert r.returncode == 0, r.stderr
        assert "BLOCKED" in r.stdout
    finally:
        srv.shutdown()
        os.unlink(cfg)
