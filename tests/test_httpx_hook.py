"""httpx hook E2E 테스트 (GAP-1)"""
import http.server
import socket
import subprocess
import threading
import os
import textwrap
import tempfile
import asyncio

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


def _start_streaming_server(chunks: list[bytes], content_type: str = "text/plain; charset=utf-8"):
    """청크 단위로 데이터를 전송하는 서버"""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"".join(chunks)
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            for chunk in chunks:
                self.wfile.write(chunk)
                self.wfile.flush()

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
    env["LLM_GUARD_SEMANTIC"] = "0"
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [VENV_PYTHON, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=15,
        env=env,
    )


# ─── 동기 클라이언트 테스트 ───────────────────────────────────────────────────

def test_httpx_client_request_body_pii_blocked():
    """httpx.Client POST 요청 body에 PII → PiiBlockedError"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b"ok")
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
try:
    client = httpx.Client()
    client.post("http://127.0.0.1:{port}/api", content=b"email: user@example.com please")
    print("NO_ERROR")
except Exception as e:
    print(type(e).__name__)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "PiiBlockedError" in result.stdout, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_httpx_client_request_header_pii_blocked():
    """httpx.Client 요청 헤더에 PII → PiiBlockedError (urllib3 훅 동일 의미론)"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b"ok")
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
try:
    client = httpx.Client()
    client.get("http://127.0.0.1:{port}/api",
               headers={{"X-User-Email": "user@example.com"}})
    print("NO_ERROR")
except Exception as e:
    print(type(e).__name__)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "PiiBlockedError" in result.stdout, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_httpx_client_response_body_masked():
    """httpx.Client GET 응답 body PII → 마스킹 (non-streaming)"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    body = b'{"contact": "user@example.com", "info": "details here"}'
    srv, port = _start_server(body)
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
client = httpx.Client()
resp = client.get("http://127.0.0.1:{port}/api")
print(resp.text)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "user@example.com" not in result.stdout, f"PII leaked: {result.stdout!r}"
    assert "[REDACTED:" in result.stdout, f"no redaction: {result.stdout!r}"


def test_httpx_client_streaming_iter_bytes_masked():
    """httpx.Client streaming iter_bytes → PII 마스킹"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
stream_enabled = true
stream_lookback_bytes = 256
""")
    body = b"contact user@example.com for streaming details padding padding"
    srv, port = _start_server(body)
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
client = httpx.Client()
chunks = []
with client.stream("GET", "http://127.0.0.1:{port}/api") as resp:
    for chunk in resp.iter_bytes():
        chunks.append(chunk)
full = b"".join(chunks).decode("utf-8")
print(full)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "user@example.com" not in result.stdout, f"PII leaked: {result.stdout!r}"
    assert "[REDACTED:" in result.stdout, f"no redaction: {result.stdout!r}"


def test_httpx_client_streaming_chunk_boundary_pii_masked():
    """httpx.Client streaming 청크 경계 PII → 마스킹"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
stream_enabled = true
stream_lookback_bytes = 256
""")
    # PII가 두 청크에 걸쳐 있도록 서버가 나눠서 전송
    chunk1 = b"contact user@exa"
    chunk2 = b"mple.com now for more details padding padding padding padding"
    srv, port = _start_streaming_server([chunk1, chunk2])
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
client = httpx.Client()
chunks = []
with client.stream("GET", "http://127.0.0.1:{port}/api") as resp:
    for chunk in resp.iter_bytes(chunk_size=16):
        chunks.append(chunk)
full = b"".join(chunks).decode("utf-8")
print(full)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "user@example.com" not in result.stdout, f"PII leaked: {result.stdout!r}"
    assert "[REDACTED:" in result.stdout, f"no redaction: {result.stdout!r}"


def test_httpx_client_binary_response_skip():
    """httpx.Client 바이너리 응답 (image/png) → 수정 없이 통과"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    png_magic = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
    srv, port = _start_server(png_magic, content_type="image/png")
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
client = httpx.Client()
resp = client.get("http://127.0.0.1:{port}/img")
print(len(resp.content))
print("OK")
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "OK" in result.stdout, f"binary response failed: {result.stderr!r}"
    assert result.returncode == 0


def test_httpx_client_no_response_config_passthrough():
    """httpx.Client response_config 없음 → 응답 PII 그대로 통과"""
    cfg = _write_config(None)  # [response] 섹션 없음
    body = b"contact user@example.com for details"
    srv, port = _start_server(body)
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
client = httpx.Client()
resp = client.get("http://127.0.0.1:{port}/api")
print(resp.text)
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "user@example.com" in result.stdout, f"PII should pass through: {result.stdout!r}"


# ─── 비동기 클라이언트 테스트 ─────────────────────────────────────────────────

def test_httpx_async_client_request_pii_blocked():
    """httpx.AsyncClient GET 요청 PII → PiiBlockedError"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
""")
    srv, port = _start_server(b"ok")
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
import asyncio

async def main():
    try:
        async with httpx.AsyncClient() as client:
            await client.post("http://127.0.0.1:{port}/api", content=b"email: user@example.com")
        print("NO_ERROR")
    except Exception as e:
        print(type(e).__name__)

asyncio.run(main())
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "PiiBlockedError" in result.stdout, f"stdout={result.stdout!r} stderr={result.stderr!r}"


def test_httpx_async_client_streaming_masked():
    """httpx.AsyncClient 응답 streaming → PII 마스킹"""
    cfg = _write_config("""
[response]
enabled = true
action = "redact"
max_body_bytes = 1048576
stream_enabled = true
stream_lookback_bytes = 256
""")
    body = b"contact user@example.com for async streaming details padding padding"
    srv, port = _start_server(body)
    code = f"""
import llm_guard_httpx_hook
llm_guard_httpx_hook.activate()
import httpx
import asyncio

async def main():
    async with httpx.AsyncClient() as client:
        chunks = []
        async with client.stream("GET", "http://127.0.0.1:{port}/api") as resp:
            async for chunk in resp.aiter_bytes():
                chunks.append(chunk)
        full = b"".join(chunks).decode("utf-8")
        print(full)

asyncio.run(main())
"""
    result = _run(code, cfg)
    srv.shutdown()
    assert "user@example.com" not in result.stdout, f"PII leaked: {result.stdout!r}"
    assert "[REDACTED:" in result.stdout, f"no redaction: {result.stdout!r}"
