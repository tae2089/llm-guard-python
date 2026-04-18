# llm-guard-python

LLM 요청에서 PII(개인정보)를 자동 탐지/차단하고, 프롬프트 인젝션 및 탈옥 시도를 감지하는 라이브러리.

Rust(PyO3) 기반으로 빠르고, `urllib3`를 자동 후킹하여 앱 코드 수정 없이 모든 HTTP 요청을 감시합니다.

## 설치

```bash
pip install llm-guard-python
```

## 사용법

### 방법 1: install() API

앱 진입점에 2줄 추가:

```python
import llm_guard
llm_guard.install("/path/to/pii_patterns.toml")

# 이후 모든 urllib3 기반 HTTP 요청 자동 감시
# (requests, openai, anthropic, httpx 등)
import openai
client = openai.OpenAI()
client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "제 이메일은 user@example.com"}]
)
# -> PiiBlockedError: 이메일 발견
```

### 방법 2: CLI 런처 (dd-trace-py 스타일)

앱 코드 수정 0줄:

```bash
LLM_GUARD_CONFIG=/path/to/pii_patterns.toml llm-guard-run python my_app.py
```

### 방법 3: 환경변수

```bash
export LLM_GUARD_CONFIG=/path/to/pii_patterns.toml
export LLM_GUARD_SEMANTIC=0  # 의미론적 분석 비활성화 (선택)
export LLM_GUARD_DISABLE=1   # 전체 비활성화 (선택)
```

## 탐지 레이어

| 레이어 | 방향 | 방식 | 동작 |
|--------|------|------|------|
| Layer 1 | 요청 | 정규식 PII 탐지 | 이메일, 전화번호, 주민번호, 신용카드 등 → 즉시 차단 |
| Layer 2 | 요청 | 임베딩 유사도 (fastembed) | 프롬프트 인젝션 → 차단, 탈옥 시도 → 경고 |
| Layer 3 | 응답 | 정규식 PII 탐지 | LLM 응답의 PII 유출 → 마스킹 또는 차단 |

## 아키텍처

### 전체 구조

```
┌─────────────────────────────────────────────────────────────┐
│                       Python 앱                              │
│  openai / anthropic / httpx / requests / urllib3 직접 호출  │
└────────────────┬──────────────────────┬─────────────────────┘
                 │                      │
        urllib3 hook               httpx hook
   (_hook.py monkey-patch)   (_httpx_hook.py monkey-patch)
                 │                      │
                 └──────────┬───────────┘
                            ▼
              ┌─────────────────────────┐
              │      Rust 코어 (PyO3)   │
              │  ┌──────────────────┐   │
              │  │ Layer 1: 정규식  │   │  ← 요청 body/header PII 탐지
              │  │  detector.rs     │   │
              │  ├──────────────────┤   │
              │  │ Layer 2: 임베딩  │   │  ← 프롬프트 인젝션/탈옥 탐지
              │  │  semantic.rs     │   │    (FastEmbed bge-m3 + DuckDB vss)
              │  │  vectordb.rs     │   │
              │  └──────────────────┘   │
              └─────────────────────────┘
                            │
                  차단 → PiiBlockedError
                  경고 → stderr 로그
                  통과 → 실제 HTTP 요청 전송
                            │
                            ▼
                     LLM API 서버
                            │
                     응답 수신
                            ▼
              ┌─────────────────────────┐
              │  Layer 3: 응답 PII 스캔 │
              │  StreamingScanner       │  ← streaming 청크 경계 PII 탐지
              │  (_streaming.py)        │    lookback / sentence 경계 모드
              └─────────────────────────┘
                            │
                  redact → [REDACTED:패턴명] 치환
                  block  → PiiBlockedError
                  warn   → 원본 반환 + 로그
```

### 핵심 모듈

| 모듈 | 위치 | 역할 |
|------|------|------|
| `_guard.abi3.so` | `llm_guard/` | Rust/PyO3 확장 — scan, mask, analyze |
| `_hook.py` | `llm_guard/` | urllib3 `HTTPConnectionPool.urlopen` monkey-patch |
| `_httpx_hook.py` | `llm_guard/` | httpx `Client.send` / `AsyncClient.send` monkey-patch |
| `_streaming.py` | `llm_guard/` | `StreamingScanner` — 청크 스트림 PII redaction |
| `__init__.py` | `llm_guard/` | `install()` 공개 API — urllib3 + httpx 동시 활성화 |
| `_boot/sitecustomize.py` | `llm_guard/` | Python 시작 시 자동 부트스트랩 (zero-config 배포) |

### HTTP 라이브러리 커버리지

| 라이브러리 | 후킹 경로 | 커버 여부 |
|-----------|-----------|-----------|
| `openai` SDK v1+ | httpx → `_httpx_hook` | ✅ |
| `anthropic` SDK v0.20+ | httpx → `_httpx_hook` | ✅ |
| `requests` | urllib3 → `_hook` | ✅ |
| `httpx` 직접 사용 | `_httpx_hook` | ✅ |
| `urllib3` 직접 사용 | `_hook` | ✅ |
| `aiohttp` | 미지원 | ❌ |

## 설정 파일 (pii_patterns.toml)

```toml
[patterns]

[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'

[patterns.phone]
name = "전화번호"
regex = '01[016789]-?\d{3,4}-?\d{4}'

[patterns.resident_id]
name = "주민등록번호"
regex = '\d{6}-?[1-4]\d{6}'

# 응답 스캔 (LLM 응답의 PII 유출 방지)
[response]
enabled = true
action = "redact"      # "redact" | "block" | "warn"
max_body_bytes = 1048576  # 1MB 초과 응답은 스캔 skip
```

### 응답 스캔 action

| action | 동작 |
|--------|------|
| `redact` | PII를 `[REDACTED:패턴명]`으로 치환 후 앱에 반환 (기본값) |
| `block` | PII 발견 시 `PiiBlockedError` 발생 |
| `warn` | 로그 기록만, 응답 내용 변경 없음 |

> **주의:** `[response]` 섹션이 없거나 `enabled = false`이면 응답 스캔은 비활성입니다.  
> Content-Type이 바이너리(image/*, application/octet-stream 등)인 응답은 항상 skip합니다.

## 예외 처리

```python
from llm_guard import PiiBlockedError, InjectionBlockedError

try:
    response = client.chat.completions.create(...)
except PiiBlockedError as e:
    # 요청 PII 차단 또는 응답 PII 차단(action="block") 시 발생
    print(f"PII 차단: {e}")
except InjectionBlockedError as e:
    print(f"인젝션 차단: {e}")
```

## Kubernetes 배포

### 방법 A: Dockerfile에 추가 (간단)

```dockerfile
FROM python:3.13-slim
RUN pip install llm-guard-python
COPY pii_patterns.toml /config/
# ... 앱 설치
```

```yaml
# deployment.yaml
env:
  - name: PYTHONPATH
    value: "<site-packages 경로>/llm_guard/_boot"
  - name: LLM_GUARD_CONFIG
    value: "/config/pii_patterns.toml"
```

### 방법 B: MutatingAdmissionWebhook (앱 이미지 수정 불가 시)

앱 코드/이미지 변경 없이 클러스터 레벨에서 자동 주입:

```yaml
# Webhook이 Pod spec에 주입하는 내용
initContainers:
  - name: llm-guard-init
    image: your-registry/llm-guard-init:0.2.0
    command: ["cp", "-r", "/opt/llm-guard/.", "/llm-guard/"]
    volumeMounts:
      - name: llm-guard-lib
        mountPath: /llm-guard

containers:
  - name: app
    env:
      - name: PYTHONPATH
        value: "/llm-guard/site-packages/llm_guard/_boot"
      - name: LLM_GUARD_CONFIG
        value: "/llm-guard/config/pii_patterns.toml"
    volumeMounts:
      - name: llm-guard-lib
        mountPath: /llm-guard
        readOnly: true

volumes:
  - name: llm-guard-lib
    emptyDir: {}
```

> Pre-built init image 권장. `pip install` init container는 PyPI 장애 시 Pod 시작 실패 리스크 있음.

## 개발

```bash
# Rust + Python 3.13 필요
cd pii_guard
maturin develop --release

# 테스트
python -m pytest tests/
```

## 라이선스

MIT
