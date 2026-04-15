# PII Guard — Python HTTP 요청 PII 차단 라이브러리 설계

## 개요

Rust(PyO3) 기반 네이티브 확장과 Python import hook을 조합하여, Python 애플리케이션에서 나가는 HTTP 요청의 header/body에 포함된 개인식별정보(PII)를 탐지하고 차단하는 라이브러리.

## 목표

- 개발/테스트 환경에서 개발자가 실수로 PII를 보내는 것을 방지
- 프로덕션 환경에서 PII 유출을 차단하는 보안 레이어 역할
- Python 코드 수정 없이 `sitecustomize.py`를 통해 자동 활성화
- 외부 설정 파일(TOML)로 PII 패턴을 유연하게 관리

## 기술 선택 배경

### 라이브러리 레벨 후킹 (소켓 레벨이 아닌 이유)

dd-trace-py, OpenTelemetry 등 프로덕션 검증된 도구들이 모두 라이브러리 레벨에서 후킹한다. 소켓 레벨 후킹은 SSL/TLS 암호화 이후 데이터를 보게 되어 HTTPS 요청의 body/header 검사가 불가능하고, 플랫폼별 네이티브 의존성이 복잡해진다.

### Import Hook (몽키패칭이 아닌 이유)

`sys.meta_path`에 커스텀 Finder를 등록하여 모듈 임포트 시점에 래핑하는 방식이 런타임 몽키패칭보다 깔끔하다. 모듈이 로드되기 전에 개입할 수 있어 타이밍 문제가 없다.

### 후킹 대상: urllib3만

`requests`, `httpx` 등 주요 Python HTTP 클라이언트가 내부적으로 `urllib3`를 사용하므로, `urllib3.connectionpool.HTTPConnectionPool.urlopen()`만 래핑해도 넓은 커버리지를 확보할 수 있다.

---

## 아키텍처

```
[Python 인터프리터 시작]
        |
[site 모듈이 sitecustomize.py 자동 실행]
        |
[sitecustomize.py -> import pii_guard (Rust PyO3 확장) + 설정 로드]
        |
[sitecustomize.py가 PiiGuardFinder를 sys.meta_path에 등록]
        |
[사용자 코드에서 import urllib3 발생]
        |
[커스텀 Finder가 가로챔 -> 원본 urllib3 로드 후 urlopen() 래핑]
        |
[래핑된 urlopen()이 호출될 때마다]
        |
[Rust 엔진이 header/body에서 PII 패턴 검사]
        |
  +-- PII 없음 -> 원본 urlopen() 정상 실행
  +-- PII 발견 -> 요청 차단 + 로그 파일 기록 + stderr 출력 + 예외 발생
```

## 프로젝트 구조

```
python-hooking-demo/
+-- pii_guard/                  # Rust PyO3 크레이트
|   +-- Cargo.toml
|   +-- src/
|       +-- lib.rs              # PyO3 모듈 진입점
|       +-- detector.rs         # PII 패턴 매칭 엔진 (regex)
|       +-- config.rs           # TOML 설정 파일 로더
|       +-- logger.rs           # 파일 로그 + stderr 출력
+-- python/
|   +-- sitecustomize.py        # 부트스트랩
|   +-- pii_guard_hook.py       # sys.meta_path Finder/Loader 구현
+-- config/
|   +-- pii_patterns.toml       # PII 패턴 정의 파일
+-- tests/
|   +-- test_detector.rs        # Rust 단위 테스트
|   +-- test_integration.py     # Python 통합 테스트
```

---

## 컴포넌트 상세

### 1. PII Detection Engine (Rust)

#### PyO3 인터페이스

```python
# 설정 로드 (sitecustomize.py에서 한 번 호출)
pii_guard.load_config("/path/to/pii_patterns.toml")

# PII 검사 (urlopen 래핑 함수에서 매 요청마다 호출)
result = pii_guard.scan(text: str) -> ScanResult | None
# ScanResult: { pattern_name: str, matched_value: str }
# matched_value는 원본 값. 마스킹은 로그 기록 시점에 logger.rs가 수행

# 로그 기록
pii_guard.log(message: str)
```

#### Rust 내부 구조

```rust
// detector.rs
pub struct PiiDetector {
    patterns: Vec<PiiPattern>,  // 컴파일된 regex 패턴 목록
}

impl PiiDetector {
    pub fn from_config(path: &str) -> Result<Self>;
    pub fn scan(&self, text: &str) -> Option<ScanMatch>;
}

// config.rs - TOML 파싱 -> PiiPattern 목록 변환
// logger.rs - 파일 + stderr 동시 출력
```

- `regex` 크레이트로 패턴 컴파일 (한 번만 수행, 이후 재사용)
- `scan()`은 첫 번째 매칭을 찾으면 즉시 반환 (차단 목적이므로 전수 검사 불필요)
- 설정 파일 경로는 환경변수 `PII_GUARD_CONFIG`로도 지정 가능

#### 크레이트 의존성

- `pyo3` — Python 바인딩
- `regex` — 정규식 엔진
- `toml` / `serde` — 설정 파일 파싱
- `chrono` — 로그 타임스탬프

### 2. PII 패턴 설정 (`pii_patterns.toml`)

```toml
[patterns]

[patterns.resident_id]
name = "주민등록번호"
regex = '\\d{6}-[1-4]\\d{6}'

[patterns.phone]
name = "전화번호"
regex = '(01[016789]-?\\d{3,4}-?\\d{4})'

[patterns.email]
name = "이메일"
regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}'

[patterns.credit_card]
name = "신용카드번호"
regex = '\\d{4}-?\\d{4}-?\\d{4}-?\\d{4}'

[patterns.bank_account]
name = "계좌번호"
regex = '\\d{3}-?\\d{2,6}-?\\d{2,6}-?\\d{1,3}'

[patterns.passport]
name = "여권번호"
regex = '[A-Z]{1}[0-9]{8}'
```

### 3. Import Hook (Python)

#### `pii_guard_hook.py`

```python
class PiiGuardFinder:
    """urllib3 임포트를 가로채는 커스텀 Finder"""
    
    _hooked = False  # 중복 후킹 방지
    
    def find_module(self, fullname, path=None):
        # urllib3.connectionpool 임포트 시에만 개입
        if fullname == "urllib3.connectionpool" and not self._hooked:
            return self  # Loader 역할도 자신이 수행
        return None  # 다른 모듈은 기본 임포트 시스템에 위임
    
    def load_module(self, fullname):
        # 1. 자신을 meta_path에서 임시 제거 (무한 재귀 방지)
        # 2. 원본 모듈을 정상 임포트
        # 3. HTTPConnectionPool.urlopen을 래핑
        # 4. 자신을 meta_path에 복원
        # 5. _hooked = True
```

#### urlopen 래핑 함수

```python
def wrapped_urlopen(original_urlopen):
    def wrapper(self, method, url, body=None, headers=None, **kwargs):
        import pii_guard
        
        # header 검사
        if headers:
            for key, value in headers.items():
                result = pii_guard.scan(f"{key}: {value}")
                if result:
                    _block(method, url, result)
        
        # body 검사
        if body:
            text = body if isinstance(body, str) else body.decode("utf-8", errors="ignore")
            result = pii_guard.scan(text)
            if result:
                _block(method, url, result)
        
        # PII 없으면 원본 실행
        return original_urlopen(self, method, url, body=body, headers=headers, **kwargs)
    
    return wrapper

def _block(method, url, scan_result):
    """요청 차단: 로그 기록 + stderr 출력 + 예외 발생"""
    import pii_guard
    msg = f"[PII_GUARD] 차단: {method} {url} - {scan_result.pattern_name} 발견"
    pii_guard.log(msg)
    print(msg, file=sys.stderr)
    raise PiiBlockedError(msg)

class PiiBlockedError(Exception):
    pass
```

핵심 포인트:
- `find_module` / `load_module`은 PEP 302 스펙 (Python 3.4+ 호환)
- 무한 재귀 방지: Finder가 자기 자신을 `sys.meta_path`에서 임시 제거한 뒤 원본 임포트 수행
- 한 번만 후킹: `_hooked` 플래그로 중복 래핑 방지
- body가 bytes인 경우 UTF-8 디코딩 시도, 바이너리 데이터는 무시

### 4. Bootstrap (`sitecustomize.py`)

```python
import os
import sys

def _bootstrap_pii_guard():
    if os.environ.get("PII_GUARD_DISABLE", "").lower() in ("1", "true"):
        return
    
    import pii_guard
    
    config_path = os.environ.get(
        "PII_GUARD_CONFIG",
        os.path.join(os.path.dirname(__file__), "pii_patterns.toml")
    )
    pii_guard.load_config(config_path)
    
    from pii_guard_hook import PiiGuardFinder
    sys.meta_path.insert(0, PiiGuardFinder())
    
    print("[PII_GUARD] 활성화됨", file=sys.stderr)

try:
    _bootstrap_pii_guard()
except Exception as e:
    print(f"[PII_GUARD] 초기화 실패: {e}", file=sys.stderr)
```

설계 원칙:
- 안전한 실패: 설정 파일 누락이나 Rust 확장 로드 실패 시에도 Python 정상 시작
- 비활성화 옵션: `PII_GUARD_DISABLE=1`
- 설정 경로 유연성: `PII_GUARD_CONFIG` 환경변수
- `sys.meta_path.insert(0, ...)`: 최우선 순위 등록

배포:
```bash
export PYTHONPATH="/path/to/pii_guard_bootstrap:$PYTHONPATH"
pip install ./pii_guard
```

---

## 로깅

### 로그 형식

```
[2026-04-15T22:50:31+09:00] BLOCKED method=POST url=https://api.example.com/users pattern=주민등록번호 matched=850101-1******
```

- 타임스탬프: ISO 8601
- 매칭된 값은 일부 마스킹 (PII 원본이 로그에 남지 않도록)
- 로그 파일 경로: `PII_GUARD_LOG` 환경변수 또는 기본값 `./pii_guard.log`

---

## 에러 처리

| 상황 | 동작 |
|------|------|
| 설정 파일 없음 | stderr 경고 + PII Guard 비활성 상태로 Python 정상 시작 |
| 설정 파일 파싱 실패 | stderr 경고 + 비활성 |
| 잘못된 정규식 패턴 | 해당 패턴만 건너뜀 + stderr 경고 |
| PII 탐지 | `PiiBlockedError` 예외 발생 + 파일 로그 + stderr |
| body 디코딩 실패 (바이너리) | 검사 건너뜀, 요청 통과 |
| 로그 파일 쓰기 실패 | stderr에만 출력, 요청 차단은 정상 수행 |

핵심 원칙:
- PII Guard의 장애가 애플리케이션을 멈추면 안 됨
- PII 탐지는 반드시 차단 (핵심 경로)
- 로그에 PII 원본을 남기지 않음 (마스킹 처리)

---

## 환경변수 요약

| 변수 | 용도 | 기본값 |
|------|------|--------|
| `PII_GUARD_DISABLE` | `1` 또는 `true`로 비활성화 | 미설정 (활성) |
| `PII_GUARD_CONFIG` | 설정 파일 경로 | `./pii_patterns.toml` |
| `PII_GUARD_LOG` | 로그 파일 경로 | `./pii_guard.log` |

---

## 지원 플랫폼

- Windows (.pyd)
- Linux (.so)
- macOS (.dylib)

PyO3 + maturin을 통해 크로스 플랫폼 빌드.

---

## 테스트 전략

### Rust 단위 테스트

- PII 패턴별 탐지 (주민등록번호, 전화번호, 이메일, 카드번호, 계좌번호, 여권번호)
- 정상 텍스트에서 false positive 없는지 확인
- TOML 설정 로드/파싱
- 잘못된 정규식 패턴 -> 해당 패턴만 스킵
- 마스킹 함수

### Python 통합 테스트

- Import Hook 등록 확인 (sys.meta_path에 PiiGuardFinder 존재)
- urllib3 임포트 후 urlopen이 래핑되었는지 확인
- PII 포함 요청 -> PiiBlockedError 발생
- PII 없는 요청 -> 정상 통과
- header에 PII -> 차단
- body에 PII -> 차단
- 로그 파일에 차단 기록
- PII_GUARD_DISABLE=1 -> 후킹 미등록

### TDD 순서

1. Rust: PII 패턴 탐지 (Red -> Green -> Refactor)
2. Rust: 설정 파일 로드
3. Rust: 마스킹
4. Rust: PyO3 인터페이스
5. Python: Import Hook 등록
6. Python: urlopen 래핑
7. Python: 차단 + 로그
8. Python: sitecustomize 부트스트랩
9. 전체 통합 테스트
