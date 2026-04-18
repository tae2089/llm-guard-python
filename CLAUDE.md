## Code Knowledge Graph (CCG)

이 프로젝트는 rust로 LLM 보안 기능을 구현한 프로젝트로. 파이썬 프레임웍을 사용하는 파이썬 프로젝트에서 LLM 보안 기능을 제공하기 위한 라이브러리입니다.

이 프로젝트를 분석하는데는 [code-context-graph](https://github.com/tae2089/code-context-graph) MCP 서버를 사용합니다.

### 코드 분석 플로우

```
get_minimal_context          ← 항상 여기서 시작 (그래프 상태 + 추천 도구)
        │
        ├─ 그래프 없음 → build_or_update_graph(path: ".")
        │
        ├─ 코드 찾기 → search(query: "키워드")
        │                → query_graph(pattern: "callers_of", target: "pkg.Func")
        │
        ├─ 변경 영향 → detect_changes(repo_root: ".")
        │                → get_impact_radius(qualified_name: "...", depth: 3)
        │                → get_affected_flows(repo_root: ".")
        │
        ├─ 구조 파악 → get_architecture_overview()
        │                → list_communities()
        │
        └─ 코드 변경 후 → build_or_update_graph(path: ".", full_rebuild: false)
```

### 팁

- `search`는 코드뿐 아니라 `@intent`, `@domainRule` 등 어노테이션도 검색합니다
- `search(path: "internal/auth")` 처럼 경로로 범위를 좁힐 수 있습니다
- MSA 환경에서는 모든 도구에 `workspace` 파라미터로 서비스를 격리하세요

````
---
## 최소 버전
```markdown
## CCG
코드 분석 시 `get_minimal_context`를 먼저 호출하세요. 그래프 상태와 다음 단계를 안내합니다.
````
