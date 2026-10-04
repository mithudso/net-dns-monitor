# Repository bootstrap audit — 2026-10-04

This audit applies to the macOS desktop application and its local developer
tools. Server endpoint registries, admin dashboards and fleet operations do not
apply to this solo-maintained desktop repository. The repository has no local
agent definitions. `AGENTS.md` remains a pointer; `CLAUDE.md` owns agent rules.

| Area | Result |
|---|---|
| Agent instructions | `CLAUDE.md` now includes portable prompt/work journals and the static documentation gate. |
| Prompt and memory continuation | Root task records the exact request and versioned work state in `prompts.md` and `memory.md`. |
| Development/configuration | Corrected the existing `config.example.yaml` screenshot fixture description; runtime defaults still come from `config.yaml` and `DEFAULT_CONFIG`. |
| Dependency/tool policy | Runtime and test dependencies are pinned. Pre-commit stays an external pipx/uv tool; its Ruff hook must match `requirements-dev.txt`. |
| Release evidence | The real-certificate release and submitted build 3 are dated 2026-09-27; later review rejection and build 4 planning do not establish current approval or signing state. |
| Static retrieval | Extended the high-signal map and overview, filled developer MCP/caching documents, and added a partial source census. |
| Drift guard | `scripts/check_docs.py` checks path safety/existence, dossier census parity and, with `--collect-tests`, published totals and per-file test counts. CI runs it. |
| Logging | Documented implemented resolution-log compaction and preservation of historical stalled-domain evidence. |
| Optional metadata | CODEOWNERS and editor-specific workspace files are unnecessary for the current solo-maintainer workflow; no speculative tooling was added. |

`docs/llms/manifest.json` records a full source-file census with shallow cards.
It separately records the 33 Group 4 runtime files read during this review.
It does not claim full deep cards or complete executable inventory coverage.
Semantic queries, indexing, Ollama startup and watcher installation were
excluded from this static documentation pass.

The drift guard intentionally checks a small mechanical contract. It does not
verify every prose claim, historical numeric call-site anchor, current App Store
Connect state, or actual privilege/sandbox behavior. Read source and dated release
records for those questions. The independent code review report tracks remaining
runtime decisions and verified regressions.
