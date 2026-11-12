# AGENTS.md — net-dns-monitor

All agent instructions for this repository live in [CLAUDE.md](CLAUDE.md).
Read it before changing code. It holds the non-negotiables, the verify loop,
the house style and the known-unverified areas, and it applies to every
coding agent, not only Claude.

This file is deliberately a pointer. An earlier copy of CLAUDE.md here drifted
within days (a second copy, merged from `master` on 2026-09-17, had drifted
again: a stale test count and a renamed escalation target), so keep a single
source of truth.

## Semantic index

Semantic queries, indexing and model execution require separate authorization.
Use source files and the static retrieval maps when that authorization is absent.
The
`scripts/semantic_indexer.py` / `scripts/watch_and_index.py` pair builds and
refreshes a Chroma index of the repository, `scripts/mcp_server.py` serves it
as the `search_codebase` MCP tool, and `scripts/query_index.py` queries it from
a shell. Do not build or refresh a missing index as a side effect of maintenance.
[docs/MCP.md](docs/MCP.md) documents the optional service and its boundaries.

## Repo-local agents

None. The repository defines no `.claude/agents/` or other agent definitions.

## Quick reference

```bash
.venv/bin/python -m pytest -q                              # full offline suite
.venv/bin/ruff check . && .venv/bin/ruff format --check .  # lint and format
.venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe   # sandboxed build
```
