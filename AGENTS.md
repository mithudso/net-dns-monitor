# AGENTS.md — net-dns-monitor

All agent instructions for this repository live in [CLAUDE.md](CLAUDE.md).
Read it before changing code. It holds the non-negotiables, the verify loop,
the house style and the known-unverified areas, and it applies to every
coding agent, not only Claude.

This file is deliberately a pointer. An earlier copy of CLAUDE.md here drifted
within days, so keep a single source of truth.

## Repo-local agents

None. The repository defines no `.claude/agents/` or other agent definitions.

## Quick reference

```bash
.venv/bin/python -m pytest -q                              # full offline suite
.venv/bin/ruff check . && .venv/bin/ruff format --check .  # lint and format
.venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe   # sandboxed build
```
