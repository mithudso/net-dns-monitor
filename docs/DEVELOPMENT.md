# Development

## Prerequisites

- macOS (the app shells out to `dscacheutil`, `killall`, `scutil`, `netstat`,
  and `log show` — it will not run on Linux/Windows)
- Python 3.9+ (the code uses bare `list[...]`/`tuple[...]` generic type hints)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Config file:

```bash
mkdir -p ~/.config/net-dns-monitor
cp config.example.yaml ~/.config/net-dns-monitor/config.yaml
# edit config.yaml — see comments in that file for every key
```

Optional — enable Claude escalation:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Without this set, escalation is skipped and reports are still written, just
without an LLM analysis section.

## Running

```bash
source .venv/bin/activate
python -m netdnsmonitor.app
```

Puts a status icon in the menu bar (🟢 healthy / 🔴 degraded). Click it and
choose "Open last report" to see the most recent incident report.

The first `log show` call may prompt for Full Disk Access / log-access
permission — see `README.md` → Permissions.

## Testing

```bash
source .venv/bin/activate
python -m pytest -v
```

See `docs/TESTING.md` for the test strategy and per-module coverage.

## Workflow

- Test-first: add/adjust a `tests/test_*.py` case before changing behavior in
  the corresponding module.
- Keep `app.py` thin. It's the one intentionally-untested module (needs a
  real macOS run loop) — push new logic into a testable module instead of
  growing it.
- Inject external effects. If new code needs to shell out, hit the network,
  or call an API, take that dependency as a constructor/function parameter
  (see every `make_*` factory in the codebase) so it can be faked in tests.

## Env vars

| Var | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables the Claude escalation step in `anthropic_escalator.py`. Omit to skip escalation entirely. |

## Troubleshooting

- **No menu bar icon appears** — run from a real Terminal session (not over
  SSH); `rumps` needs a GUI session.
- **`log show` output empty or permission errors** — grant Full Disk Access
  to your terminal/Python in System Settings → Privacy & Security.
- **DNS flush repair reports `partial`** — expected, not a bug. See
  `docs/known-issues.md`.
