# CLAUDE.md

Guidance for Claude Code (and any other AI assistant) working in this repo.

## What this is

A macOS menu bar app (Python + `rumps`) that monitors network/DNS
connectivity, runs an offline troubleshooting ladder, optionally escalates
unresolved incidents to the Claude API, and writes an IT-ready incident
report. See `README.md` for the full pitch and `docs/ARCHITECTURE.md` for
how the modules fit together.

## Workflow rules

- **TDD first.** This codebase was built test-first (see commit history) and
  every decision module (`classifier`, `flap_gate`, `ladder`, `escalation`,
  `report`, `state_machine`, `repair_executor`, `dns_query`, `prober`,
  `log_watcher`, `report_storage`, `status`) has a matching `tests/test_*.py`
  file with fakes/injected callables for every external effect. Add or
  change behavior with a failing test first, then make it pass.
- **`app.py` is thin wiring**, intentionally untested — it needs a real
  macOS run loop. Don't add test-avoidance patterns to the tested modules;
  push logic down into a testable module instead of growing `app.py`.
- **No real external calls in tests.** Network, subprocess, and the
  Anthropic API are always injected as callables/fakes in tests — never hit
  them for real in the test suite.
- **Run tests before considering a change done:**
  ```bash
  source .venv/bin/activate
  python -m pytest -v
  ```
- **Don't invent privileged behavior.** Repair steps that need elevated
  rights (DHCP renew, interface toggle) are intentionally stubbed as
  `NEEDS_PRIVILEGE` in `repair_executor.py` — this is a known, documented
  MVP boundary, not a bug to silently "fix" by shelling out with sudo.
- **Preserve empirically-confirmed behavior.** The partial-success wording
  in `flush_dns_cache()` (`repair_executor.py`) reflects a real, verified
  macOS permission boundary (`mDNSResponder` HUP requires privilege
  `dscacheutil` doesn't). Don't simplify it back to a blanket success/failure
  without re-verifying on-device.

## Commands

| Task | Command |
|---|---|
| Install deps | `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt` |
| Run the app | `python -m netdnsmonitor.app` |
| Run tests | `python -m pytest -v` |
| Config | copy `config.example.yaml` to `~/.config/net-dns-monitor/config.yaml` |

## Scope note

This is a personal single-maintainer utility, not a service with a
deployment pipeline, CI, or external API surface beyond the (optional,
user-provided-key) Anthropic escalation call. Don't propose CI/CD,
multi-tenant, or server-side infrastructure — it doesn't apply here.
