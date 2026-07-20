# net-dns-monitor

macOS menu bar app that monitors network + DNS connectivity, auto-diagnoses
via an offline troubleshooting ladder, escalates to Claude when the ladder
can't resolve it, and saves an IT-ready incident report -- no user action
required to detect, diagnose, or report an issue.

## Honest scope

This app can genuinely fix a small set of local problems and diagnose a
great many more -- but even that small set is partial. `dscacheutil
-flushcache` runs fine unprivileged; the `killall -HUP mDNSResponder` half
of a full DNS cache flush does not, since mDNSResponder runs as a different
user and a signal to a process you don't own is rejected regardless of the
command's own permissions (confirmed empirically, not assumed). The app
reports that case as `partial` rather than claiming success. It cannot fix an ISP outage, a
misconfigured upstream DNS server, or a captive portal -- those need a
human. The diagnostic report is the primary deliverable for most real
incidents, not a fallback.

Repairs that need elevated privilege (renewing a DHCP lease, toggling a
network interface) are stubbed as `NEEDS_PRIVILEGE` in this MVP rather than
executed, because a sandboxed menu-bar app doesn't have the rights to do
them. See `netdnsmonitor/repair_executor.py` and the design plan's
sandbox/privileged-helper discussion for the path to adding a proper
`SMAppService` helper later.

## Setup

Requires Python 3.9+ (the code uses bare `list[...]`/`tuple[...]` generic
type hints).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

mkdir -p ~/.config/net-dns-monitor
cp config.example.yaml ~/.config/net-dns-monitor/config.yaml
# edit config.yaml: add the domains you actually care about, any internal
# targets, and (optionally) sensitive_strings to redact before LLM escalation
```

To enable the Claude escalation step (used only when the offline ladder +
repair attempt still leave an incident unresolved):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Without that variable set, escalation is skipped and the report still gets
written -- it just won't have an LLM analysis section.

## Run

```bash
source .venv/bin/activate
python -m netdnsmonitor.app
```

This puts a status icon in the menu bar (🟢 healthy / 🔴 degraded) and
polls on the configured interval. Click the menu bar item and choose
"Open last report" to see the most recent incident report.

## Permissions

Reading system logs (`log show`) may require the "Full Disk Access" or
log-access permission the first time it runs, depending on macOS version --
macOS will prompt if so. No other special entitlements are needed for the
diagnose-only build; see the README section above for what changes if you
add privileged repair actions.

## Reports

Every incident produces a timestamped `.json` (machine-readable) and `.md`
(human-readable) file under `reports_dir` (default:
`~/Library/Application Support/net-dns-monitor/reports/`). Each report is
self-contained: classification, probe results, log excerpts, every ladder
step attempted and its outcome, the repair outcome, the recheck result, and
the Claude escalation response if one occurred. Hand the `.md` file to IT.

## Resolution monitor

Independent of incident detection, the app mines the local DNS query log
(`log show`) every `resolution_interval_seconds` (default 300 = 5 minutes)
for the `resolution_top_n` (default 50) most-frequently-queried domains,
attempts to resolve each in parallel, and appends the outcome to
`resolution_log_path` (default:
`~/Library/Application Support/net-dns-monitor/resolution-log.jsonl`) as one
JSON object per line: `domain`, `resolved`, `error`, `elapsed_seconds`,
`checked_at`. This is a standing health record of the domains this machine
actually uses, separate from the `domains` list that drives incident
detection.

## Tests

```bash
source .venv/bin/activate
python -m pytest -v
```

All decision logic (classification, anti-flap gating, the troubleshooting
ladder, escalation redaction/gating, the report builder, and the full
state-machine orchestration) is unit tested with injected fakes for every
external effect (network, subprocess, LLM). The `app.py` menu-bar shell
itself is thin wiring over those tested modules and isn't exercised by the
test suite, since it needs a real macOS run loop.

## Project layout

- `classifier.py` -- network-vs-DNS-vs-healthy-vs-unclassified split
- `flap_gate.py` -- anti-flap consecutive-count debounce
- `ladder.py` -- the offline troubleshooting ladder definition
- `repair_executor.py` -- dispatches ladder steps to real macOS commands
- `dns_query.py` -- raw UDP query against a specific public resolver
- `prober.py` -- TCP-connect reachability + DNS resolution aggregation
- `log_watcher.py` -- `log show` tailing/filtering for DNS/network errors
- `query_log.py` -- `log show` reading + top-queried-domain extraction for the resolution monitor
- `resolution_prober.py` -- parallel DNS resolution of a domain batch
- `resolution_log.py` -- JSONL append for resolution-monitor findings
- `escalation.py` -- redaction + the escalate-or-not gate
- `anthropic_escalator.py` -- the Claude API call itself
- `report.py` / `report_storage.py` -- incident report schema + persistence
- `status.py` -- menu bar title/icon logic
- `state_machine.py` -- orchestrates all of the above
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell
