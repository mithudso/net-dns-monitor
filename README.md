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
./scripts/start.sh
```

Checks the install and launches the app as a proper `.app` bundle (so the
Dock/Force-Quit/Cmd-Tab name correctly reads "Net-DNS-Monitor" instead of
"Python") -- output goes to `net-dns-monitor.log`, and the terminal
detaches once it's running; quit via the menu bar's Quit item. For direct
foreground debugging instead (Ctrl-C works, but the Dock/Force-Quit name
falls back to "Python"):

```bash
source .venv/bin/activate
python -m netdnsmonitor.app
```

Either way, the menu bar shows the current network statistics followed by a
status dot (🟢 healthy / 🟡 flaky -- a probe just started failing but hasn't
crossed the incident threshold yet / 🔴 incident):

```
61ms 1.2M↓0.3M↑ 🟢 Net/DNS: healthy
```

Round-trip time to `ping_host`, recent packet loss (shown only when nonzero),
and current throughput in bits per second. The Dock tile carries the same
round-trip time in the same status colour. Click the menu bar item and choose
"Open last report" for the most recent incident report, or "Test network
alert" to check that alerts actually reach you. See `HOWTO.md`'s Menu bar
reference section for the full status-icon and resolution-monitor-badge
behavior.

## Ping heartbeat and network-failed alert

Separately from incident detection, the app sends one ICMP echo request to
`ping_host` (default `8.8.8.8`) every `ping_interval_seconds` (default 5).
When a ping fails it **bounces the Dock icon and posts a "network failed"
notification** naming the host and the error.

The alert is edge-triggered: it fires when the network goes down and then
stays quiet, rather than bouncing twelve times a minute for the length of an
outage. Recovery re-arms it and cancels the bounce.

Two knobs if the default is too noisy or too quiet:

- `ping_failure_threshold` (default 1) -- consecutive failed pings before
  alerting. 1 is literal: a single dropped echo request alerts. On Wi-Fi that
  will occasionally be one lost packet rather than a real outage; set it to 2
  to ignore those and still alert within 10 seconds of a real outage.
- `ping_alert_repeat_seconds` (default 0 = one alert per outage) -- set to
  e.g. 300 to be re-alerted every 5 minutes while the network stays down.

This heartbeat only drives the display and the alert. It never runs the repair
ladder, escalates to Claude, or writes a report -- that stays with the
debounced 30-second incident poll, because acting on a false positive there
costs flushed caches and API calls. It also uses ICMP where the incident
prober deliberately uses TCP-connect; see `netdnsmonitor/ping.py` for why.

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

Independent of incident detection, every `resolution_interval_seconds`
(default 300 = 5 minutes) the app re-resolves **every domain that has ever
stalled on this machine**, in parallel, and appends the outcome to
`resolution_log_path` (default:
`~/Library/Application Support/net-dns-monitor/resolution-log.jsonl`) as one
JSON object per line: `domain`, `resolved`, `error`, `elapsed_seconds`,
`outcome`, `checked_at`. The stall list is read back out of that same log, so
the feature builds its own watch list over time.

"Stalled" means the lookup *took* at least `resolution_stall_seconds`
(default 1.0) -- not that it failed. An instant `NXDOMAIN` is a fast,
definitive answer and is not a stall. This distinction matters more than it
sounds: the query-log mining this replaced swept up non-domains (bundle IDs
like `com.apple.mDNSResponder`, truncated tokens like `com.code42.agen`), and
14,845 of 16,282 observed records were those failing instantly. Keying on
elapsed time excludes them without needing a "is this a real domain" guess.

Because the list only grows, each cycle is bounded by
`resolution_batch_deadline_seconds` (default 240, which must stay under the
interval). Domains still outstanding at the deadline are logged with
`outcome: "abandoned"`, and abandoned records are deliberately **not** treated
as stall evidence -- otherwise a slow batch would enlarge the list, which
would make batches slower still. The batch runs on a worker thread so it can
never delay the 30-second incident poll.

Note that `resolution_timeout_seconds` is not enforceable per lookup:
`socket.setdefaulttimeout()` does not bound `socket.getaddrinfo()`, which is a
blocking call into the system resolver. Measured on macOS, a missing `.local`
name took 5.01s against a 2.0 setting. The batch deadline is the real ceiling.

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
- `ping.py` -- one-shot ICMP ping with round-trip-time parsing
- `ping_monitor.py` -- loss window + the edge-triggered alert decision
- `net_stats.py` -- interface byte counters and throughput derivation
- `alert.py` -- Dock bounce + network-failed notification
- `log_watcher.py` -- `log show` tailing/filtering for DNS/network errors
- `stall_log.py` -- selects every ever-stalled domain from the resolution log
- `query_log.py` -- `log show` reading + top-queried-domain extraction; no longer wired into the resolution monitor (kept and still unit-tested)
- `resolution_prober.py` -- parallel, deadline-bounded DNS resolution of a domain batch
- `resolution_log.py` -- JSONL append for resolution-monitor findings
- `escalation.py` -- redaction + the escalate-or-not gate
- `anthropic_escalator.py` -- the Claude API call itself
- `report.py` / `report_storage.py` -- incident report schema + persistence
- `status.py` -- menu bar title/stats-segment logic
- `dock_icon.py` -- draws the Dock tile as the current reading
- `state_machine.py` -- orchestrates all of the above
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell
