# net-dns-monitor: How-To Guide

macOS menu bar app that watches network + DNS connectivity, auto-diagnoses
via an offline troubleshooting ladder, escalates to Claude when the ladder
can't resolve it, saves an IT-ready incident report, and separately tracks
resolution health for the domains this machine actually queries most.

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the app](#running-the-app)
- [Feature: incident detection and auto-repair](#feature-incident-detection-and-auto-repair)
- [Feature: DNS resolution monitor (top-50 query log)](#feature-dns-resolution-monitor-top-50-query-log)
- [Feature: Claude escalation](#feature-claude-escalation)
- [Feature: incident reports](#feature-incident-reports)
- [Menu bar reference](#menu-bar-reference)
- [Permissions](#permissions)
- [Running the tests](#running-the-tests)
- [Troubleshooting](#troubleshooting)
- [Project layout](#project-layout)
- [Honest scope / known limitations](#honest-scope--known-limitations)

## Requirements

- macOS (uses `log show`, `scutil`, `dscacheutil`, `killall` -- all macOS-only)
- Python 3.9+ (the code uses bare `list[...]`/`tuple[...]` generic type hints)
- (Optional) an Anthropic API key, only needed for the Claude escalation
  feature

## Installation

```bash
git clone <this-repo-url> net-dns-monitor
cd net-dns-monitor

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create your config from the example template:

```bash
mkdir -p ~/.config/net-dns-monitor
cp config.example.yaml ~/.config/net-dns-monitor/config.yaml
```

Edit `~/.config/net-dns-monitor/config.yaml` -- see
[Configuration](#configuration) below for every key.

(Optional) enable Claude escalation:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Without that variable set, escalation is skipped and incident reports are
still written -- they just won't have an LLM analysis section.

## Configuration

All keys are optional; anything you omit falls back to the default shown
below (from `netdnsmonitor/config.py`). Config file lives at
`~/.config/net-dns-monitor/config.yaml` by default.

| Key | Default | Used by | Meaning |
|---|---|---|---|
| `external_targets` | `[["1.1.1.1", 443], ["8.8.8.8", 443]]` | prober | Host/port pairs to TCP-connect to for "is the internet reachable" (any one succeeding counts) |
| `internal_targets` | `[]` | prober | Same, but for your LAN (e.g. your router) -- tracked separately from external |
| `domains` | `[]` | prober | Domains resolved every poll to decide `dns_ok`. Empty by default on purpose -- the app does **not** auto-detect "sites you visit". **Leaving this empty means `dns_ok` is always unknown, which the classifier treats as `unclassified` rather than `healthy` -- populate it with at least one real domain, or the status icon will eventually latch onto a permanent false incident.** |
| `poll_interval_seconds` | `30` | main loop | How often the connectivity probe runs |
| `failure_threshold` | `2` | flap gate | Consecutive failed probes before declaring an incident |
| `success_threshold` | `2` | flap gate | Consecutive healthy probes before clearing an incident |
| `log_lookback` | `"5m"` | log watcher | Window of unified log scanned for error excerpts when building an incident report |
| `sensitive_strings` | `[]` | escalation | Strings (internal hostnames, VPN ranges, etc.) redacted before anything is sent to the Anthropic API |
| `reports_dir` | `~/Library/Application Support/net-dns-monitor/reports` | report storage | Where incident `.json`/`.md` reports are written |
| `resolution_log_path` | `~/Library/Application Support/net-dns-monitor/resolution-log.jsonl` | resolution monitor | Where resolution-check findings are appended |
| `resolution_interval_seconds` | `300` | resolution monitor | How often (seconds) the top-domain resolution check runs |
| `resolution_lookback` | `"1h"` | resolution monitor | Window of unified log scanned to find the busiest queried domains |
| `resolution_top_n` | `50` | resolution monitor | How many top-queried domains to resolve each cycle |
| `resolution_timeout_seconds` | `2.0` | resolution monitor | Per-domain resolution timeout |
| `resolution_max_workers` | `10` | resolution monitor | Thread pool size for parallel resolution |

Example `config.yaml`:

```yaml
external_targets:
  - ["1.1.1.1", 443]
  - ["8.8.8.8", 443]

internal_targets:
  - ["192.168.1.1", 443]   # your router

domains:
  - "example.com"
  - "internal-app.corp.local"

poll_interval_seconds: 30
failure_threshold: 2
success_threshold: 2
log_lookback: "5m"

sensitive_strings:
  - "corp.local"

reports_dir: "~/Library/Application Support/net-dns-monitor/reports"

resolution_log_path: "~/Library/Application Support/net-dns-monitor/resolution-log.jsonl"
resolution_interval_seconds: 300
resolution_lookback: "1h"
resolution_top_n: 50
resolution_timeout_seconds: 2.0
resolution_max_workers: 10
```

## Running the app

Recommended: `scripts/start.sh` -- it checks the install (macOS, Python
3.9+, required system tools, venv), verifies every component imports and
the config loads, materializes a default config if none exists, then
launches with the recommended settings in one step.

```bash
./scripts/start.sh
```

It launches the app as a proper `.app` bundle (built fresh each run at
`build/Net-DNS-Monitor.app`) rather than a bare `python3` process, so the
Dock icon, Force Quit dialog, and Cmd-Tab switcher correctly show
"Net-DNS-Monitor" instead of "Python" -- a bare interpreter process
otherwise inherits Apple's built-in "Python" identity, which no
in-process API call can override (confirmed empirically: overriding
`CFBundleName`/`NSProcessInfo.processName` changed the app-menu title but
not the Dock name). Two consequences of launching this way:

- **The terminal detaches once launched.** The app becomes an
  independent process, not a child of your shell -- Ctrl-C in the
  terminal no longer stops it. Quit via the menu bar item's Quit control,
  or `pkill -f netdnsmonitor.app`.
- **Output goes to `net-dns-monitor.log`** in the repo root (`tail -f` it)
  instead of your terminal.

For direct foreground debugging where Ctrl-C should still work (at the
cost of the Dock/Force-Quit name issue), run the module directly instead:

```bash
source .venv/bin/activate
python -m netdnsmonitor.app
```

A status icon appears in the menu bar: 🟢 healthy / 🟡 flaky / 🔴 incident
(see [Menu bar reference](#menu-bar-reference)). **This needs at least
one entry in `domains` to work correctly** -- see the callout under
[incident detection](#feature-incident-detection-and-auto-repair) below;
with the shipped default (`domains: []`) the icon latches to a false
incident within a couple of poll cycles even when the network is fine.
Two independent timers start immediately:

1. **Connectivity poll** (`poll_interval_seconds`, default 30s) -- feeds
   incident detection.
2. **Resolution monitor** (`resolution_interval_seconds`, default 300s /
   5 min) -- feeds the top-domain resolution log.

## Feature: incident detection and auto-repair

Every `poll_interval_seconds`:

1. **Probe** -- TCP-connects to `external_targets` / `internal_targets`
   (not ICMP ping, which is often filtered and gives false negatives) and
   resolves each of `domains`.
2. **Classify** -- splits the result into `healthy`, `network` (can't reach
   anything), `dns` (reachable but names won't resolve), or `unclassified`
   (either measurement is unavailable). **This is why `domains` cannot stay
   empty in practice:** with the shipped default (`domains: []`), DNS
   resolution is never checked, so that half of the classification is
   always `None` -- every tick classifies as `unclassified`, never
   `healthy`, and the anti-flap gate below eventually latches into a
   permanent (and permanently uncleared) "unclassified issue" state even
   when the network is completely fine. Add at least one real domain to
   `domains` in your `config.yaml` to get accurate health status.
3. **Anti-flap gate** -- an incident is only declared after
   `failure_threshold` consecutive bad probes, and only cleared after
   `success_threshold` consecutive good ones, so a single missed check
   (laptop asleep, brief Wi-Fi roam) doesn't trigger the full pipeline.
4. **Offline troubleshooting ladder** -- runs on the `healthy -> incident`
   transition, branching on classification:
   - **Network ladder:** check interface state, check default route, renew
     DHCP lease (stubbed, needs privilege), toggle network service (stubbed,
     needs privilege).
   - **DNS ladder:** check configured DNS servers, check `/etc/resolver`
     overrides, flush DNS cache (real repair attempt), resolve a probe
     domain against a public resolver (isolates "your resolver is broken"
     from "DNS is broken everywhere," e.g. a captive portal).
5. **Recheck** -- re-probes after the ladder to see if the repair worked.
6. **Escalate** (conditionally) -- see
   [Claude escalation](#feature-claude-escalation).
7. **Report** -- an incident report is written; see
   [incident reports](#feature-incident-reports).

## Feature: DNS resolution monitor (top-50 query log)

Independent of incident detection. Every `resolution_interval_seconds`
(default 5 minutes):

1. **Read the query log** -- runs `log show` over the last
   `resolution_lookback` (default `1h`), filtered to `mDNSResponder` /
   `"DNS"` entries.
2. **Extract top domains** -- regex-extracts dotted hostnames from the raw
   log text and counts frequency (IP addresses like `10.0.0.1` are excluded
   by requiring a non-numeric final label). Returns the `resolution_top_n`
   (default 50) most-frequently-queried domains.
3. **Resolve in parallel** -- resolves all of them concurrently via a
   thread pool (`resolution_max_workers`, default 10) instead of serially,
   so a batch of 50 domains with a couple of slow/unreachable ones still
   finishes in roughly one timeout period, not minutes.
4. **Log the findings** -- appends one JSON object per domain to
   `resolution_log_path` as JSON Lines (one record per line, not one big
   array, so a crash mid-write can't corrupt earlier entries and the file
   can be tailed/grepped like a normal log).

Each record looks like:

```json
{"domain": "example.com", "resolved": true, "error": null, "elapsed_seconds": 0.031, "checked_at": "2026-07-20T09:00:00+00:00"}
```

- `resolved` -- `true`/`false`
- `error` -- the resolver error string, or `null` on success
- `elapsed_seconds` -- how long that one resolution took
- `checked_at` -- UTC ISO-8601 timestamp for the whole batch that record
  belongs to

### Watching it live

```bash
tail -f ~/Library/Application\ Support/net-dns-monitor/resolution-log.jsonl
```

### Querying it (examples)

Domains that failed to resolve at least once:

```bash
jq -r 'select(.resolved == false) | .domain' ~/Library/Application\ Support/net-dns-monitor/resolution-log.jsonl | sort -u
```

Slowest resolutions (top 10):

```bash
jq -s 'sort_by(-.elapsed_seconds) | .[0:10] | .[] | "\(.elapsed_seconds)s \(.domain)"' ~/Library/Application\ Support/net-dns-monitor/resolution-log.jsonl -r
```

(The `jq` examples above need `jq` installed -- `brew install jq` -- it's
not otherwise required to run the app.)

This is a standing health record of the domains the machine actually uses,
separate from the `domains` config list (which only drives incident
detection and stays empty unless you populate it). Note the scope of
`sensitive_strings`: it redacts data sent to the Anthropic API on
escalation, but resolution-log.jsonl is written locally, unredacted --
if some of your top-queried domains are internal-only, that file will
contain them in plain text on disk. The log file also has no rotation
built in; it grows forever, so prune or rotate it yourself if a
long-running install starts to matter for disk space.

## Feature: Claude escalation

Escalation to the Claude API only fires after the offline ladder has run
and a post-repair recheck *still* shows the incident unresolved -- never on
first failure, so transient blips are never escalated. Because it needs
working connectivity to reach the Anthropic API, it can only help with
*partial* degradation, not a full outage; the incident report is written
either way.

- Enable by setting `ANTHROPIC_API_KEY`. Without it, escalation is skipped
  and reported as `"error": "ANTHROPIC_API_KEY not set; skipped LLM escalation"`.
- Uses `claude-haiku-4-5-20251001` by default (a bounded
  classification/diagnosis task); falls back to `claude-sonnet-5` when
  local triage couldn't classify the incident at all (the harder case).
- Everything sent is redacted first: every string in `sensitive_strings`
  is replaced with `[REDACTED]` in the classification, probe results,
  ladder results, and log excerpts before they leave the machine.

## Feature: incident reports

Every declared incident produces a timestamped pair of files under
`reports_dir`:

- `<timestamp>.json` -- machine-readable
- `<timestamp>.md` -- human-readable, meant to be handed directly to IT

Each report is self-contained:

- classification (`network` / `dns` / `unclassified`)
- probe results (external/internal reachability, DNS ok)
- log excerpts from the last `log_lookback` window (the evidence a human
  would otherwise have to go dig up manually)
- every ladder step attempted and its outcome
- the repair outcome (e.g. `flush_dns_cache: ok` or `... partial: ...`)
- the recheck result and whether the incident was resolved
- the Claude escalation response, if one occurred
- a one-line summary

## Menu bar reference

- **App name:** shows as "Net-DNS-Monitor" everywhere -- app menu, Dock,
  Force Quit, Cmd-Tab -- when launched via `scripts/start.sh`'s `.app`
  bundle. Launched directly via `python -m netdnsmonitor.app` instead, the
  app-menu title still says "Net-DNS-Monitor" (a runtime override), but
  the Dock/Force-Quit/Cmd-Tab name falls back to "Python" -- that specific
  fix needs the real bundle's own `Info.plist` identity, which only the
  `.app` launch path provides.
- **Dock icon:** a 📶-style network glyph tinted green/yellow/red for the
  same three status states below, replacing the generic Python rocket.
- **Status icon, three states from two small heuristics:**
  - 🟢 healthy -- no recent probe failures.
  - 🟡 flaky -- at least one consecutive probe failure, but still below
    `failure_threshold`, so no incident has been declared yet. An early
    warning the binary healthy/incident split wouldn't otherwise show.
  - 🔴 incident -- the anti-flap gate has declared one (with the layer,
    e.g. "🔴 Net/DNS: dns issue").
  - Independent of all three: if the most recent resolution-monitor batch
    (see [resolution monitor](#feature-dns-resolution-monitor-top-50-query-log))
    had any failed domain, the title gets a `N/total resolution fails`
    suffix -- since a top-queried domain can stop resolving without
    tripping the single configured `domains` check.
- **"Open last report"** -- opens the most recent incident report's
  Markdown file in your default browser. Shows a notification instead if
  no incident has occurred yet.

## Permissions

Reading system logs (`log show`, used by both the incident log watcher and
the resolution monitor's query-log reader) may require "Full Disk Access"
or a log-access prompt the first time it runs, depending on macOS version.
Grant it via **System Settings -> Privacy & Security -> Full Disk Access**
if `log show` calls silently return no data.

No other special entitlements are needed for this diagnose-only build. See
[Honest scope](#honest-scope--known-limitations) for what would change if
you add privileged repair actions.

## Running the tests

```bash
source .venv/bin/activate
python -m pytest -v
```

All decision logic (classification, anti-flap gating, the troubleshooting
ladder, escalation redaction/gating, report building, query-log parsing,
parallel resolution, resolution-log persistence, and full state-machine
orchestration) is unit tested with injected fakes for every external effect
(network, subprocess, LLM, filesystem). `app.py`'s menu-bar shell itself is
thin wiring over those tested modules; only its wiring logic is directly
exercised -- `build_resolution_job`'s composition, and a regression test
that drives `tick()` against a fake state machine to confirm the menu bar
title reads live flap-gate state (`status.py`'s title logic itself is unit
tested separately, on its own). The rest needs a real macOS run loop.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Menu bar title stuck on "starting..." | App hasn't completed its first poll tick yet | Wait one `poll_interval_seconds` cycle |
| Menu bar stuck on 🔴 "unclassified issue" forever, even though the network is fine | `domains` is empty (the default) -- `dns_ok` is always unknown, `classify()` returns `unclassified` (never `healthy`), and the anti-flap gate latches into a permanent incident it can never clear | Add at least one real domain to `domains` in `config.yaml` |
| No incident reports ever appear | `failure_threshold` not yet reached, or connectivity is actually fine (with `domains` populated) | Lower `failure_threshold` temporarily to test, or check `reports_dir` permissions |
| Resolution log file never appears | No queries seen in `resolution_lookback` window, or `log show` needs a permission grant | Check Full Disk Access; try a larger `resolution_lookback` |
| Escalation field shows an error instead of an analysis | `ANTHROPIC_API_KEY` not set, or the API call failed | Export the key; check the error string in the report's escalation field for the underlying cause |
| `flush_dns_cache` reports `partial` | `dscacheutil -flushcache` succeeded but `killall -HUP mDNSResponder` was rejected | Expected and documented -- mDNSResponder runs as a different user; a signal from an unprivileged process is rejected regardless of the command's own permissions |
| `scripts/start.sh` finishes with no visible menu bar icon | `open -n build/Net-DNS-Monitor.app` failed silently, or the bundle launcher script errored before reaching rumps | Check `net-dns-monitor.log` in the repo root for the actual error; `chmod +x build/Net-DNS-Monitor.app/Contents/MacOS/NetDNSMonitor` if it lost its executable bit |
| Ctrl-C in the terminal doesn't stop the app | Expected once launched via `scripts/start.sh`'s `.app` bundle -- it's an independent process, not a child of the shell | Quit via the menu bar's Quit item, or `pkill -f netdnsmonitor.app`; use `python -m netdnsmonitor.app` directly instead if you want Ctrl-C to work |
| Repair steps report `NEEDS_PRIVILEGE` | DHCP renewal / interface toggling need elevated rights this sandboxed app doesn't have | Not implemented in this MVP; see Honest scope below |

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
- `status.py` -- menu bar title logic + the shared healthy/flaky/incident status decision
- `dock_icon.py` -- renders the tinted network-glyph Dock icon
- `state_machine.py` -- orchestrates incident detection end to end
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell wiring everything together
- `scripts/start.sh` -- install check + component verification + launches the app as a `.app` bundle (generated fresh each run at `build/Net-DNS-Monitor.app`, gitignored)

## Honest scope / known limitations

- `dscacheutil -flushcache` runs fine unprivileged; the
  `killall -HUP mDNSResponder` half of a full DNS cache flush does not,
  since mDNSResponder runs as a different user and a signal to a process
  you don't own is rejected regardless of the command's own permissions
  (confirmed empirically). The app reports this as `partial`, not success.
- Cannot fix an ISP outage, a misconfigured upstream DNS server, or a
  captive portal -- those need a human. The diagnostic report is the
  primary deliverable for most real incidents, not a fallback.
- Repairs needing elevated privilege (renewing a DHCP lease, toggling a
  network interface) are stubbed as `NEEDS_PRIVILEGE` rather than executed,
  since a sandboxed menu-bar app doesn't have the rights to do them. Adding
  a proper `SMAppService` privileged helper would remove this limitation.
- Domain extraction in the resolution monitor is a regex over raw `log
  show` text, not a parse of mDNSResponder's internal log schema (which
  isn't stable across macOS versions and isn't independently documented by
  Apple) -- treat the top-50 list as a good-faith approximation of query
  volume, not an exact count.
