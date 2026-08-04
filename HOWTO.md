# net-dns-monitor: How-To Guide

macOS menu bar app that watches network + DNS connectivity, auto-diagnoses
via an offline troubleshooting ladder, escalates to Claude when the ladder
can't resolve it, saves an IT-ready incident report, and separately re-checks
every DNS lookup that has ever stalled on this machine.

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the app](#running-the-app)
- [Feature: incident detection and auto-repair](#feature-incident-detection-and-auto-repair)
- [Feature: DNS resolution monitor (every ever-stalled domain)](#feature-dns-resolution-monitor-every-ever-stalled-domain)
- [Feature: Claude escalation](#feature-claude-escalation)
- [Feature: incident reports](#feature-incident-reports)
- [Feature: ping heartbeat and the network-failed alert](#feature-ping-heartbeat-and-the-network-failed-alert)
- [Dashboard window](#dashboard-window)
- [Feature: system log viewer and search](#feature-system-log-viewer-and-search)
- [Feature: forensic log of every down/up episode](#feature-forensic-log-of-every-downup-episode)
- [Feature: LAN peer discovery](#feature-lan-peer-discovery)
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

Copy the shipped default config into place (`install.sh` does this for you):

```bash
mkdir -p ~/.config/net-dns-monitor
cp config.yaml ~/.config/net-dns-monitor/config.yaml
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
| `resolution_interval_seconds` | `300` | resolution monitor | How often (seconds) the stalled-domain resolution check runs |
| `resolution_stall_seconds` | `1.0` | resolution monitor | A lookup at or above this elapsed time counts as a stall and joins the retry list permanently |
| `resolution_batch_deadline_seconds` | `240` | resolution monitor | Wall-clock ceiling on one batch; must stay below `resolution_interval_seconds` |
| `resolution_timeout_seconds` | `2.0` | resolution monitor | Intended per-domain timeout. **Not enforceable** -- see [the note below](#the-timeout-that-isnt) |
| `resolution_max_workers` | `10` | resolution monitor | Thread pool size for parallel resolution |
| `ping_host` | `"8.8.8.8"` | ping heartbeat | Host sent one ICMP echo request every `ping_interval_seconds`. Point elsewhere if your network filters ICMP to it |
| `ping_interval_seconds` | `5` | ping heartbeat | Heartbeat cadence -- how often the stats and the Dock tile refresh |
| `ping_timeout_seconds` | `2.0` | ping heartbeat | Per-ping ceiling. A failed ping takes roughly this long to give up, so keep it well under the cadence |
| `ping_failure_threshold` | `2` | ping heartbeat | Consecutive failed pings before the alert fires. `1` is the literal reading; the default is `2` because lone dropped Wi-Fi packets were each opening an episode |
| `ping_alert_repeat_seconds` | `0` | ping heartbeat | `0` = one alert per outage. Set to e.g. `300` to be re-alerted every 5 minutes while the network stays down |
| `ping_loss_window` | `12` | ping heartbeat | How many recent pings the loss percentage averages over. 12 at a 5s cadence is the last minute |
| `ui_refresh_seconds` | `1` | dashboard | How often the window repaints and picks up a finished troubleshooting step |
| `open_dashboard_at_launch` | `true` | dashboard | Open the window shortly after launch, ordered front without stealing focus |
| `forensic_log_path` | `~/Library/Application Support/net-dns-monitor/forensic-log.jsonl` | forensic log | Append-only journal, written as each event happens |
| `forensic_episodes_dir` | `~/Library/Application Support/net-dns-monitor/episodes` | forensic log | Per-episode `.md`/`.json` write-ups, produced on recovery |
| `peer_discovery_enabled` | `true` | peer discovery | Announce on the LAN and look for other instances. `false` opens no socket and broadcasts nothing |
| `peer_port` | `45737` | peer discovery | UDP port for announce/probe/pong |
| `peer_announce_seconds` | `300` | peer discovery | Re-announce and heartbeat every known peer on this cadence |
| `peer_current_seconds` | `600` | peer discovery | Heard from within this window counts as `current`. Two announce intervals, so one dropped broadcast is not a demotion |
| `peer_recent_seconds` | `86400` | peer discovery | Heard from within this window but not the one above: `recent`. Older: `other` |
| `peer_record_path` | `~/Library/Application Support/net-dns-monitor/peers.json` | peer discovery | File record of current / recent / other hosts, read back at startup |
| `log_view_enabled` | `true` | system log viewer | Read the network parts of the unified log. `false` means no subprocess at all, not a hidden pane |
| `log_view_backfill_window` | `"15m"` | system log viewer | Read once at launch so the pane is not blank for a poll interval. Measured 4.2s; a 60m window measured 16.9s |
| `log_view_poll_window` | `"1m"` | system log viewer | The steady-state read. Deliberately longer than the interval below so nothing falls between two polls; the overlap is de-duplicated in memory |
| `log_view_poll_seconds` | `30` | system log viewer | How often the log is re-read |
| `log_view_timeout_seconds` | `45` | system log viewer | Not the 10s used for the incident-report excerpt. A timeout shows as a line in the pane, never as an empty pane |
| `log_view_max_entries` | `3000` | system log viewer | Entries held in memory. Nothing is written to disk by the viewer |
| `log_view_errors_only` | `true` | system log viewer | Start filtered to error/fault. All levels over the same subsystems measured 192,901 lines in 30 minutes; errors-only was 919 in 15. The button above the pane switches this at runtime |
| `log_view_row_limit` | `400` | system log viewer | Rows drawn in the pane, after identical messages are collapsed into one `(xN)` row |
| `log_view_announce_limit` | `3` | system log viewer | New error lines announced in the results pane per poll. A cap on the announcement only -- everything still lands in the log pane |
| `log_view_noise_patterns` | 4 substrings | system log viewer | Entries containing any of these are dropped entirely. The shipped four are high-frequency framework complaints from unrelated software. `[]` shows everything |

Retired keys, ignored if still present in your `config.yaml`:
`resolution_lookback`, `resolution_top_n` (the monitor no longer mines the
query log for the busiest domains).

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
resolution_stall_seconds: 1.0
resolution_batch_deadline_seconds: 240
resolution_timeout_seconds: 2.0
resolution_max_workers: 10

ping_host: "8.8.8.8"
ping_interval_seconds: 5
ping_timeout_seconds: 2.0
ping_failure_threshold: 2
ping_alert_repeat_seconds: 0
ping_loss_window: 12
```

## Running the app

Recommended: `scripts/start.sh` -- it checks the install (macOS, Python
3.9+, required system tools, venv), verifies every component imports and
the config loads, materializes a default config if none exists, then
launches with the recommended settings in one step.

```bash
./scripts/start.sh
```

It launches the app as a real, frozen `.app` bundle
(`dist/Net-DNS-Monitor.app`, built via `py2app` -- installed on demand,
rebuilt only when missing or when `netdnsmonitor/`, `setup.py`, or
`requirements.txt` changed since the last build) rather than a bare
`python3` process, so the Dock icon, Force Quit dialog, and Cmd-Tab
switcher correctly show "Net-DNS-Monitor" instead of "Python".

That took three attempts to get right, confirmed empirically each time:
overriding `CFBundleName` fixed the app-menu title only; also overriding
`NSProcessInfo.processName` still didn't touch the Dock; a hand-built
lightweight wrapper `.app` around `exec python3 -m netdnsmonitor.app`
didn't work either, because framework Python re-execs itself into its own
bundled `Python.app` stub the instant rumps creates the GUI (confirmed via
`ps aux` -- the running binary was Python.framework's own
`Resources/Python.app/Contents/MacOS/Python`, not anything of ours), and
that stub's `Info.plist` says "Python" regardless of what launched it.
Only a real frozen build -- py2app embeds its own private interpreter
copy that never touches that shared re-exec path -- actually works
(confirmed: the embedded interpreter's own `NSBundle.mainBundle()`
resolves to this project's bundle path and name, not Python.framework's).

Two consequences of launching this way:

- **The terminal detaches once launched.** The app becomes an
  independent process, not a child of your shell -- Ctrl-C in the
  terminal no longer stops it. Quit via the menu bar item's Quit control,
  or `pkill -f Net-DNS-Monitor`.
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
   5 min) -- re-checks every ever-stalled domain. Runs on a worker thread, so
   a long batch never delays timer 1.

### Starting automatically at login

Install the LaunchAgent template at
`scripts/com.mitchhudson.net-dns-monitor.plist` (edit the paths inside it to
match your checkout):

```bash
cp scripts/com.mitchhudson.net-dns-monitor.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.mitchhudson.net-dns-monitor.plist
launchctl list | grep net-dns    # confirm it registered
```

To stop it starting at login again:

```bash
launchctl bootout gui/$(id -u)/com.mitchhudson.net-dns-monitor
```

Three things about that plist are deliberate:

- **`LaunchAgent`, not `LaunchDaemon`.** This is a GUI menu bar app and needs
  the logged-in user's session. A daemon runs before login with no window
  server access and could never draw a status item.
- **`ProgramArguments` points at the executable inside the `.app` bundle**, not
  at `python -m netdnsmonitor.app`. A bare module launch reintroduces the
  "Python" Dock/Force-Quit name that the frozen bundle exists to fix.
- **No `KeepAlive`.** With it, quitting from the menu bar's Quit item would
  immediately relaunch the app, so you could never turn it off without
  unloading the agent.

`launchctl bootstrap` runs the agent immediately as well as at login, so quit
any copy you started by hand first or you'll get two menu bar items.

Note that the path inside the plist points at wherever you built the bundle. If
you move or delete that checkout -- including removing this git worktree after
merging -- login startup breaks silently. Fix by editing the path in the plist
and running `launchctl bootout` then `bootstrap` again.

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

## Feature: DNS resolution monitor (every ever-stalled domain)

Independent of incident detection. Every `resolution_interval_seconds`
(default 5 minutes):

1. **Select the stalled domains** -- streams `resolution_log_path` and picks
   every domain whose lookup has *ever* taken at least
   `resolution_stall_seconds` (default 1.0). "Ever" is literal: one clean fast
   run afterwards does not drop a domain off the list. The list is ordered
   least-recently-checked first, so a deadline-truncated cycle can't starve the
   tail of the list forever.
2. **Resolve in parallel** -- resolves all of them concurrently via a thread
   pool (`resolution_max_workers`, default 10) instead of serially, so a batch
   with several slow/unreachable entries still finishes in roughly one timeout
   period per worker-load, not minutes.
3. **Stop at the batch deadline** -- anything still outstanding after
   `resolution_batch_deadline_seconds` (default 240) is recorded as
   `outcome: "abandoned"` and the batch returns. Lookups that never started are
   cancelled; ones already inside `getaddrinfo` are left to finish on their own
   rather than holding up the app.
4. **Log the findings** -- appends one JSON object per domain to
   `resolution_log_path` as JSON Lines (one record per line, not one big
   array, so a crash mid-write can't corrupt earlier entries and the file
   can be tailed/grepped like a normal log).

The batch runs on a worker thread, not the menu bar run loop, so a long cycle
can never delay the 30-second incident poll. If a cycle is still running when
the next one is due, the new one is skipped rather than stacked. Findings are
picked up and shown in the title by the next incident tick (AppKit status-item
updates aren't thread-safe, so the worker never touches the title itself).

Each record looks like:

```json
{"domain": "example.com", "resolved": true, "error": null, "elapsed_seconds": 0.031, "outcome": "completed", "checked_at": "2026-07-20T09:00:00+00:00"}
```

- `resolved` -- `true`/`false`
- `error` -- the resolver error string, or `null` on success
- `elapsed_seconds` -- how long that one resolution took
- `outcome` -- `"completed"` if the lookup returned, `"abandoned"` if the batch
  deadline passed first
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

## Dashboard window

There are **four** ways to get the window, because the status item in the
top-right is easy to miss on a crowded or notched menu bar:

1. It opens **shortly after launch** by default (`open_dashboard_at_launch`),
   ordered front *without* stealing focus.
2. **Click the Dock icon.** macOS asks the application delegate about this via
   `applicationShouldHandleReopen:`, which rumps does not implement -- so before
   this existed, a Dock click on an app owning no windows activated it and did
   nothing else. The app now watches for activation instead.
3. **"Net-DNS-Monitor" -> Open Dashboard** in the menu bar at the top-*left*,
   which appears when the app is active. rumps never populates that menu, so
   clicking the app name genuinely had no items behind it; it now does.
4. **Open dashboard**, the first item in the status-item dropdown at the
   top-right.

Note that route 2 relies on a notification that macOS does *not* post when the
app is already frontmost -- route 3 covers that case.

The window has four panes of information and a button per troubleshooting step.

What it shows:

- **Network right now** -- ping target, round-trip time, packet loss, download
  and upload rate. Reads `not measured yet` rather than `0` before the first
  ping, and `no reply` while pings are going unanswered.
- **Monitor** -- current status, consecutive probe failures, what the last
  incident was classified as and where its report is, the last resolution batch,
  and whether a forensic episode is currently open.
- **Other monitors on this network** -- see [LAN peer
  discovery](#feature-lan-peer-discovery).
- **Settings in force** -- every cadence and threshold actually in effect. The
  point is that the app's behaviour is explicable without opening the config
  file: if it is alerting more than you expected, this pane says why.

The buttons, each of which reports *why* the step exists alongside its result:

| Button | Kind | What it does |
| --- | --- | --- |
| Ping now | check | One immediate ICMP echo request, out of band from the heartbeat |
| Check interface state | check | `scutil --nwi` |
| Check default route | check | `netstat -rn -f inet` |
| Check DNS servers | check | `scutil --dns` |
| Check resolver overrides | check | Lists `/etc/resolver` entries |
| Resolve via public resolver | check | Raw UDP query against a public resolver |
| Flush DNS cache | **repair** | `dscacheutil -flushcache` + `killall -HUP mDNSResponder` |
| Run full diagnosis | **repair** | Probes, classifies, then runs the whole ladder for that classification |
| Open last incident report | -- | Opens the most recent report in your browser |
| Open forensic logs folder | -- | Reveals `forensic_episodes_dir` in Finder |
| Test network alert | -- | Fires the alert so you can confirm it reaches you |

Steps that mutate system state say so on the button. Everything that shells out
runs on a worker thread, never on the run loop -- `repair_executor` allows 5s per
step and a full ladder is four of them, so an inline click would freeze the
window and all four timers for up to half a minute. A second click while a step
is still running is refused rather than queued.

Anything you run by hand is recorded in the forensic log too, tagged `manual`, so
an episode's write-up shows human intervention alongside the automatic steps.

## Feature: system log viewer and search

The right-hand column of the window shows what macOS itself is saying about the
network, rather than only what this app measured. It needs no clicking: 15
minutes are backfilled at launch, then the last minute is re-read every 30
seconds, on a worker thread.

**What it reads.** Entries from `mDNSResponder`, `configd`, `symptomsd`,
`airportd`, `networkd`, `nesessionmanager` and `socketfilterfw`, plus anything --
any process -- logging under `com.apple.network`, `com.apple.mdns`,
`com.apple.SystemConfiguration`, `com.apple.WiFiManager` or `com.apple.symptomsd`.
That second half is where another app's failed connection shows up, and it is
where the useful entries were found.

**It reports automatically.** New error and fault lines are echoed into the
results pane on the left, counted in the Monitor section of the stats, and --
while a forensic episode is open -- written into that episode. So an outage's
write-up carries what the OS said at the time, not just what the prober measured.
The echo is capped by `log_view_announce_limit` per poll; the cap is on the
announcement, not on capture.

### Searching

Terms are ANDed. A term starting with `-` excludes. Matching is case-insensitive
substring over the time, level, process, subsystem and message:

```
dns                      every captured line mentioning DNS
dns -crowdstrike         ...except CrowdStrike's
configd dhcp             lines from configd that mention DHCP
[C134.1.1:3]             a connection id, pasted straight in
```

Substring rather than regex on purpose: `[C134.1.1:3]` is the kind of thing
someone pastes into a log search, and as a regex it would be an error instead of a
search. The pane re-filters as you type, off the window's 1-second refresh.

### The four controls

| Control | What it does |
|---|---|
| Refresh now | Re-reads immediately instead of waiting for the next poll |
| Errors only / All levels | The label states the filter **in force**, not the action. Switching re-reads, because the level is part of the `log show` predicate and other levels were never fetched |
| Clear search | Empties the search box |
| Empty buffer | Discards everything captured so far, and the since-launch error count |

The status line under them distinguishes "nothing captured yet" from "nothing
matched your search" from "the read failed" -- in an empty pane all three look
identical, and only some of them say anything about the network.

### Why the defaults are what they are

Measured with `log show` on a real machine:

| Query | Time | Lines |
|---|---|---|
| network errors/faults, last 1m | 1.4s | 44 |
| network errors/faults, last 5m | 1.6s | 289 |
| network errors/faults, last 15m | 4.2s | 919 |
| network errors/faults, last 60m | **16.9s** | 16,354 |
| *all levels*, same subsystems, last 30m | -- | **192,901** |

Cost is dominated by the window, not the predicate, so this polls a small window
often instead of re-reading a large one. Errors-only is the default because
192,901 lines is not something anyone reads. And the timeout is 45 seconds rather
than the 10 used elsewhere for `log show`, because 10 would silently return
nothing on the very machine this was built for.

**Coalescing is load-bearing, not cosmetic.** Of those 16,354 "errors", hundreds
were one repeated CrowdStrike line and hundreds more were one repeated WeatherMenu
line. Identical messages from the same process are collapsed into a single row
carrying the most recent time and an `(xN)` count, which is what made the one
entry that mattered visible at all:

```
12:48:56 ! identityservicesd: nw_socket_handle_socket_event [C134.1.1:3] Socket SO_ERROR [51: Network is unreachable]
```

`log_view_noise_patterns` goes further and drops entries not worth a row at all.

### What it cannot show you

macOS redacts private data in the unified log, so a DNS query arrives as:

```
getaddrinfo start -- hostname: <mask.hash: 'bUgVj5G8ik0EQt8fUVm4Fg=='>
```

Turning that back into a hostname needs a logging configuration profile. It is
not a permission this app can request, and the elevated-permission grant does not
affect it.

## Feature: forensic log of every down/up episode

Every network down/up episode is written up automatically: what was detected,
every step taken, **why** it was taken, and what it returned.

### What counts as one episode

The app has two detectors on different clocks, and neither alone can answer the
question:

| Detector | Notices | Acts |
| --- | --- | --- |
| ping heartbeat (5s) | within seconds | never -- it only displays and alerts |
| anti-flap gate (30s) | after debounce, so ~60s+ | runs the whole ladder, escalates, writes a report |

So an episode **opens on the first "down" from either detector** and **closes only
when both agree the network is back**. The heartbeat supplies the timing, the gate
supplies the actions, and one document covers both. A gate incident declared while
the heartbeat is already down joins the open episode rather than starting a second
one; a DNS incident declared while ICMP still answers opens one on its own and is
closed by the gate clearing, not by the heartbeat.

### Two artifacts

- **`forensic-log.jsonl`** -- one JSON object per event, appended *the moment it
  happens*. This is the durable half: an app killed, crashed, or a machine powered
  off mid-outage still leaves the evidence behind, which is the one case a forensic
  log exists for.
- **`episodes/<timestamp>-episode.md`** (and `.json`) -- the write-up, produced when
  the network comes back. Contains a chronological timeline and a "Steps taken"
  table of step / kind / why it was run / result.

An outage that cleared before the ladder ever started says so in words rather than
showing an empty table -- the recovery was the network's own, not the app's, and
the document should not imply otherwise.

Multi-line command output (`scutil --nwi` is a dozen lines) is flattened for the
table so one step's output cannot break the rendering of every row after it.

## Feature: LAN peer discovery

The app announces itself on the local network and looks for other copies of the
monitor running on other machines.

- **At launch** it announces (on the first sweep -- nothing about this blocks
  startup) and probes every host it remembers from the previous run.
- **Every `peer_announce_seconds`** (default 300) it re-announces and then
  heartbeats every known peer with a probe, which each peer answers with a pong.

### The protocol, in full

    announce   broadcast, "I exist, here is my id, hostname and status"
    probe      unicast, "are you still there"
    pong       unicast reply to a probe

There is no leader, no shared state, and no remote commands. A peer can learn
another peer's hostname and monitor status, and nothing else.

### The three buckets

Peers are filed by how recently they were last heard from, so a machine that is
switched off needs nothing to notice it left:

| Bucket | Meaning |
| --- | --- |
| `current` | within `peer_current_seconds` (600 = two announce intervals, so one dropped broadcast is not a demotion) |
| `recent` | within `peer_recent_seconds` (a day) -- was here, isn't answering now |
| `other` | known, but older than that -- kept as history |

All three go to `peer_record_path` (`peers.json`) and appear in the dashboard,
along with a count of missed heartbeats per peer. That file is read back at
startup, which is what lets a fresh process probe the hosts it knew about last
run instead of waiting for one of them to announce.

### What this discloses, and how to turn it off

Any host on the same LAN can learn this machine's hostname and whether its
network is currently healthy. That is the point of the feature, but it is a
disclosure:

```yaml
peer_discovery_enabled: false   # opens no socket, broadcasts nothing
```

Incoming datagrams are size-capped at 2 KB, JSON-only, checked for a protocol
tag, and every string is truncated and stripped of control characters. The peer
table is capped so a host spraying announcements with fresh ids cannot exhaust
memory. Nothing from a packet is ever used as a path, a command, or an argument.

If the UDP port is unavailable -- another copy on this machine already has it, or
a sandbox denies it -- discovery is simply off for that sweep and the monitor
carries on. A network-monitoring tool that refuses to start because it could not
open a discovery socket has its priorities backwards.

## Menu bar reference

- **App name:** shows as "Net-DNS-Monitor" everywhere -- app menu, Dock,
  Force Quit, Cmd-Tab -- when launched via `scripts/start.sh`'s `.app`
  bundle. Launched directly via `python -m netdnsmonitor.app` instead, the
  app-menu title still says "Net-DNS-Monitor" (a runtime override), but
  the Dock/Force-Quit/Cmd-Tab name falls back to "Python" -- that specific
  fix needs the real bundle's own `Info.plist` identity, which only the
  `.app` launch path provides.
- **Dock icon:** the current round-trip time in milliseconds, drawn in the
  status colour below (`✕` while pings go unanswered, `--` before the first
  one comes back). This replaced a tinted `wifi` SF Symbol, which looked
  identical whether the round trip was 12ms or 900ms.
- **Network statistics**, at the front of the title, replacing what used to be
  a constant 📶 glyph:

  ```
  61ms 1.2M↓0.3M↑ 🟢 Net/DNS: healthy
  61ms 8% 340K↓12K↑ 🟢 Net/DNS: healthy
  no reply 🔴 Net/DNS: ping issue
  ```

  Round-trip time to `ping_host`, then packet loss over the last
  `ping_loss_window` pings *only when it is nonzero* (menu bar width is
  scarce), then throughput in bits per second, down and up. All of it refreshes
  every `ping_interval_seconds` (default 5). `--ms` means no ping has come back
  yet, which is the first few seconds after launch.
- **Status icon, three states from two small heuristics:**
  - 🟢 healthy -- no recent probe failures.
  - 🟡 flaky -- at least one consecutive probe failure, but still below
    `failure_threshold`, so no incident has been declared yet. An early
    warning the binary healthy/incident split wouldn't otherwise show.
  - 🔴 incident -- the anti-flap gate has declared one (with the layer,
    e.g. "🔴 Net/DNS: dns issue"), **or** the ping heartbeat is failing, which
    reads "🔴 Net/DNS: ping issue". The heartbeat drives the indicator
    directly because the gate debounces a 30-second poll and would otherwise
    leave the menu bar green for up to a minute after the network dropped. A
    real gate-declared incident keeps its own more specific label.
  - Independent of all three: if the most recent resolution-monitor batch
    (see [resolution monitor](#feature-dns-resolution-monitor-every-ever-stalled-domain))
    had any failed domain, the title gets a `N/total resolution fails`
    suffix -- since a top-queried domain can stop resolving without
    tripping the single configured `domains` check.
- **"Open dashboard"** -- opens the window described in [Dashboard
  window](#dashboard-window): live statistics, the settings in force,
  discovered peers, and a button per troubleshooting step.
- **"Open last report"** -- opens the most recent incident report's
  Markdown file in your default browser. Shows a notification instead if
  no incident has occurred yet.
- **"Test network alert"** -- fires the network-failed alert on demand: the
  Dock bounces and a notification appears. Use it once after installing to
  confirm alerts actually reach you. Whether macOS draws a notification banner
  depends on notification authorisation for this bundle, which the app cannot
  check from the inside; if the Dock bounces but no banner appears, allow
  Net-DNS-Monitor under System Settings → Notifications. Every alert also
  writes an `[alert]` line to the app log, so `net-dns-monitor-service logs`
  will show whether the app decided to alert regardless.

## Feature: ping heartbeat and the network-failed alert

Every `ping_interval_seconds` (default 5) the app sends one ICMP echo request
to `ping_host` (default `8.8.8.8`) and reads the interface byte counters. That
pair drives the statistics in the menu bar, the Dock tile, and the alert.

When a ping fails, the app **bounces the Dock icon** (a critical-priority
attention request, so it keeps bouncing until you activate the app) and posts a
**"network failed" notification** naming the host and the error.

The alert is edge-triggered. At a 5-second cadence, alerting on every failed
ping would mean twelve bounces and twelve notifications a minute for as long as
the network is down -- precisely when you can do least about it. So it fires on
the transition into failure and then goes quiet. Recovery cancels the bounce
and re-arms the alert, so the next outage alerts again.

Tuning:

| Key | Default | Effect |
| --- | --- | --- |
| `ping_host` | `8.8.8.8` | What to ping. Point elsewhere if your network filters ICMP to this address. |
| `ping_interval_seconds` | `5` | Heartbeat cadence. |
| `ping_timeout_seconds` | `2.0` | Per-ping ceiling. A failed ping takes about this long to give up. |
| `ping_failure_threshold` | `2` | Consecutive failed pings before alerting. Set to `1` to alert on every dropped packet. |
| `ping_alert_repeat_seconds` | `0` | `0` = one alert per outage. Set to `300` to be re-alerted every 5 minutes while down. |
| `ping_loss_window` | `12` | How many recent pings the loss percentage averages over. 12 at 5s is the last minute. |

Two deliberate boundaries:

- **The heartbeat never repairs anything.** It does not touch the anti-flap
  gate, the troubleshooting ladder, Claude escalation, or incident reports.
  Those stay behind the debounced 30-second poll, because acting on a false
  positive there costs flushed DNS caches and API calls, while a false positive
  here costs one unnecessary Dock bounce.
- **It uses ICMP where the incident prober deliberately does not.** `prober.py`
  avoids ICMP because it is widely filtered and a filtered target reads as a
  false "down". That reasoning still holds for incident detection; for a
  display-and-alert heartbeat against one host you named explicitly, a filtered
  path only degrades the display. See `netdnsmonitor/ping.py`.

The ping runs on a worker thread, never on the run loop: a failed ping takes
about 3 seconds to give up, and doing that inline would freeze the UI and both
other timers for most of every cycle throughout an outage. The consequence is
that the display trails the ping by one cadence, the same trade the resolution
batch already makes.

## Permissions

Reading system logs (`log show`, used by the incident log watcher, the
resolution monitor's query-log reader, and the system log viewer in the window)
may require "Full Disk Access" or a log-access prompt the first time it runs,
depending on macOS version. Grant it via **System Settings -> Privacy &
Security -> Full Disk Access** if `log show` calls silently return no data.

### Elevated permissions for the two root-only repair steps

Two repair steps need root. The dashboard has a **Grant elevated permissions**
button and a **Revoke elevated permissions** button beside it. Clicking Grant
prints exactly what it will permit into the results pane *before* macOS raises
its authentication dialog, so it can still be cancelled after reading.

It installs one file -- `/etc/sudoers.d/net-dns-monitor`, `root:wheel`, mode
0440 -- listing your account and these complete commands:

```
/usr/bin/killall -HUP mDNSResponder         restart the system DNS responder
/usr/sbin/ipconfig set <interface> DHCP     re-request a DHCP lease
```

This is a real and persistent change to what this Mac will do without
authenticating. Once the file exists, **any** process running as you -- not only
this app, and including software you did not install deliberately -- can run
those specific commands as root with no prompt. Decide whether that trade is
worth it before clicking; the app cannot make that call for you.

What bounds the exposure:

- Both are complete command lines, and sudo matches arguments, so the grant does
  not extend to `killall` or `ipconfig` in general.
- No wildcard anywhere in the file, and no shell entry. Either would amount to
  unrestricted root, which is why interfaces are enumerated at grant time and
  validated against `^en\d+$` before being written.
- Neither command takes a file path, reads or writes your data, or can be made to
  run another program. The worst either can do is briefly interrupt this
  machine's own network.
- sudo logs every use. **Revoke** deletes the file.

Before installing anything, the grant verifies that `/etc/sudoers` really
includes `/etc/sudoers.d` -- otherwise the file would be silently ignored and the
button would be reporting success for nothing -- and validates the generated file
with `visudo -cf`, because an invalid file in `sudoers.d` breaks `sudo` for the
whole machine. It never edits `/etc/sudoers` itself; if the include line is
missing it explains that and stops.

The current state is shown in the window's **Permissions** section, checked with
`sudo -n -l <command>`, which asks whether a command is permitted rather than
running it. (Checking by running the real command would restart the DNS responder
every time the window refreshed.)

**With the grant:** "Flush DNS cache" restarts mDNSResponder instead of
reporting a partial result, and `renew_dhcp_lease` runs on the default-route
interface instead of returning `NEEDS_PRIVILEGE`.

**Still not automated, by choice:** `toggle_network_service`. Down-then-up cannot
be one command, and the only way to make it one would be to allow a shell as
root. Two commands is worse than the problem it solves -- if anything interrupts
the second, the machine is offline with no network to fix it over. The step
reports `NOT_AUTOMATED` and says why, rather than implying a missing permission.
Toggle Wi-Fi or the cable by hand if the rest of the ladder has not helped.

**Not a permission at all:** macOS redacts private data in the unified log, so
DNS names appear as `qname: <mask.hash: '...'>`. That needs a logging
configuration profile; sudo does not affect it.

See [Honest scope](#honest-scope--known-limitations) for the rest of what this
build does and does not do.

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
| Resolution log never appears at all on a fresh install | Expected, and it will not self-correct: the selector reads the resolution log, and the only thing that writes that log is the job consuming the selector's output. No log means no domains, which means no findings, which means nothing is appended | See [the seeding limitation](#the-monitor-needs-a-seeded-log) -- the log has to be seeded once by something else |
| Resolution log has no new entries | Nothing has crossed `resolution_stall_seconds` yet, so the retry list is empty | Lower `resolution_stall_seconds` to widen what counts as a stall |
| Resolution records all say `outcome: "abandoned"` | The batch is hitting `resolution_batch_deadline_seconds` before the lookups return | Raise `resolution_max_workers`, raise `resolution_stall_seconds` to shrink the list, or raise the deadline (keeping it under `resolution_interval_seconds`) |
| Escalation field shows an error instead of an analysis | `ANTHROPIC_API_KEY` not set, or the API call failed | Export the key; check the error string in the report's escalation field for the underlying cause |
| `flush_dns_cache` reports `partial` | `dscacheutil -flushcache` succeeded but `killall -HUP mDNSResponder` was rejected | Expected and documented -- mDNSResponder runs as a different user; a signal from an unprivileged process is rejected regardless of the command's own permissions |
| `scripts/start.sh` finishes with no visible menu bar icon | `open -n dist/Net-DNS-Monitor.app` failed silently, or the app errored before reaching rumps | Check `net-dns-monitor.log` in the repo root for the actual error |
| `python setup.py py2app` fails with `[Errno 66] Directory not empty` | py2app's intermediate `build/` staging dir from a previous run wasn't cleaned (seen intermittently) | `scripts/start.sh` already does this before every build; if running the command by hand, `rm -rf build dist` first |
| Ctrl-C in the terminal doesn't stop the app | Expected once launched via `scripts/start.sh`'s `.app` bundle -- it's an independent process, not a child of the shell | Quit via the menu bar's Quit item, or `pkill -f netdnsmonitor.app`; use `python -m netdnsmonitor.app` directly instead if you want Ctrl-C to work |
| Repair steps report `NEEDS_PRIVILEGE` | DHCP renewal / interface toggling need elevated rights this sandboxed app doesn't have | Not implemented in this MVP; see Honest scope below |

## Project layout

- `classifier.py` -- network-vs-DNS-vs-healthy-vs-unclassified split
- `flap_gate.py` -- anti-flap consecutive-count debounce
- `ladder.py` -- the offline troubleshooting ladder definition
- `repair_executor.py` -- dispatches ladder steps to real macOS commands
- `dns_query.py` -- raw UDP query against a specific public resolver
- `prober.py` -- TCP-connect reachability + DNS resolution aggregation
- `ping.py` -- one-shot ICMP ping with round-trip-time parsing
- `ping_monitor.py` -- packet-loss window + the edge-triggered alert decision
- `net_stats.py` -- interface byte counters and throughput derivation
- `alert.py` -- Dock bounce + the network-failed notification
- `log_watcher.py` -- `log show` tailing/filtering for DNS/network errors
- `stall_log.py` -- selects every ever-stalled domain from the resolution log
- `query_log.py` -- `log show` reading + top-queried-domain extraction; no longer wired into the resolution monitor (kept and still unit-tested)
- `resolution_prober.py` -- parallel DNS resolution of a domain batch
- `resolution_log.py` -- JSONL append for resolution-monitor findings
- `escalation.py` -- redaction + the escalate-or-not gate
- `anthropic_escalator.py` -- the Claude API call itself
- `report.py` / `report_storage.py` -- incident report schema + persistence
- `status.py` -- menu bar title logic + the shared healthy/flaky/incident status decision
- `dock_icon.py` -- draws the Dock tile as the current reading, in the status colour
- `dock_icon.py` -- renders the tinted network-glyph Dock icon
- `state_machine.py` -- orchestrates incident detection end to end
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell wiring everything together
- `scripts/start.sh` -- install check + component verification + builds/launches the frozen `.app` bundle
- `setup.py` -- py2app build spec (run `python setup.py py2app`; output at `dist/Net-DNS-Monitor.app`, gitignored)

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
- The resolution monitor's stall list is seeded from records the app wrote
  itself, which were originally produced by a regex over raw `log show` text
  rather than a parse of mDNSResponder's internal log schema (not stable
  across macOS versions, not independently documented by Apple). So the list
  can contain entries that were never really hostnames. They are kept rather
  than filtered: something that took 30s to answer is a real observation about
  this machine, and inventing an "is this a real domain" predicate would throw
  away true stalls as readily as false ones.
- On the observed log this selects a list dominated by `.local` mDNS names
  (UUID-named Bonjour/AirPlay devices) and reverse `in-addr.arpa` lookups.
  That is genuine local-network slowness, not a bug, but it does mean the list
  is more about LAN discovery than about internet DNS.

### The monitor needs a seeded log

The retry list is "every domain that has ever stalled", read out of the
resolution log. The only writer of that log is the resolution job that consumes
the list. Those two facts together make the set **closed**:

- On a **fresh install** the monitor is a permanent no-op. Empty log to `[]`
  domains to no findings to nothing appended to still-empty log, every cycle,
  forever. Verified against an empty directory: the log is never even created.
- Even with a primed log, a domain that is not already in it can never enter
  the set, because only domains already selected are ever re-resolved.

This is a property of the requested design ("retry everything that ever
stalled"), not a bug in it -- but it does mean the feature reports on a fixed
population. On this machine that population is the 16k-record history left by
the retired query-log path, which yields 91 domains.

`query_log.extract_top_domains` -- which used to do the discovery -- is still
present and still unit-tested, just not wired into `app.py`. Re-adding a
discovery pass to `build_resolution_job` is about a five-line change if you
later want new stalls to be found automatically.

### The timeout that isn't

`resolution_timeout_seconds` does not bound a lookup. `socket.getaddrinfo()`
is a blocking call into the system resolver and is not interruptible from
Python; `socket.setdefaulttimeout()` has no effect on it. Measured on this
machine: a missing `.local` name took **5.01s** against a 2.0 setting, and the
resolution log contains real lookups at 30s and 35s under the same setting.

The key is kept because injected resolvers in the tests honour it and it
documents intent, but the thing that actually bounds a cycle is
`resolution_batch_deadline_seconds`. Bounding a single lookup properly would
mean either resolving out-of-process or issuing raw DNS queries instead of
using the system resolver -- and the latter would stop testing the code path
that actually matters (`.local` mDNS names don't resolve over plain UDP DNS at
all).
