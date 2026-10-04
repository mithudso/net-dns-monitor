# Scripts

Every runnable entry point in this repo: what it is for, when to reach for it, **when
not to**, its options, a real invocation, and the output you should expect.

`README.md` is the product description; this page is the operator's manual — the
commands you actually type, including the one-shot module invocations that are the
only way to exercise a piece of this app without a menu bar.

Every example below was executed against this repo on macOS 25.4 with Python 3.13.1.
The notification, `StateMachine` and title samples were re-run on 2026-09-14 with
Python 3.13.15 after `b07eee5`. Where output is shown it is real, trimmed for length,
never illustrative, unless the text says it is an example.

## The one rule

**This app diagnoses far more than it fixes, and the report is the deliverable.** Of
the eight ladder steps present by default, three are repairs. Without the sudoers
grant from `privileges.py`, exactly one of them mutates anything (`flush_dns_cache`),
and it only half-works: `dscacheutil -flushcache` succeeds, `killall -HUP
mDNSResponder` does not, because the system rejects a signal to a process owned by
another user regardless of the command's own permissions. It reports `partial`.
`renew_dhcp_lease` reports `NEEDS_PRIVILEGE` and runs nothing. With the grant, the
flush completes and `renew_dhcp_lease` runs; the grant has never been exercised live.
`toggle_network_service` is never automated and reports `NOT_AUTOMATED`.

Enabling failover (`failover_enabled` plus both service names) adds a ninth step,
`switch_to_backup_network`, which is the only one that rewrites system network
configuration. It is off by default and reports
`NEEDS_PRIVILEGE` rather than acting when the administrator right is refused. Read
"Reading the output correctly" at the bottom before concluding this app fixed anything.

One command is a gate rather than an experiment. Run it before trusting the rest:

```bash
python3 -m pytest -q          # 2150 tests; the whole decision surface
```

## Quick reference

| Command | For | Network |
|---|---|---|
| `python3 -m netdnsmonitor.cli <cmd>` | **start here** — the CLI | varies |
| `python3 -m netdnsmonitor.cli interfaces` | every service, live, with reachability | **yes** |
| `python3 -m netdnsmonitor.cli bench` | + measured throughput per interface | **yes** |
| `python3 -m netdnsmonitor.cli console` | interactive diagnostics | **yes** |
| `python3 -m netdnsmonitor.app` | the menu bar app — **blocks forever** | **yes** |
| `python3 -m pytest` | **gate:** the full decision surface, 2150 tests | no |
| one-shot `prober` (below) | "is it up right now", scriptable | **yes** |
| one-shot `ladder` + `repair_executor` | run the triage steps by hand | **yes** |
| one-shot `log_watcher` | what log evidence a report would carry | no |
| one-shot `extract_failed_domains` | which domains the app would learn | no |
| one-shot `query_public_dns` | bypass the system resolver entirely | **yes** |
| one-shot `format_notification` | see the alert text without sending it | no |
| one-shot `StateMachine` | the whole pipeline, offline, with fakes | no |
| one-shot `service_order` + `interface_probe` | read-only failover dry run | **yes** |
| menu bar **Switch to backup now** | **mutates system network config** — the intended live check | **yes** |
| **failover live check** by hand (below) | **mutates system network config** | **yes** |
| `scripts/appstore/build_appstore.py adhoc\|release` | build and sign the Mac App Store bundle | no |
| `scripts/appstore/make_icon.py OUT.icns` | draw the app icon (`PREVIEW.png` for one 1024px render) | no |
| `scripts/appstore/shoot_screenshots.py OUT_DIR` | run the store edition from source and render its windows to PNG (GUI session) | no |
| `scripts/appstore/compose_screenshots.py IN_DIR OUT_DIR` | place those renders on 2880x1800 backgrounds for App Store Connect | no |
| `sandbox_probe` inside an ad-hoc bundle | measure what works inside the App Sandbox | **yes** |

The CLI is the interface for diagnostics, and `app.py` stays a rumps shell over the
same tested modules. `scripts/` holds the launcher and installer (`start.sh`,
`install.sh`, `net-dns-monitor-service`; see `docs/DEVELOPMENT.md`) and the Mac App
Store build tools (`scripts/appstore/`, below). The one-shot `python3 -c` invocations
further down predate the CLI and are kept because they show which module owns which
decision — but for day-to-day use, reach for `netdnsmonitor.cli`. Everything runs from
the repo root.

### `python3 -m netdnsmonitor.cli` — the CLI

| Subcommand | Does |
|---|---|
| `status` | classification, probe results, failover state. Exit 1 if unhealthy. |
| `interfaces [--bench]` | every network service: device, enabled, reachable, speed |
| `bench` | measure throughput per reachable interface |
| `failover status\|backup\|preferred [--service NAME]` | show or change the live network |
| `priority [--promote NAME]` | show or rewrite the service order |
| `ladder network\|dns [--repair]` | run the troubleshooting ladder |
| `commands` | the diagnostic command catalogue |
| `run KEY [--value NAME=VAL] [--yes]` | run one catalogue command |
| `guide` | what to do when the network breaks |
| `console` | interactive |

`--json` on `status`, `interfaces` and `bench` gives machine-readable output.

Real output from this machine:

```
$ python3 -m netdnsmonitor.cli bench
 #  SERVICE                    DEVICE   SVC  REACHABLE     Mbps
---------------------------------------------------------------
 1  AX88179B                   en6      on   not probed       -
 2  USB 10/100/1000 LAN        en7      on   not probed       -
 3  USB 10/100/1G/2.5G LAN     en9      OFF  unreachable      -
 4  M3100                      en12     OFF  unreachable      -
 5  Thunderbolt Bridge         bridge0  on   unreachable      -
 6  Wi-Fi                      en0      on   reachable      3.5
 7  iPhone USB                 en11     on   not probed       -
```

Three columns worth reading carefully:

- **`SVC = OFF`** means the network *service* is disabled. macOS skips it no matter
  where it sits in the priority order, so promoting it alone does nothing — the app
  enables it as well, and `netdns run enable --value service='M3100' --yes` does it by
  hand.
- **`not probed` is not `unreachable`.** An unplugged adapter disappears from the
  interface list entirely; calling that "unreachable" would send you after the wrong
  fault.
- **`Mbps = -`** means not measured, never "zero". Only reachable interfaces are
  benchmarked, because there is nothing to measure on a path carrying no traffic.

### `python3 -m netdnsmonitor.cli console` — interactive

A REPL over the same catalogue. `?` guide · `i` interfaces · `b` benchmark ·
`c` commands · `s` failover status · `f` switch to fastest backup · `p` back to
preferred · `q` quit. Pick a diagnostic by number or key.

Anything that changes system state — a catalogue command marked `!`, switching
networks (`f`/`p`), or `promote` — prints the exact argv and waits for `yes`. Nothing
that rewrites configuration happens on a single keypress. A command with a placeholder
asks for the value rather than shelling out with a literal `{device}` in it.

The menu bar's "Open console" item opens a different console: an arbitrary shell
(`console.py` + `console_window.py`), not this catalogue.

---

## Setup

```bash
python3.13 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -c constraints.txt      # the app's four runtime pins
pip install -r requirements-dev.txt -c constraints.txt  # adds pytest and ruff, for the gate

mkdir -p ~/.config/net-dns-monitor
cp config.yaml ~/.config/net-dns-monitor/config.yaml
```

**Optional credentials, all three independent.** Each unset feature degrades to a
no-op rather than an error:

```bash
export ANTHROPIC_API_KEY=sk-ant-...                          # LLM escalation
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... # Slack alerts
export SMTP_PASSWORD=...                                      # email auth, if the relay needs it
```

The app reads each one from the environment first and from the Keychain second
(`credentials.py`). The menu bar's Credentials submenu saves a value to the Keychain.
An exported variable wins over a saved one.

**No secret belongs in `config.yaml`.** For a Slack incoming webhook the URL *is* the
credential. `config.yaml` is gitignored anyway, but the split is not about git — it is
so an error string can never carry the secret. Email also needs `email_recipients` in
the config; an empty recipient list leaves that channel inactive.

---

## The app

### `python3 -m netdnsmonitor.app` — the menu bar shell

**Purpose.** Poll on `poll_interval_seconds`, classify, run the offline ladder,
recheck, escalate to Claude if still broken, write the report, alert Slack/email, and
paint a status icon.

**When to use it.** Normal operation, and the only way to exercise `rumps.Timer` and
the status item.

**When *not* to use it.** From a script, an agent, or CI. `rumps.App().run()` starts a
macOS run loop and **never returns** — invoke it expecting completion and you hang.
Use the one-shot invocations below instead. It also needs a real GUI session; there is
no headless mode.

```bash
source .venv/bin/activate
python3 -m netdnsmonitor.app     # blocks; Ctrl-C or the menu to quit
```

**An exception in a timer callback does not stop the timer.** `rumps` 0.4.0 catches
exceptions in `Timer.callback_` and `MenuItem.callback_` and prints the traceback. The
hazard is the rest of that callback: a raise skips the title repaint and, on an incident
edge, the alert, which the anti-flap gate never offers again. That is why `app.tick()`
wraps `_tick()` and why every injected call in the incident pipeline fails as data.

Title output from `status.build_title` with no heartbeat reading yet (`--ms` is replaced
by the ping and throughput stats once the first ping lands):

```
healthy   None           -> --ms 🟢 Net/DNS: healthy
incident  dns            -> --ms 🔴 Net/DNS: dns issue
incident  None           -> --ms 🔴 Net/DNS: unknown issue
healthy   ping_down=True -> --ms 🔴 Net/DNS: ping issue
```

**The title is driven by the live flap-gate state, not by the last report.** That is a
fixed bug, not a detail: recovery produces no report, so a title read off "last
report" stayed red forever after the network came back.

**The menu.** Three greyed indicator rows (readouts, not actions), then the controls.
The item order below is the direct build's, taken from
`NetDnsMonitorApp._menu_layout`; the indicator text is an example:

```
Active: Wi-Fi — failover is automatic
○ Preferred: AX88179B (en6) — unreachable
● Backup: Wi-Fi (en0) — reachable
─────────────────────────
Open dashboard
Open console
Toggle mini window
Open last report
─────────────────────────
Router ▸       Management Console · Configure... · Start · Stop · List Interfaces · Troubleshoot
Start at Login
Test network alert
Credentials ▸  Set Anthropic API key… · Set Slack webhook URL… · Set SMTP password… · Remove saved credentials
─────────────────────────
Switch to backup now
Switch back to preferred now
Refresh network status
```

The Mac App Store build leaves out Open console, Router, Start at Login and the two
Switch items, and adds "Allow Claude diagnosis…", "Withdraw Claude permission" and
"Privacy Policy". See `docs/APP_STORE_SUBMISSION.md`.

`●` marks the service at the head of the service order. That is not always the link
carrying traffic: see `docs/known-issues.md` for an unplugged adapter at the head.
Reachability is tri-state and says `not probed` for an absent adapter rather than
`unreachable`, because an unplugged cable is not a dead link.

The rows are repainted on startup, after any switch, after an incident report, after
an attempted failback, and on "Refresh network status" — **not** every tick. A refresh
costs a `networksetup` subprocess plus two interface probes, which is not an
every-30-seconds price to pay on the run loop.

---

## One-shot invocations

These are the operator's real tools. Every module takes its side effects as injected
callables, which is what makes each one runnable in isolation.

### `prober` — is it up right now?

**Purpose.** TCP-connect reachability plus DNS resolution, aggregated. TCP rather than
ICMP ping because ping is widely filtered and rate-limited, which produces false
"down" readings.

**When to use it.** Scripted health checks; confirming a config change probes what you
meant.

**When *not* to use it.** To measure latency. It returns `True`, `False` or `None` per
field and deliberately throws away timing.

```bash
python3 -c "
from netdnsmonitor.prober import make_prober
p = make_prober(external_targets=[('1.1.1.1',443)], internal_targets=[], domains=['api.anthropic.com'])
print(p())
"
```

```
{'external_reachable': True, 'internal_reachable': None, 'dns_ok': True, 'domain_results': {'api.anthropic.com': True}}
```

Note `internal_reachable: None`. **`None` means "not probed", not "down"** — with no
internal targets configured there is nothing to report, and `classify` maps a `None`
in either load-bearing field to `unclassified` rather than guessing.

**All domain lookups share one deadline** (`probe_timeout_seconds`, default 2.0s), run
on worker threads. Two reasons, both learned the hard way: `socket.setdefaulttimeout`
does **not** bound `socket.getaddrinfo` (it only affects new socket objects), so the
obvious-looking timeout was inert; and sequential lookups made the block additive —
with 20 learned names plus the control domain, an outage froze the menu bar for ~42s.

### `ladder` + `repair_executor` — run the triage by hand

**Purpose.** Execute the steps a `dns`- or `network`-classified incident would run.

**When to use it.** Reproducing what a report says, or checking a step still works
after a macOS update.

**When *not* to use it.** Without reading which steps mutate. The filter below runs
`kind == "check"` only — every check shells out to a read-only system tool. Drop the
filter and you also run `flush_dns_cache`, which really does flush your DNS cache.

```bash
python3 -c "
from netdnsmonitor.classifier import classify
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.repair_executor import make_repair_executor
ex = make_repair_executor()
c = classify(True, False)
print('classification:', c.value)
for step in ladder_for(c):
    if step.kind == 'check':
        out = ex(step)
        print(f'{step.name}: {out.splitlines()[0] if out else out}')
"
```

```
classification: dns
check_configured_dns_servers: DNS configuration
check_resolver_overrides: no /etc/resolver overrides configured
resolve_against_public_resolver: example.com resolved via public resolver
```

The nine steps (eight with failover disabled) and what they actually do:

| Step | Kind | Runs | Privilege |
|---|---|---|---|
| `check_interface_state` | check | `scutil --nwi` | no |
| `check_default_route` | check | `netstat -rn -f inet` | no |
| `check_configured_dns_servers` | check | `scutil --dns` | no |
| `check_resolver_overrides` | check | reads `/etc/resolver` | no |
| `resolve_against_public_resolver` | check | raw UDP to 1.1.1.1 | no |
| `flush_dns_cache` | **repair** | `dscacheutil` + `killall -HUP` (+ `sudo -n killall -HUP` with the grant) | **partial** without the grant |
| `renew_dhcp_lease` | repair | `sudo -n ipconfig set <iface> DHCP` with the grant; **nothing** without it | sudoers grant |
| `toggle_network_service` | repair | **nothing — `NOT_AUTOMATED`** | not automated by design |
| `switch_to_backup_network` | **repair** | `networksetup -ordernetworkservices` | **needs admin — really attempted** |

The sudoers grant (`privileges.py`, the "Grant elevated permissions" button) writes
`/etc/sudoers.d/net-dns-monitor`. It has never been exercised live; see
`docs/known-issues.md`.

### `log_watcher` — what evidence would a report carry?

**Purpose.** Tail `log show` for DNS/network subsystem entries and keep the error-like
lines.

**When to use it.** Before filing a bug about an empty "Log Excerpts" section.

**When *not* to use it — and this one matters.** Do not raise `log_lookback` past the
default `5m` without checking the read still finishes. `log show` runs with a fixed
10s timeout (`LOG_SHOW_TIMEOUT_SECONDS`, not configurable). Measured on this machine:

```
5m  -> 424 lines   real 2.25s
15m -> 1619 lines  real 4.97s
30m -> 3942 lines  real 10.15s     <- at the 10s limit; an earlier run returned 0
```

If `log show` times out, exits nonzero or cannot run, the watcher returns one line
instead of excerpts, for example:

```
[net-dns-monitor] no log evidence: log show timed out after 10s (lookback 30m)
```

`[]` means `log show` ran and no line matched. A `30m` lookback no longer fails
silently. It still sits at the limit, so its report can carry that line instead of log
evidence.

```bash
python3 -c "
from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX, make_log_watcher
lines = make_log_watcher(lookback='5m')()
if lines and lines[0].startswith(NO_EVIDENCE_PREFIX):
    print(lines[0])
else:
    print('error-like lines:', len(lines))
    for l in lines[:2]: print(l[:110])
"
```

```
error-like lines: 498
2026-08-05 20:33:10.017 Df airportd[517:66a464] [com.apple.WiFiManager:] [corewifi] LQM: rssi=-28dBm per_ant_r
2026-08-05 20:33:10.054 Df mDNSResponder[441:66b4fc] [com.apple.mdns:resolver] [Q65460] Sent 47-byte query #1
```

**Several hundred "error-like" lines on a healthy machine is normal.** The filter is
substring matching on `error`/`fail`/`timed out`/`timeout`/`unreachable`/`refused`,
so a line reporting Wi-Fi signal quality qualifies. Count is not signal — and it moves
run to run, since the window slides; the 498 above and the 424 below are two runs
minutes apart, not a discrepancy.

### `extract_failed_domains` — which domains would be learned?

**Purpose.** Show which hostnames the auto-learner would pick up from the log. Domains
that *failed* resolution are, by definition, names someone tried to reach and could
not — better evidence than browser history, and it needs no user action.

**When to use it.** Before enabling `learn_domains_from_logs` on a machine you care
about, and when the probe list contains something you did not expect.

**When *not* to use it.** As a general hostname extractor. It requires a
resolution-failure marker on the line, vetoes success phrasing, and rejects IP
literals, `.arpa` reverse zones, and bare labels. And do not read a `[]` as "nothing
failed" — see the masking note below.

```bash
python3 -c "
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.domain_learner import extract_failed_domains
lines = make_log_watcher(lookback='5m')()
found = extract_failed_domains(lines)
print(f'{len(lines)} error-like lines -> {len(found)} learnable domains')
print(found[:8])
"
```

If the log could not be read, `lines` holds the one `[net-dns-monitor] no log evidence`
line, which `extract_failed_domains` skips, so the output reads `1 error-like lines -> 0
learnable domains`. Check `lines[0]` before reading that as a log with nothing to learn.

On this machine the answer is nothing — and **not** because nothing failed:

```
424 error-like lines -> 0 learnable domains
[]
```

**macOS redacts hostnames in the unified log by default, so this feature finds nothing
on a stock install.** Measured on this machine: of 758 error-like lines, 198 carry a
literal `<mask.hash: 'qJ2TZCt3dlygbou+PwMBqg=='>` in place of the hostname, and
mDNSResponder's resolver lines encode the queried name as an opaque token —
`BBUpzafn IN A?` rather than `example.com IN A?`. A redacted name cannot be extracted
by any regex, so `extract_failed_domains` returns `[]` whether or not resolutions
failed.

Unmasking is a **system-wide privacy change**, not a per-app setting — it makes every
subsystem's private data readable by anything that can read the log:

```bash
sudo log config --mode "private_data:on"     # do not leave this on
```

Decide accordingly. With masking left on (the default), treat `domains` in
`config.yaml` as the real probe list and auto-learning as inert. **A zero here is
ambiguous by construction** — it cannot distinguish "no lookups failed" from "the
names were redacted".

**If you see something that is obviously not a website in the probe list, say so.**
Running this against the live log is how `com.apple.mdns` was found being learned as a
domain: the log's own subsystem label `[com.apple.mdns:resolver]` has the exact shape of
a hostname. Bracketed spans are now stripped before matching and reverse-DNS
identifiers are rejected, but the general hazard stands — the input is unstructured log
text from an OS that owes this app no format stability.

**Learned names are prunable, and the control domain is why that works.** A learned
name that fails while `control_domain` (default `api.anthropic.com`) still resolves is
a dead name, not a broken resolver, and is evicted. With the control also failing,
nothing is pruned — that is the systemic outage worth reporting. Without an anchor the
guarantee collapses on the default `domains: []`, where every probed name is a learned
failure and "something else resolved" is false by construction. `dns_ok` is
`all()`-across-domains, so one un-prunable dead name would pin a permanent false
incident.

Inspect the store:

```bash
python3 -c "
from netdnsmonitor.config import load_config
import os
cfg = load_config(os.path.expanduser('~/.config/net-dns-monitor/config.yaml'))
print('path:', cfg['learned_domains_path'])
print('exists:', os.path.isfile(cfg['learned_domains_path']))
print('control:', cfg['control_domain'], '| interval:', cfg['domain_learn_interval_seconds'])
"
```

```
path: /Users/<you>/Library/Application Support/net-dns-monitor/learned_domains.json
exists: False
control: api.anthropic.com | interval: 300
```

**`domain_learn_interval_seconds` is clamped to at least twice
`poll_interval_seconds`** by `load_config`. Scanning every tick re-adds a dead name as
fast as pruning drops it, so the flap gate's success counter never resets and one dead
name latches a permanent incident by a second route.

### `query_public_dns` — bypass the system resolver

**Purpose.** Hand-rolled UDP query against a chosen resolver. `getaddrinfo` cannot do
this: it always goes through whatever the OS is configured to use, so it cannot tell
"your resolver is broken" from "DNS is broken everywhere" — the captive-portal case.

```bash
python3 -c "
from netdnsmonitor.dns_query import query_public_dns
print('1.1.1.1 ->', query_public_dns('api.anthropic.com'))
print('8.8.8.8 ->', query_public_dns('api.anthropic.com', server='8.8.8.8'))
"
```

**When *not* to use it.** As a resolver. It parses no answer records — there is no
address in the result. It returns one of three values:

| Result | Meaning |
|---|---|
| `True` | the resolver replied to this query with `rcode` 0 |
| `False` | a reply arrived with any other `rcode`, was malformed or did not match the query, or the name has no DNS wire form |
| `None` | no reply arrived (timeout, no route, UDP port 53 blocked): the name was never tested |

The ladder step reports `None` as "could not reach the public resolver", never as a
failed lookup.

### `format_notification` — see the alert without sending it

**Purpose.** Render the exact text Slack and email would receive.

**When to use it.** Reviewing what leaves the machine before pointing it at a real
channel. With no `SLACK_WEBHOOK_URL` and no `email_recipients`, the fan-out has zero
channels and returns `[]` — there is no accidental-send path.

```bash
python3 -c "
from netdnsmonitor.notifications import format_notification, make_notifier
report = {
    'classification': 'dns', 'started_at': '2026-08-05T20:31:00+00:00',
    'duration_seconds': 12.0, 'resolved': False,
    'summary': 'DNS-layer incident detected, unresolved after the ladder ran.',
    'repair_outcome': 'flush_dns_cache: partial', 'escalation': None,
}
print(format_notification(report, '/tmp/2026-08-05.md'))
print('--- zero channels:', make_notifier([])('x'))
"
```

```
Net/DNS incident: dns
Started: 2026-08-05T20:31:00+00:00
Duration: 12s
Healthy on recheck: False
Summary: DNS-layer incident detected, unresolved after the ladder ran.
Repair outcome: flush_dns_cache: partial
Full report: /tmp/2026-08-05.md
--- zero channels: []
```

`Healthy on recheck` is the recheck result only. It is `True` for an `unclassified`
incident, which runs no ladder, and for a blip that cleared while every repair returned
`NEEDS_PRIVILEGE`, so it never claims a repair worked. `format_notification` omits the
`Repair outcome` line when no repair ran and the `Full report` line when the report
could not be saved. When Claude answered, it adds a line starting
`Claude analysis (unverified, derived from local logs):`.

**Note what is absent: `probe_results` and `log_excerpts`.** Those stay in the on-disk
report, where they are unredacted by design. The notification is a pointer to the
artifact, not a copy of it, and `sensitive_strings` is applied to this text before it
is sent.

### `StateMachine` — the whole pipeline, offline

**Purpose.** Drive detect → classify → ladder → recheck → escalate → report with every
side effect faked. No network, no subprocess, no API call.

**When to use it.** Understanding the order of operations, or reproducing a report
shape without waiting for a real outage.

```bash
python3 -c "
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.report import render_markdown

probe = {'external_reachable': True, 'dns_ok': False, 'domain_results': {'api.anthropic.com': False}}
machine = StateMachine(
    prober=lambda: probe,
    repair_executor=lambda step, classification=None: 'simulated',
    escalator=lambda bundle: {'error': 'skipped in demo'},
    log_watcher=lambda: ['mDNSResponder: query for api.anthropic.com timed out'],
    failure_threshold=2, success_threshold=2, sensitive_strings=[],
)
print('tick 1 report:', machine.tick())
report = machine.tick()
print('tick 2 flap state:', machine.flap_gate.state)
print(render_markdown(report)[:200])
"
```

```
tick 1 report: None
tick 2 flap state: incident
# Network/DNS Incident Report

**Started:** 2026-09-14T16:24:12.722104+00:00
**Duration:** 0s
**Resolved:** False

## Classification
dns

## Summary
DNS-layer incident detected at 2026-09-14T16:24:12.
```

The state machine calls `repair_executor(step, classification)`. A one-argument fake
raises `TypeError` there, and every step then reports `failed: step raised TypeError`
rather than crashing the tick.

**Tick 1 returns `None` on a failing probe, and that is the anti-flap gate working.**
A report fires only on the healthy→incident edge, after `failure_threshold` consecutive
failures. That is also why there is exactly one notification per incident, with no
rate limiter anywhere: the gate already provides it.

---

### `service_order` + `interface_probe` — failover dry run (read-only)

**Purpose.** Answer the two questions the failover decision rests on, without
changing anything: does the configured service name exist, and does the backup
interface actually carry traffic right now?

**When to use it.** Before turning `failover_enabled` on, and any time a switch did
not happen and you want to know which brake held.

```bash
python3 -c "
from netdnsmonitor.failover import default_run
from netdnsmonitor.service_order import parse_service_order, promote
from netdnsmonitor.interface_probe import make_interface_prober

services = parse_service_order(default_run(['networksetup','-listnetworkserviceorder']).stdout)
for s in services:
    print(f'{s.name!r:32} device={s.device} enabled={s.enabled}')

probe = make_interface_prober([('1.1.1.1',443),('8.8.8.8',443)], timeout=2.0)
for s in services:
    print(f'{s.name!r:32} reachable={probe(s.device)}')

print('order after a failover to Wi-Fi:', promote(services, 'Wi-Fi'))
"
```

`reachable=None` means **not probed** — the interface is absent (an unplugged USB
adapter disappears entirely). That is not the same as `False`, and the policy will not
switch onto, or back to, an interface it could not ask.

### Failover live check — **this one mutates system network config**

Everything above is read-only. This is not. The offline suite covers the parser, the
policy, the brakes and the persistence, and `IP_BOUND_IF` probing was confirmed by
hand — but the privileged `networksetup -ordernetworkservices` write has **not** been
executed against a real machine. Until someone runs this, treat "the switch works" as
unverified.

**The intended way is the button**, not the shell. Set both service names, leave
`failover_enabled: false` (manual-only mode), start the app, and click
**Switch to backup now**. That runs the same guarded path the automatic switch does —
permutation guard, a re-list right before the write, then read-back verification — and
the notification tells you exactly
which of the outcomes below you got. Click **Switch back to preferred now** to undo.

Do it when the wired adapters have **no link** (unplugged) for a first try: with only
Wi-Fi active, reordering changes the stored order but not the active route, so the
blast radius is close to zero.

The by-hand equivalent, if you want to watch it without the app:

```bash
# 1. Record the current order. Keep this output -- it is your undo.
networksetup -listnetworkserviceorder

# 2. Apply the failover order by hand. Every service name must be present,
#    including the disabled (*) ones, quoted exactly.
networksetup -ordernetworkservices "Wi-Fi" "AX88179B" "USB 10/100/1000 LAN" \
  "USB 10/100/1G/2.5G LAN" "M3100" "Thunderbolt Bridge" "iPhone USB"

# 3. Confirm it landed. networksetup can exit 0 and do nothing, which is why
#    the app reads the order back rather than trusting the exit code.
networksetup -listnetworkserviceorder

# 4. Restore your original order from step 1.
```

What each outcome means. On the machine this was written for the first row is the
likely one: `scselect -n <current-set>` — a deferred no-op selecting the location that
was already active — wrote to root-owned
`/Library/Preferences/SystemConfiguration/preferences.plist` (mtime moved, exit 0) from
a non-root admin account with no password prompt. That is the same
`system.services.systemconfiguration.network` authorization `networksetup` needs, so
the right is satisfiable here without prompting. It is a strong prior, not proof:
`scselect` and `networksetup` are different binaries, and `-n` defers the apply.

| Result | Meaning |
|---|---|
| order changed, no prompt | the app's switch will work silently — the intended case |
| a password prompt appeared | not unattended. UNVERIFIED in the app: its `networksetup` calls run with a 5s timeout (`failover.default_run`), so an unanswered prompt should end as `failed:` after 5s |
| `You must be running as root` | the app reports `NEEDS_PRIVILEGE` and changes nothing |
| exit 0, order unchanged | the app reports `failed: ... order is unchanged` |

**Do not** run step 2 with a service name omitted. `-ordernetworkservices` rewrites the
order to exactly the list it is given; a missing name removes that service. The app
builds this command only in `failover.apply_service_order`. That function refuses any
list that `service_order.is_order_intact` rejects (not a permutation of the current
order), and re-lists the order right before the write so a service added during the
check is not dropped — by hand, you are the guard.

---

## Mac App Store build — `scripts/appstore/`

`docs/APP_STORE_SUBMISSION.md` is the authoritative guide: Apple setup, entitlements,
metadata, and what the store build cannot do. This section lists the entry points only.
All of them need macOS. The build also needs Xcode and a virtualenv with `py2app`:

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -c constraints.txt
.venv/bin/pip install py2app -c constraints.txt
```

### `build_appstore.py` — build, sign and package

**Purpose.** Build the bundle with py2app, then do what py2app cannot: rebuild the
launcher stubs against the installed SDK, remove the string `itms-services` from the
bundled standard library, refuse links to libraries outside the bundle or the OS, set
`LSMinimumSystemVersion` from the bundled binaries, strip extended attributes, sign
inside-out, and verify the signature.

**When to use it.** `adhoc` after any change that adds a subprocess or file access, to
run that change inside the App Sandbox without an Apple account. `release` only to
produce a package for upload.

**When *not* to use it.** To run the direct-download build; that is `scripts/start.sh`.
Each run deletes `build/appstore/<mode>/` first. `release` has never run with real
certificates.

| Mode | Signs with | Output | Needs |
|---|---|---|---|
| `adhoc` | the ad-hoc identity `-`, with the real sandbox entitlements | `build/appstore/adhoc/dist/Net-DNS-Monitor.app` | Xcode |
| `release` | your Apple Distribution identity, with the provisioning profile embedded | `build/appstore/release/Net-DNS-Monitor-<version>-<build>.pkg` | certificates, profile, `--privacy-policy-url` |

Options for both modes: `--bundle-id` (default `com.net-dns-monitor.app`), `--version`
(default `1.0`), `--build-number` (default `1`), `--copyright`,
`--declare-exempt-encryption`, `--privacy-policy-url`, and `--icon` (a designed `.icns`;
without it the `make_icon.py` placeholder is used, and a `release` run says so in a
warning). `adhoc` adds `--with-probe`.
`release` requires `--team-id`, `--app-identity`, `--installer-identity` and
`--profile`. The full `release` command is in `docs/APP_STORE_SUBMISSION.md` §4.2.

```bash
.venv/bin/python scripts/appstore/build_appstore.py adhoc --with-probe
```

The build stops if a `release` run has no `https://` privacy policy URL or the URL still
holds a placeholder, if the profile belongs to a different app ID, if a `release` bundle
contains the probe, if `itms-services` survives anywhere, if any binary links a
library outside the bundle, `/System/Library/` or `/usr/lib/`, if the bundle's
`Info.plist` lacks `CFBundleIdentifier`, either version string,
`LSApplicationCategoryType`, `LSMinimumSystemVersion` or
`NSLocalNetworkUsageDescription`, or if `--icon` names a file that is not `.icns` or
lacks the 512x512 elements (`ic09`, `ic10`).

### `make_icon.py` — the app icon

**Purpose.** Draw the app icon with AppKit (the macOS icon grid, a teal-to-navy body,
a wireframe globe, a heartbeat trace as its equator) and write an `.icns` with every
size App Store Connect needs, including 512x512 and 512x512@2x. `build_appstore.py`
runs it for every build; run it alone to look at the icon. The drawing helpers it
shares with the two screenshot scripts live in `appkit_draw.py` beside it.

**When *not* to use it.** For a hand-made icon: ship that through
`build_appstore.py --icon`, which checks it for the two 512 sizes.

```bash
.venv/bin/python scripts/appstore/make_icon.py /tmp/AppIcon.icns
.venv/bin/python scripts/appstore/make_icon.py /tmp/preview.png   # one 1024px render, to look at
```

It prints the output path. With any other argument count, or a name that ends in
neither `.icns` nor `.png`, it prints its usage and exits 2.

### `shoot_screenshots.py` — render the app's own windows

**Purpose.** Run the app from source as the store edition (`NETDNS_DISTRIBUTION=appstore`)
and render the dashboard, the dashboard after "Run full diagnosis" and the Claude
permission dialog to PNG, in-process, so no screen-recording permission is needed.
The run is isolated under `OUT_DIR`: a config derived from `config.example.yaml` with
every file the app writes moved to `OUT_DIR/app-data`, Slack, e-mail and peer discovery
off, an empty credential store, its own consent file and the drawn `AppIcon.icns`. It refuses an
`OUT_DIR` under the app's own data directories. Each phase waits for the app's own
signal (first ping, the diagnosis worker finishing, the dialog appearing) with a
deadline, and a watchdog ends the process after 180 s.

**When *not* to use it.** From a script or an agent expecting completion: it starts the
GUI app and needs a GUI session. On an unhealthy network: it stops before the diagnosis,
whose capture would show an incident rather than the healthy state.

```bash
.venv/bin/python scripts/appstore/shoot_screenshots.py build/appstore/screenshots/raw
```

Prints each capture's name and pixel size, then `done`; exit 1 with the missing names on
stderr if any of the three files is not there at the end.

### `compose_screenshots.py` — compose for App Store Connect

**Purpose.** Place every PNG in `IN_DIR` on a 2880x1800 brand-gradient background with a
drop shadow, framed by its point size (so a 1x and a Retina capture of the same window
come out alike) and never upscaled past Retina size, and write it to `OUT_DIR` as a PNG
without an alpha channel, which is what the store requires.

```bash
.venv/bin/python scripts/appstore/compose_screenshots.py build/appstore/screenshots/raw build/appstore/screenshots
```

A source that is not an image is reported and skipped; the exit status is 1 if any
was, or if `IN_DIR` holds no PNG at all.

### `sandbox_probe` — what works inside the sandbox

**Purpose.** Measure, from inside the App Sandbox, which of the app's operations work:
a container write, reading the real `~/.config` file, a TCP connect, `getaddrinfo`, a
UDP DNS query, an HTTPS request, an interface-bound connect, a UDP bind, a Keychain
round trip, and a set of read-only commands (`ping`, `networksetup
-listnetworkserviceorder`, `scutil`, `netstat`, `ifconfig`, `route`, `log show`).

**When to use it.** After `build_appstore.py adhoc --with-probe`, and after any change
that adds a subprocess or file access. Update the table in
`docs/APP_STORE_SUBMISSION.md` §1 from its output.

**When *not* to use it.** Outside the ad-hoc bundle. The sandbox applies from the
bundle executable's entitlements, so `scripts/appstore/sandbox_probe.py` run with plain
Python is not sandboxed and says nothing about the store build. The build refuses to
package a `release` bundle that contains the probe.

It changes no network setting. It adds one Keychain item and deletes it again, and
writes `sandbox-probe.json` to `~/Library/Application Support/net-dns-monitor/`, which
inside the sandbox is the container.

```bash
build/appstore/adhoc/dist/Net-DNS-Monitor.app/Contents/MacOS/sandbox_probe
```

It prints JSON with an `environment` object (`sandboxed`, `distribution`, `home`,
`python`) and a `checks` object. A check that raised records `"ok": false` and the
exception class name.

---

## Tests

```bash
python3 -m pytest -q            # 2150 passed
python3 -m pytest -v            # per-test names
python3 -m pytest tests/test_domain_learner.py -q
```

`pytest.ini` sets `testpaths = tests`, so a bare `python3 -m pytest` from the root is
the whole suite.

The coordinator regenerates this per-file distribution and its total with the command
in `docs/TESTING.md`. Do not edit the numbers by hand.

| Tests | File |
|---|---|
| 244 | `test_config.py` |
| 109 | `test_failover.py` |
| 101 | `test_settings_window.py` |
| 75 | `test_privileges.py` |
| 61 | `test_status.py` |
| 60 | `test_cli_console.py` |
| 62 | `test_app_appstore_wiring.py` |
| 57 | `test_dashboard.py` |
| 54 | `test_console.py` |
| 53 | `test_app_dashboard_wiring.py` |
| 52 | `test_peer_net.py` |
| 51 | `test_system_log.py` |
| 47 | `test_peers.py` |
| 42 | `test_cli.py` |
| 41 | `test_app_failover_wiring.py` |
| 41 | `test_domain_learner.py` |
| 40 | `test_repair_executor.py` |
| 40 | `test_router.py` |
| 37 | `test_localize.py` |
| 37 | `test_router_window.py` |
| 35 | `test_app_log_wiring.py` |
| 33 | `test_appstore_build.py` |
| 33 | `test_throughput.py` |
| 31 | `test_forensic_log.py` |
| 29 | `test_failover_policy.py` |
| 26 | `test_graphs.py` |
| 26 | `test_net_stats.py` |
| 26 | `test_notifications.py` |
| 25 | `test_app_router_wiring.py` |
| 25 | `test_history.py` |
| 26 | `test_ping.py` |
| 22 | `test_ping_monitor.py` |
| 21 | `test_app_privilege_wiring.py` |
| 21 | `test_state_machine.py` |
| 20 | `test_appstore_screenshots.py` |
| 20 | `test_service_order.py` |
| 19 | `test_app_settings_wiring.py` |
| 18 | `test_app_peer_wiring.py` |
| 18 | `test_mini_window.py` |
| 17 | `test_anthropic_escalator.py` |
| 17 | `test_dock_icon.py` |
| 17 | `test_stall_log.py` |
| 17 | `test_alert.py` |
| 22 | `test_app_ping_wiring.py` |
| 16 | `test_indexer_scripts.py` |
| 16 | `test_interface_probe.py` |
| 16 | `test_resolution_prober.py` |
| 15 | `test_console_window.py` |
| 15 | `test_escalation.py` |
| 15 | `test_router_scripts.py` |
| 14 | `test_app_notification_wiring.py` |
| 16 | `test_credentials.py` |
| 13 | `test_app_console_wiring.py` |
| 13 | `test_log_watcher.py` |
| 13 | `test_prober.py` |
| 12 | `test_flap_gate.py` |
| 12 | `test_query_log.py` |
| 14 | `test_dns_query.py` |
| 10 | `test_ai_consent.py` |
| 10 | `test_distribution.py` |
| 10 | `test_ladder.py` |
| 10 | `test_report.py` |
| 9 | `test_app_status_wiring.py` |
| 8 | `test_report_storage.py` |
| 7 | `test_resolution_log.py` |
| 7 | `test_router_configs.py` |
| 6 | `test_classifier.py` |
| 3 | `test_app_resolution_wiring.py` |
| 2 | `test_app_report_storage_wiring.py` |
| **2150** | **total** |

**What the suite does not cover.** `prober.default_resolve` and `prober.default_connect` are never
exercised against a real socket — every prober test injects `resolve_fn`/`connect_fn`,
which is what keeps the suite offline and fast, and also means a change to the real
resolver path is only caught by the one-shot invocations above. The `rumps` run loop
is likewise untested; `tick()` and the builder functions are covered with fakes, the
event loop is not. Loading a menu-bar app cannot be automated, so it is verified by
hand.

---

## Reports

```bash
ls -t ~/Library/Application\ Support/net-dns-monitor/reports/ | head
```

Every incident writes a timestamped `.json` (tooling) and `.md` (hand to IT) pair.
Each is self-contained: classification, probe results, log excerpts, every ladder step
and its outcome, the repair outcome, the recheck result, and the Claude analysis if
one happened. **The report is written whether or not escalation and notification
succeed** — that ordering is the point, since both of those need the network that is
currently broken.

---

## Reading the output correctly

The tools are honest; the risk is in what a reader concludes. Five things that
constrain everything above.

**1. "Resolved" means the recheck passed, not that this app fixed it.** Without the
sudoers grant, the one repair that runs is a partial DNS-cache flush. The notification
says `Healthy on recheck`, not "resolved by local repair", for the same reason. If a
transient outage ended on its own between
the probe and the recheck, the report says resolved — correctly, and with no claim of
credit.

**2. Escalation and notification cannot work during a full outage.** Both need to
reach the network. They help only for *partial* degradation, which is why the on-disk
report is built unconditionally and why `ANTHROPIC_API_KEY` being unset is a no-op
rather than an error.

**3. There is no recovery notification.** `tick()` returns a report only on the
healthy→incident edge, so incident→healthy is silent by construction. The menu bar
icon is the recovery signal.

**4. Read the "Log Excerpts" section before trusting it, and treat an empty
learned-domain list as ambiguous.** An empty section means `log show` ran and no line
matched. If `log show` failed or timed out, the section holds one line starting
`[net-dns-monitor] no log evidence:` instead. See the `log_watcher` timing table — at
the default `5m` a timeout is not a real risk; raise `log_lookback` and it becomes one.
The learner's `[]` is ambiguous for an independent reason: macOS masks hostnames in the
log by default, so the names are unreadable rather than absent.

**4a. Reports are large, and "hand the `.md` to IT" needs that caveat.** Real reports on
this machine run **282 KB to 3.8 MB** of Markdown, because `log_excerpts` carries every
error-like line from the lookback window and the filter matches Wi-Fi signal-quality
chatter. The part a human reads — header, classification, ladder steps, repair outcomes
— is the first ~25 lines; the rest is raw evidence. Send the top of the file and attach
the whole thing.

```bash
du -h ~/Library/Application\ Support/net-dns-monitor/reports/*.md | sort -h | tail -3
```

**5. Without the grant, two of the three ladder repairs do nothing at all.**
`renew_dhcp_lease` returns `NEEDS_PRIVILEGE` until the sudoers grant in
`privileges.py` is installed, and that grant has never been exercised live.
`toggle_network_service` returns `NOT_AUTOMATED` whatever is granted. A ladder that ran
to completion is not a machine that was repaired.

**No live order, no live claim.** Where this repo is unverified it says so — see
"Honest scope" in `README.md`.
