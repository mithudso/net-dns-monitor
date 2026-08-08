# Scripts

Every runnable entry point in this repo: what it is for, when to reach for it, **when
not to**, its options, a real invocation, and the output you should expect.

`README.md` is the product description; this page is the operator's manual — the
commands you actually type, including the one-shot module invocations that are the
only way to exercise a piece of this app without a menu bar.

Every example below was executed against this repo on macOS 25.4 with Python 3.13.1.
Where output is shown it is real, trimmed for length, never illustrative.

## The one rule

**This app diagnoses far more than it fixes, and the report is the deliverable.** Of
the eight ladder steps present by default, exactly one mutates anything
(`flush_dns_cache`), and even that one only half-works unprivileged —
`dscacheutil -flushcache` succeeds, `killall -HUP mDNSResponder` does not, because
signalling a process owned by another user is rejected regardless of the command's own
permissions. It reports `partial`. Two more repairs are `NEEDS_PRIVILEGE` stubs.

Enabling failover adds a ninth step, `switch_to_backup_network`, which is the only one
that rewrites system network configuration. It is off by default and reports
`NEEDS_PRIVILEGE` rather than acting when the administrator right is refused. Read
"Reading the output correctly" at the bottom before concluding this app fixed anything.

One command is a gate rather than an experiment. Run it before trusting the rest:

```bash
python3 -m pytest -q          # 1079 tests; the whole decision surface
```

## Quick reference

| Command | For | Network |
|---|---|---|
| `python3 -m netdnsmonitor.cli <cmd>` | **start here** — the CLI | varies |
| `python3 -m netdnsmonitor.cli interfaces` | every service, live, with reachability | **yes** |
| `python3 -m netdnsmonitor.cli bench` | + measured throughput per interface | **yes** |
| `python3 -m netdnsmonitor.cli console` | interactive diagnostics | **yes** |
| `python3 -m netdnsmonitor.app` | the menu bar app — **blocks forever** | **yes** |
| `python3 -m pytest` | **gate:** the full decision surface, 1079 tests | no |
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

There is no `scripts/` directory: the CLI is the interface, and `app.py` stays a thin
rumps shell over the same tested modules. The one-shot `python3 -c` invocations further
down predate the CLI and are kept because they show which module owns which decision —
but for day-to-day use, reach for `netdnsmonitor.cli`. Everything runs from the repo
root.

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

The same console is available as a window from the menu bar ("Open console…").

---

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt          # rumps 0.4.0, anthropic, PyYAML 6.0.3, pytest

mkdir -p ~/.config/net-dns-monitor
cp config.yaml ~/.config/net-dns-monitor/config.yaml
```

**Optional environment, all three independent.** Each unset feature degrades to a
no-op rather than an error:

```bash
export ANTHROPIC_API_KEY=sk-ant-...                          # LLM escalation
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... # Slack alerts
export SMTP_PASSWORD=...                                      # email auth, if the relay needs it
```

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

Real title output for all three states, taken from `status.build_title`:

```
healthy   None  -> 🟢 Net/DNS: healthy
incident  dns   -> 🔴 Net/DNS: dns issue
incident  None  -> 🔴 Net/DNS: unknown issue
```

**The title is driven by the live flap-gate state, not by the last report.** That is a
fixed bug, not a detail: recovery produces no report, so a title read off "last
report" stayed red forever after the network came back.

**The menu.** Three greyed indicator rows (readouts, not actions), then the controls:

```
Active: Wi-Fi — failover is automatic
○ Preferred: AX88179B (en6) — unreachable
● Backup: Wi-Fi (en0) — reachable
─────────────────────────
Switch to backup now
Switch back to preferred now
Refresh network status
─────────────────────────
Open last report
```

`●` is the side currently carrying traffic. Reachability is tri-state and says
`not probed` for an absent adapter rather than `unreachable`, because an unplugged
cable is not a dead link.

The rows are repainted on startup, after any switch, and on "Refresh network status" —
**not** every tick. A refresh costs a `networksetup` subprocess plus two interface
probes, which is not an every-30-seconds price to pay on the UI thread.

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

**When *not* to use it.** To measure latency. It returns booleans and deliberately
throws away timing.

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
| `flush_dns_cache` | **repair** | `dscacheutil` + `killall -HUP` | **partial** |
| `renew_dhcp_lease` | repair | **nothing — stub** | needs helper |
| `toggle_network_service` | repair | **nothing — stub** | needs helper |
| `switch_to_backup_network` | **repair** | `networksetup -ordernetworkservices` | **needs admin — really attempted** |

### `log_watcher` — what evidence would a report carry?

**Purpose.** Tail `log show` for DNS/network subsystem entries and keep the error-like
lines.

**When to use it.** Before filing a bug about an empty "Log Excerpts" section.

**When *not* to use it — and this one matters.** Do not raise `log_lookback` past the
default `5m` without also raising the watcher's subprocess timeout. The timeout is
hardcoded at 10s and a timeout returns `[]`, which is **indistinguishable from "no
errors found"**. Measured on this machine:

```
5m  -> 424 lines   real 2.25s
15m -> 1619 lines  real 4.97s
30m -> 3942 lines  real 10.15s     <- at the 10s limit; an earlier run returned 0
```

A `30m` lookback is a coin flip that fails *silently*, and the failure mode is a
confident empty report rather than an error.

```bash
python3 -c "
from netdnsmonitor.log_watcher import make_log_watcher
lines = make_log_watcher(lookback='5m')()
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
control: api.anthropic.com | learn interval: 300
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

**When *not* to use it.** As a resolver. It returns a bool from the response `rcode`
and parses no answer records — there is no address in the result.

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
Resolved by local repair: False
Summary: DNS-layer incident detected, unresolved after the ladder ran.
Repair outcome: flush_dns_cache: partial
Full report: /tmp/2026-08-05.md
--- zero channels: []
```

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
    repair_executor=lambda step: 'simulated',
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

**Started:** 2026-08-06T00:39:38.647878+00:00
**Duration:** 0s
**Resolved:** False
```

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
permutation guard, then read-back verification — and the notification tells you exactly
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
| a password prompt appeared | it works, but not unattended; the tick will block |
| `You must be running as root` | the app reports `NEEDS_PRIVILEGE` and changes nothing |
| exit 0, order unchanged | the app reports `failed: ... order is unchanged` |

**Do not** run step 2 with a service name omitted. `-ordernetworkservices` rewrites the
order to exactly the list it is given; a missing name removes that service. The app
guards this with `is_order_intact`, which refuses any list that is not a permutation of
the current one — by hand, you are the guard.

## Tests

```bash
python3 -m pytest -q            # 1079 passed
python3 -m pytest -v            # per-test names
python3 -m pytest tests/test_domain_learner.py -q
```

`pytest.ini` sets `testpaths = tests`, so a bare `python3 -m pytest` from the root is
the whole suite. Current distribution:

| Tests | File |
|---|---|
| 63 | `test_failover.py` |
| 54 | `test_status.py` |
| 53 | `test_privileges.py` |
| 45 | `test_system_log.py` |
| 42 | `test_settings_window.py` |
| 41 | `test_cli_console.py` |
| 38 | `test_dashboard.py` |
| 38 | `test_console.py` |
| 35 | `test_app_log_wiring.py` |
| 33 | `test_app_dashboard_wiring.py` |
| 31 | `test_peer_net.py` |
| 30 | `test_app_failover_wiring.py` |
| 29 | `test_peers.py` |
| 25 | `test_repair_executor.py` |
| 25 | `test_localize.py` |
| 25 | `test_failover_policy.py` |
| 25 | `test_domain_learner.py` |
| 21 | `test_net_stats.py` |
| 20 | `test_throughput.py` |
| 20 | `test_forensic_log.py` |
| 20 | `test_config.py` |
| 19 | `test_ping_monitor.py` |
| 19 | `test_history.py` |
| 17 | `test_service_order.py` |
| 17 | `test_app_privilege_wiring.py` |
| 16 | `test_stall_log.py` |
| 16 | `test_notifications.py` |
| 16 | `test_graphs.py` |
| 16 | `test_app_ping_wiring.py` |
| 15 | `test_dock_icon.py` |
| 15 | `test_app_peer_wiring.py` |
| 14 | `test_alert.py` |
| 13 | `test_resolution_prober.py` |
| 13 | `test_console_window.py` |
| 13 | `test_app_notification_wiring.py` |
| 12 | `test_ping.py` |
| 12 | `test_app_console_wiring.py` |
| 11 | `test_query_log.py` |
| 10 | `test_interface_probe.py` |
| 10 | `test_anthropic_escalator.py` |
| 9 | `test_prober.py` |
| 9 | `test_dns_query.py` |
| 9 | `test_app_status_wiring.py` |
| 8 | `test_log_watcher.py` |
| 8 | `test_ladder.py` |
| 8 | `test_flap_gate.py` |
| 7 | `test_state_machine.py` |
| 7 | `test_report_storage.py` |
| 7 | `test_escalation.py` |
| 6 | `test_resolution_log.py` |
| 6 | `test_classifier.py` |
| 5 | `test_report.py` |
| 3 | `test_app_resolution_wiring.py` |
| **1079** | **total** |

**What the suite does not cover.** `default_resolve` and `default_connect` are never
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

**1. "Resolved" means the recheck passed, not that this app fixed it.** The one real
repair is a partial DNS-cache flush. If a transient outage ended on its own between
the probe and the recheck, the report says resolved — correctly, and with no claim of
credit.

**2. Escalation and notification cannot work during a full outage.** Both need to
reach the network. They help only for *partial* degradation, which is why the on-disk
report is built unconditionally and why `ANTHROPIC_API_KEY` being unset is a no-op
rather than an error.

**3. There is no recovery notification.** `tick()` returns a report only on the
healthy→incident edge, so incident→healthy is silent by construction. The menu bar
icon is the recovery signal.

**4. An empty "Log Excerpts" section is ambiguous, and so is an empty learned-domain
list.** `log show` failing, timing out, or genuinely finding nothing are the same `[]`
to every caller. See the `log_watcher` timing table — at the default `5m` that is not a
real risk; raise `log_lookback` and it becomes one. The learner's `[]` is ambiguous for
a second, independent reason: macOS masks hostnames in the log by default, so the names
are unreadable rather than absent.

**4a. Reports are large, and "hand the `.md` to IT" needs that caveat.** Real reports on
this machine run **282 KB to 3.8 MB** of Markdown, because `log_excerpts` carries every
error-like line from the lookback window and the filter matches Wi-Fi signal-quality
chatter. The part a human reads — header, classification, ladder steps, repair outcomes
— is the first ~25 lines; the rest is raw evidence. Send the top of the file and attach
the whole thing.

```bash
du -h ~/Library/Application\ Support/net-dns-monitor/reports/*.md | sort -h | tail -3
```

**5. Two of the three repairs do nothing at all.** `renew_dhcp_lease` and
`toggle_network_service` return `NEEDS_PRIVILEGE` strings. A sandboxed menu-bar app
does not have those rights; a real fix needs an `SMAppService` privileged helper that
does not exist yet. A ladder that ran to completion is not a machine that was repaired.

**No live order, no live claim.** Where this repo is unverified it says so — see
"Honest scope" in `README.md`.
