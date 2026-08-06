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

The one exception is the optional network-failover step, which is genuinely
attempted rather than stubbed — reordering network services can succeed for an
administrator account without a helper. It is still tagged as needing
privilege, and when the write is refused it reports `NEEDS_PRIVILEGE` and
changes nothing. See "Automatic network failover" below.

## Automatic network failover

Optional, **off by default**. When the preferred network dies, the app can move
the machine onto a backup network by rewriting the macOS network service order,
and move it back when the preferred one recovers.

```yaml
failover_enabled: true
failover_preferred_service: "AX88179B"   # the wired link
failover_backup_service: "Wi-Fi"         # the hotspot
```

Names must match `networksetup -listnetworkserviceorder` exactly; a name that
doesn't match is reported as a failure listing the names that do exist, and
nothing is reordered.

**Menu bar controls.** Three indicator rows show which service is carrying
traffic (`●`) and which is not (`○`), each with its device and whether it can
actually reach anything right now:

```
Active: Wi-Fi — failover is automatic
○ Preferred: AX88179B (en6) — unreachable
● Backup: Wi-Fi (en0) — reachable
Switch to backup now
Switch back to preferred now
Refresh network status
```

The switch buttons skip the policy — a person clicking a button has already
supplied the judgement the rate brakes exist to substitute for — but not the
execution safety: the permutation guard and the read-back verification still
apply, and the result is reported in a notification.

**Three modes**, set by which keys you fill in:

| `failover_enabled` | Both names set | Behaviour |
|---|---|---|
| `false` | no | Off entirely |
| `false` | yes | **Manual only** — buttons work, nothing moves on its own |
| `true` | yes | Automatic, buttons still available |

Manual-only is the way to try this before trusting it unattended.

**The one failure this addresses.** A link that is *up but not carrying
traffic* — it has a cable and an address, so macOS keeps it primary and keeps
routing into a hole. When a cable is simply unplugged the interface disappears
and macOS fails over on its own; this feature correctly does nothing there.

**It verifies the backup before moving.** Reachability is tested *through* the
backup interface specifically, using the `IP_BOUND_IF` socket option, so a
switch only happens when the other side is known to carry traffic. Binding the
source address instead would not work: on Darwin the route lookup follows the
destination, so a socket bound to the Wi-Fi address still leaves via whichever
interface owns the route.

**It is built to be reluctant.** Four brakes must all release before anything
moves: the incident must be a configured trigger (network-layer only by
default), the backup must be independently verified, the cooldown must have
expired, and the hourly switch budget must not be spent. Failback is
asymmetric — it waits for the preferred link to pass several consecutive checks
— so a flapping link cannot drag the machine back and forth. Every refusal
records *why*, and that reason appears in the incident report.

**It restores your exact order.** The service order in place before the first
failover is recorded and restored verbatim, rather than leaving the backup
permanently in second place. The record survives a restart, so an app
relaunched mid-outage can still put you back.

**Privilege, honestly.** Reordering network services needs an administrator
right. Whether that succeeds without a password prompt depends on your account
and on the "Require an administrator password to access system-wide
preferences" setting. If it is refused, the step reports `NEEDS_PRIVILEGE` and
nothing changes. And because `networksetup` can exit 0 without doing anything,
the order is read back and compared after every attempt — a switch is only
reported as `ok` once the new order has been confirmed on disk.

**Not yet verified live.** The decision logic, the parser, the rate brakes and
the persistence are covered by offline tests, and the `IP_BOUND_IF` probing was
confirmed by hand against real interfaces. The privileged
`networksetup -ordernetworkservices` write itself has **not** been executed on a
real machine. Clicking "Switch to backup now" is the way to find out: it runs
the same guarded path the automatic switch does and reports exactly what
happened. Evidence suggests it will work without a password prompt — `scselect
-n` wrote to root-owned `preferences.plist` from a non-root admin account
silently, using the same authorization right — but that is a prior, not proof.

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

To enable notifications (both channels are optional and independent):

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...   # Slack
export SMTP_PASSWORD=...                                        # email, if the relay authenticates
```

Neither secret belongs in `config.yaml` -- for a Slack incoming webhook the
URL *is* the credential, so it stays in the environment and is never echoed
back in an error message. Email also needs `email_recipients` in
`config.yaml`; with an empty recipient list that channel stays inactive.

## Notifications

When an incident is declared and its report is written, a redacted one-block
summary goes to every configured channel: classification, start time,
duration, whether local repair resolved it, the repair outcome, the Claude
analysis if there was one, and the path to the local report. Raw probe results
and log excerpts are deliberately *not* sent -- those are unredacted by design
because the report stays on the machine. Anything in `sensitive_strings` is
stripped on the way out, the same rule that governs LLM escalation.

Honest limits, same shape as the escalation caveat above:

- These channels need working connectivity, so they cannot fire during a
  genuine full outage -- only during partial degradation. The on-disk report
  is written either way.
- Notifications fire on incident *onset* only. Recovery produces no report
  (see `status.py`), so there is no "back to normal" message; the menu bar
  icon is the recovery signal.
- Send timeouts are short (`notify_timeout_seconds`, default 5s) because this
  runs on the UI thread at the moment the network is known to be broken.
- A delivery failure is recorded and swallowed, never raised: a Slack outage
  must not stop the report from being saved.

## Auto-learned domains

`domains` in the config is a floor, not the whole list. Every
`domain_learn_interval_seconds` (default 300) the app scans the unified log for
*failed DNS resolutions* and adds those hostnames to the probe list --
evidence already on the machine that someone tried to reach a name and could
not. That avoids the browser-history route, which would mean reading another
app's data.

**On a stock macOS install this finds nothing, and that is not a bug in the parser.**
macOS masks hostnames in the unified log by default: mDNSResponder's resolver lines
carry `<mask.hash: '...'>` or an opaque token (`BBUpzafn IN A?`) where the queried name
would be, so there is no name to extract. Measured on one machine: 758 error-like
lines, 198 of them explicitly masked, 0 learnable domains. Unmasking
(`sudo log config --mode "private_data:on"`) is a **system-wide privacy change** and is
not recommended lightly. Treat `domains` as the real probe list and this feature as
opportunistic. `docs/SCRIPTS.md` shows how to check what your own log yields.

Two guards keep this from making the monitor worse:

- `dns_ok` is an all()-across-domains signal, so one dead name scraped out of a
  log line would otherwise pin the app in a permanent false incident. A learned
  domain that fails *while the control domain still resolves* is a dead name
  rather than a broken resolver, and is evicted. With the control domain also
  failing, nothing is pruned -- that is the real outage this app exists to
  report. Hand-configured domains and the control domain are never evicted.

  The control domain (`control_domain`, default `api.anthropic.com` -- the host
  LLM escalation already depends on, so a failing control means escalation was
  going to fail too) is what makes that test possible. Learned names are by definition names that *failed*, so
  on the default `domains: []` every probed name is a learned failure and
  "something else resolved" is false by construction; a name known to resolve
  is the anchor that breaks the tie. Setting `control_domain: null` with no
  configured domains disables pruning's anchor.
- Scraped hostnames are validated before use (no IP literals, no
  `in-addr.arpa`/`ip6.arpa` reverse zones, no bare labels, length-capped), and
  the store is capped at `max_learned_domains` so a log flood cannot grow the
  probe list without bound.

- All domain lookups in a tick share **one** deadline
  (`probe_timeout_seconds`, default 2s), resolved on worker threads. Serial
  lookups would make the block additive -- with 20 learned names plus the
  control domain, a resolver outage would freeze the menu bar for ~42s.
- `domain_learn_interval_seconds` is clamped to at least twice
  `poll_interval_seconds`. Scanning every tick re-adds a dead name as fast as
  pruning drops it, so the flap gate's success counter never resets and one
  dead name latches a permanent incident.

Learned domains live in `learned_domains_path` and stay local; only the
redacted summary described above ever leaves the machine. Set
`learn_domains_from_logs: false` to probe exactly the configured list. Setting
`control_domain: null` *and* leaving `domains` empty removes the anchor: with
nothing known-good to compare against, a dead learned name can no longer be
identified as dead and will hold the app in an incident.

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

## Tests

```bash
source .venv/bin/activate
python -m pytest -v
```

`docs/SCRIPTS.md` is the operator's manual for every entry point — including the
one-shot module invocations that exercise the prober, the ladder, the log watcher, the
domain learner and the notification text without starting a menu bar.

All decision logic (classification, anti-flap gating, the troubleshooting
ladder, escalation redaction/gating, the report builder, and the full
state-machine orchestration) is unit tested with injected fakes for every
external effect (network, subprocess, LLM, SMTP, webhook). The `app.py`
menu-bar shell is thin wiring over those tested modules; its `tick()` and
builder functions are covered with fakes, but the rumps run loop itself is
not, since that needs a real macOS event loop.

## Project layout

- `classifier.py` -- network-vs-DNS-vs-healthy-vs-unclassified split
- `flap_gate.py` -- anti-flap consecutive-count debounce
- `ladder.py` -- the offline troubleshooting ladder definition
- `repair_executor.py` -- dispatches ladder steps to real macOS commands
- `dns_query.py` -- raw UDP query against a specific public resolver
- `prober.py` -- TCP-connect reachability + DNS resolution aggregation
- `log_watcher.py` -- `log show` tailing/filtering for DNS/network errors
- `escalation.py` -- redaction + the escalate-or-not gate
- `service_order.py` -- parses/reorders the macOS network service list
- `interface_probe.py` -- reachability forced out of a named interface
- `failover_policy.py` -- the pure switch/don't-switch decision + rate brakes
- `failover.py` -- executes the reorder, verifies it, persists the old order
- `domain_learner.py` -- learns/validates/prunes domains from failed log lookups
- `notifications.py` -- redacted Slack webhook + SMTP email incident alerts
- `anthropic_escalator.py` -- the Claude API call itself
- `report.py` / `report_storage.py` -- incident report schema + persistence
- `status.py` -- menu bar title/icon logic
- `state_machine.py` -- orchestrates all of the above
- `config.py` -- YAML config loading with defaults
- `app.py` -- the rumps menu bar shell
