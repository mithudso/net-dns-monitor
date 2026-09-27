# Architecture

## System context

`net-dns-monitor` is a single-process macOS menu bar app. It has no server
component and no database. Everything runs inside one `rumps` process on the
user's machine, polling on timers. The process reaches outside the machine only
in these ways:

- It probes the configured targets and domains.
- It exchanges UDP messages with other copies of itself on the LAN
  (`peer_net.py`).
- If configured, it calls Anthropic, posts to Slack and sends email.

Two entry points share the same modules. `python3 -m netdnsmonitor.app` is the
menu bar app. `python3 -m netdnsmonitor.cli` is the `netdns` command line.
`docs/SCRIPTS.md` documents both.

## Module map — the incident core

This map follows the actual imports (`grep -n '^from netdnsmonitor'
netdnsmonitor/*.py`). An arrow `──►` means "imports". `state_machine.py` does
not import the modules in the `build_state_machine()` box: `app.py` builds them
and passes them into `StateMachine.__init__` as callables.

```
 app.py  (rumps shell: menu, windows, six recurring timers and a one-shot launch timer)
   │
   │  distribution.detect() -> Capabilities, then
   │  build_state_machine() builds and injects:
   │  ┌────────────────────────────────────────────────────────────────────────
   │  │ prober           prober.py, fed its domain list by domain_learner.py
   │  │                  domain_learner.py ──► log_watcher.py, report_storage.py
   │  │ log_watcher      log_watcher.py (`/usr/bin/log show`, error-like lines)
   │  │                  or a one-line "unavailable" watcher (store build)
   │  │ repair_executor  repair_executor.py ──► dns_query.py, privileges.py,
   │  │                                         ladder.py
   │  │                  failover_fn = NetworkFailover.attempt_failover
   │  │                                (failover.py, built by build_failover)
   │  │ escalator        build_escalator(): anthropic_escalator.py with the key
   │  │                  from credentials.CredentialStore; wrapped by
   │  │                  ai_consent.gate_escalator in the store build
   │  └────────────────────────────────────────────────────────────────────────
   │
   │  app.tick() on the poll_interval_seconds timer
   ▼
 state_machine.py ──► classifier.py
                  ──► flap_gate.py
                  ──► ladder.py ──► classifier.py
                  ──► escalation.py        (should_escalate, redact)
                  ──► report.py ──► classifier.py
   │
   │  returns a report only on the healthy -> incident edge
   ▼
 app.py then uses:
   report_storage.py ──► report.py         writes a timestamped .json + .md
   escalation.redact, notifications.py     Slack and email, sent on a worker thread
   forensic_log.py ──► report_storage.py   folds the incident into the open episode
   status.py                               menu bar title from the live gate state
```

`failover.py` imports `failover_policy.py`, `service_order.py`,
`interface_probe.py`, `throughput.py` and `report_storage.py`. `throughput.py`
imports `interface_probe.py`.

## Data flow — one incident

1. The `rumps` timer calls `app.tick()`, which calls `state_machine.tick()`.
2. `tick()` calls the injected `prober()` for a reachability and DNS snapshot.
3. `classifier.classify()` turns that into `healthy`, `network`, `dns` or
   `unclassified`. A `None` in either load-bearing field gives `unclassified`.
4. `flap_gate.FlapGate` debounces. It declares an incident only after
   `failure_threshold` consecutive non-healthy ticks. It clears the incident only
   after `success_threshold` consecutive healthy ticks. An `unclassified` tick
   counts as non-healthy.
5. On the `healthy -> incident` edge, `state_machine` takes `StateMachine.lock`.
   It runs `ladder.ladder_for(classification, failover_classifications)` through
   the injected `repair_executor`. `unclassified` has no ladder.
6. It re-probes (the recheck).
7. `escalation.should_escalate()` decides whether to call the escalator. If it
   does, `escalation.redact()` strips `sensitive_strings` from the bundle,
   dictionary keys included. The bundle carries at most 200 log lines, each cut
   to 300 characters. The on-disk report keeps every line.
8. Every injected call in steps 5 to 7 fails as data. A raising step returns
   `failed: step raised <ClassName>`. A raising recheck reads as `unclassified`.
   A raising escalator returns `{"error": ...}`. The report is always built.
9. `report.build_report()` assembles the report. `app._tick()` records the
   classification first and then saves the report through `report_storage`. If
   the save raises, the alert and the forensic record still go out.
10. `app._tick()` redacts the notification text on the run loop. A worker thread
    sends the finished string.
11. On a tick that returns no report, `app._tick()` asks the failover for a
    failback. `status.py` then repaints the title.

## Key design decisions

- **All external effects are injected callables.** `prober`, `repair_executor`,
  `escalator` and `log_watcher` are passed into `StateMachine.__init__`. The
  decision modules import no `socket` and no `subprocess`. This makes every
  decision path unit-testable with fakes. See `docs/TESTING.md`.
- **Escalation fires only after the loop closes**, never on first detection.
  The ladder and the recheck run first. See the docstring of `state_machine.py`.
- **A privileged repair is either attempted or reported as not attempted.** It is
  never silently skipped. `flush_dns_cache` reports `partial` when the
  `mDNSResponder` HUP fails. `renew_dhcp_lease` runs only under the sudoers grant
  in `privileges.py` and reports `NEEDS_PRIVILEGE` without it.
  `toggle_network_service` returns `NOT_AUTOMATED`. `failover.py` attempts the
  switch and reads the service order back before it claims anything.
- **One function writes the network service order.**
  `failover.apply_service_order` builds the `networksetup -ordernetworkservices`
  argv. It refuses any order that `service_order.is_order_intact` rejects. It
  re-lists the order right before the write and reads the order back afterwards.
  The CLI calls the same function.
- **No auto-detected targets, with one bounded exception.** `domains` and
  `internal_targets` are explicit, user-supplied config (`config.yaml`, which is
  the shipped default rather than a sample). The app never reads browser history
  or other app data. `domain_learner.py` learns only from *failed* resolutions in
  the unified log. Every learned name is validated, capped, and pruned once it is
  shown to be dead.

## ADRs (informal)

| Decision | Status |
|---|---|
| `rumps` instead of a native Swift menu bar app | Current |
| Stub every privileged repair; an `SMAppService` helper is follow-up work | **Superseded** by the narrow sudoers grant |
| Narrow sudoers grant for the two repairs that need root | Current |
| Failover builders live in `failover.py`, not `app.py` | Current |
| Mac App Store edition gated by `distribution.py` in the same codebase | Current |

- **Why `rumps`?** It is fast to build and test in Python, it matches the rest of
  the codebase, and a menu bar utility needs little of a full app bundle.
- **Why stub privileged repairs? (superseded)** The MVP stubbed every repair that
  needed root and named an `SMAppService` privileged helper as the follow-up.
  That helper does not exist. The sudoers grant replaced the stubs for
  `flush_dns_cache` and `renew_dhcp_lease`. `toggle_network_service` stays
  unautomated for a different reason: down and up cannot be one command.
- **Why a narrow sudoers grant?** After one macOS admin dialog, `privileges.py`
  writes `/etc/sudoers.d/net-dns-monitor`. The file lists two complete command
  lines: `/usr/bin/killall -HUP mDNSResponder`, and
  `/usr/sbin/ipconfig set <interface> DHCP` for each interface present at grant
  time. It has no wildcard and no shell. `visudo -cf` validates the file before
  it is moved into place. The Revoke button deletes it. The grant has never been
  exercised live; see `docs/known-issues.md`.
- **Why failover builders in `failover.py`?** `build_failover` and the
  `failover_*` config helpers moved out of `app.py`. `cli.py` can then build the
  same failover without importing `rumps` and AppKit. `app.py` re-exports the
  names, so imports from `netdnsmonitor.app` still work.
- **Why one codebase for the Mac App Store edition?** See "Distribution" below.

## Beyond the core

Everything below hangs off the same `app.py` shell. This section is a map, not a
second diagram. Each module's own docstring is the authority on why it is shaped
the way it is.

**Surfaces.** `dashboard.py` (imports `graphs.py`) is the main window: stats,
graphs, a troubleshooting button grid and a system-log pane. `mini_window.py` is
its collapsed form. `settings_window.py` (imports `config.py`) edits
`config.yaml`. `dock_icon.py` draws the Dock tile. `graphs.py` renders the
history offscreen so it stays pixel-testable.

**Heartbeat and alert.** `ping.py` runs one ICMP ping. `ping_monitor.py` decides
from the ping stream whether the network is down and whether an alert fires now;
it does no I/O. `net_stats.py` reads throughput from the kernel's per-interface
byte counters. `alert.py` bounces the Dock tile and posts the "network failed"
notification. This path is separate from the incident core: it runs on
`ping_interval_seconds` and does not pass through the anti-flap gate.

**The console.** `console.py` holds the decisions of an arbitrary-shell console:
built-ins, `cd`, and a runner guarded by a timeout, a process-group kill, a
`/dev/null` stdin and an output cap. `console_window.py` (imports `console.py`)
is its AppKit shell and holds no decisions. It opens from the menu bar and from a
dashboard button. Both go through the one controller at `App.console`, so the two
share a working directory and a history. `app.py` registers
`console.kill_running` to run before quit.

**The CLI.** `cli.py` is the `netdns` entry point. `commands.py` is its catalogue
of diagnostic commands, each marked for whether it mutates. `cli_console.py`
(imports `cli.py` and `commands.py`) is the REPL behind `netdns console`. This is
a terminal surface and is *not* the GUI console: it offers a vetted catalogue,
where the GUI console offers a shell. `cli.py` does not import `rumps`.

**Failover.** `failover.py` switches to a backup network service and back, and
builds the failover from config. `failover_policy.py` decides whether a switch is
allowed (cooldowns, rate caps, which classifications qualify).
`service_order.py` parses the service order and checks that a new order is a
permutation of the current one. `interface_probe.py` measures a specific
interface with `IP_BOUND_IF`. `throughput.py` ranks candidate backups.

**Notifications.** `notifications.py` builds the Slack and email channels. Each
channel is opt-in by its credential being present. `app.build_notifier` reads the
credentials through `CredentialStore.as_env()`, so a value comes from the
environment or, failing that, the Keychain. `app.py` redacts on the run loop and
sends on a worker, because a timer callback must not wait on network I/O while the
network is known to be broken.

**Evidence and lifecycle.** `forensic_log.py` records down/up episodes.
`history.py` keeps the rolling sample window behind the graphs.
`resolution_prober.py`, `resolution_log.py` and `stall_log.py` run and record the
stalled-domain batch. `domain_learner.py` learns probe targets from the unified
log and prunes dead ones. `system_log.py` and `query_log.py` read macOS's own
logs; `config.py` imports `system_log.py` for its default noise patterns.
`peers.py` and `peer_net.py` (imports `peers.py`) find other copies of the
monitor on the LAN. `localize.py` compares their view with this machine's to say
where a fault is. `privileges.py` owns the sudoers grant and the `osascript`
admin call.

## Router

The repository holds two router implementations. They conflict: both want UDP
port 67, and both set `net.inet.ip.forwarding`. The owner keeps both (decided
2026-09-14). They must not run at the same time, which is why `Router` refuses to
start while the `router/` LaunchDaemon is installed.

| | App router mode | `router/` stack |
|---|---|---|
| Code | `netdnsmonitor/router.py`, `netdnsmonitor/router_window.py` | `router/scripts/`, `dnsmasq/`, `unbound/` |
| DHCP and DNS | macOS `bootpd` | `dnsmasq` and `unbound` |
| LAN | `192.168.10.1/24` by default (`router.DEFAULTS`) | `192.168.4.0/24` |
| NAT | pf anchor `com.apple/netdnsmonitor_nat` | pf anchor `com.apple/custom_nat` |
| Installed as | nothing persistent; started from the menu | LaunchDaemon `com.custom.router.nat` |
| Documentation | module docstrings | `router/docs/ROUTER.md` |

**`router.py`** (imports `privileges.py`) validates every interface name and
address before any of it reaches the root script. It builds the script inline
and runs it through `privileges._osascript_admin`, so nothing is staged in
`/tmp`. `Router.start()` and `Router.stop()` return an outcome string that starts
with `ok:`, `cancelled:`, `refused:` or `failed:`. Both read the result back
before they report `ok:`. `stop` flushes only its own anchor and never disables
pf. Both refuse while `/Library/LaunchDaemons/com.custom.router.nat.plist`
exists.

**`app.py`** builds a `Router` only when `router_enabled` is true and the build
includes the router (not the Mac App Store edition). It never starts the router at
launch. The Router menu's Start and Stop run on a worker thread,
because they wait on the macOS admin dialog.

**`router_window.py`** is the Router Management Console window. It imports
`router.py`, and imports `settings_window.py`, `escalation.py` and
`anthropic_escalator.py` lazily. Its decisions are plain functions. Every
subprocess, the Anthropic client and the hop back to the main thread are
injected. The AI config check redacts its prompt with `escalation.redact` and
calls Claude through `anthropic_escalator`. Save writes only the router keys,
through `settings_window.save_config`.

The test suite never executes the `router/` shell scripts.
`tests/test_router_scripts.py` and `tests/test_router_configs.py` check them as
text.

## Distribution — Mac App Store edition

`docs/APP_STORE_SUBMISSION.md` is the authoritative document for the store build.
This section only places the modules.

- **`distribution.py`** reads the environment and returns `Capabilities`.
  `APP_SANDBOX_CONTAINER_ID` (set by the sandbox) or
  `NETDNS_DISTRIBUTION=appstore` selects the App Store edition. That edition
  switches off the shell console, the privileged repairs, the service-order
  write, the unified log readers, the router and the LaunchAgent login item. A
  switched-off feature reports text starting `UNAVAILABLE_IN_APP_STORE_BUILD`,
  never `ok` and never a silent no-op. The module imports nothing from the
  package.
- **`credentials.py`** looks up `ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL` and
  `SMTP_PASSWORD` in the environment first and in the Keychain second, in both
  editions. A sandboxed app launched by LaunchServices has no shell environment.
  Errors carry the OSStatus number only.
- **`credentials_prompt.py`** holds the modal dialogs behind the Credentials and
  Claude-permission menu items. Monitoring pauses while one is open, because a
  modal session does not service the run loop mode the `rumps` timers use.
- **`ai_consent.py`** (imports `report_storage.py`) records explicit, versioned
  permission before any incident data goes to Anthropic. The record lives in
  `~/Library/Application Support/net-dns-monitor/ai-consent.json`, not in
  `config.yaml`.
- **`scripts/appstore/`** holds `build_appstore.py` (builds, fixes and signs the
  bundle), `make_icon.py` (draws a placeholder icon) and `sandbox_probe.py`
  (measures sandbox behaviour from inside the sandbox; imports `distribution.py`
  and `credentials.py`). The entitlements live in `packaging/appstore/`.

`app.py` imports all four modules. `NetDnsMonitorApp.__init__` calls
`distribution.detect()` once, unless a `capabilities` argument is passed, and
builds the state machine and the menu from the result:

- `build_state_machine` swaps in the one-line unavailable log watcher, turns off
  domain learning, passes `unavailable_fn` to `make_repair_executor`, and makes
  the failover step report the service-order write as unavailable.
- `build_escalator` takes the Anthropic key from the `CredentialStore`. In the
  store build it wraps the escalator in `ai_consent.gate_escalator`, which sends
  nothing until the user grants permission in the app.
- The menu leaves out the items for switched-off features rather than greying
  them out. Every build has a Credentials submenu. The store build adds the
  Claude-permission items and a Privacy Policy item.
