# CLAUDE.md — net-dns-monitor

Instructions for agents working in this repository. Read before changing code.

## What this is

A macOS menu-bar app that watches network and DNS connectivity, runs an offline
troubleshooting ladder when something breaks, optionally fails over to a backup network,
escalates to Claude when the ladder cannot resolve it, writes an IT-ready incident
report, and alerts Slack/email. Python 3.13, stdlib-first, `rumps` for the menu bar.

**The danger here is a confident wrong diagnosis, not a lost trade.** This app tells a
human what is wrong with their network. A report that misattributes a DNS failure to the
network — or claims a repair worked when it silently did nothing — is worse than no
report, because someone will act on it.

## Non-negotiables

1. **Never claim a repair that did not happen.** `flush_dns_cache` returns `partial` when
   `dscacheutil` succeeds but the `mDNSResponder` HUP fails, because that is what
   happened. `renew_dhcp_lease` returns `NEEDS_PRIVILEGE` and runs nothing unless the
   sudoers grant covers the interface, and `toggle_network_service` always returns
   `NOT_AUTOMATED`. Do not collapse these into "ok" — see `repair_executor.py`. The
   failover switch goes further and reads the service order *back* before claiming
   anything, because `networksetup` can exit 0 without changing a thing; an
   unconfirmable switch is reported `failed:`, never `ok:`.
2. **`None` is not `False`.** In probe results, `None` means *not probed*; `classify`
   maps a `None` in either load-bearing field to `unclassified` rather than guessing. A
   change that makes an unknown look like a healthy or a failed reading is a correctness
   bug, not a simplification. An absent network interface is `None` for the same reason —
   an unplugged cable is not a dead link, and saying so sends someone after the wrong
   fault.
3. **The engine does not touch the network — the injected callable does.** Every side
   effect (probe, subprocess, LLM call, SMTP, webhook) enters as a parameter with a real
   default. That is what makes the whole decision surface testable offline; the test
   suite opens no sockets. Do not import `socket`/`subprocess` into a decision module.
   `failover_policy.py` and `service_order.py` are decision modules and must stay clean.
4. **No secret in a return value, a report, or an error string.** The Slack webhook URL
   *is* a credential, and `urllib`'s exception text can embed the full request URL.
   Credentials (`ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL`, `SMTP_PASSWORD`) come from the
   environment, then the Keychain (`credentials.py`), never `config.yaml`. Error paths
   return a status code, an OSStatus number or an exception *class name* — never the
   exception message from an auth failure.
5. **Nothing may raise out of a tick.** `tick()` is a rumps timer callback. rumps 0.4.0
   catches an exception in a timer or menu callback, so the timer survives. The rest of
   that tick does not run: the title repaint, the gate-recovery note, and on the
   healthy→incident edge the saved report, the alert and the forensic DOWN. The gate
   offers that edge once, so the incident is never reported. `tick()` wraps `_tick()`,
   and the recovery path is wrapped too. Anything called from a tick must fail as data.
6. **Every outbound path is redacted; the on-disk report is not.** `sensitive_strings`
   is applied to the LLM bundle and to the notification text. The report keeps raw probe
   results and log excerpts because it stays on the machine — so never copy report
   internals into a notification or a prompt.
7. **All domain lookups in a tick share one deadline.** Sequential per-domain timeouts
   made the UI block additive (~42s with a full learned list). And note
   `socket.setdefaulttimeout()` does **not** bound `socket.getaddrinfo` — that timeout
   was inert until the lookup moved onto a worker thread. The same rule governs the
   failover path: a healthy tick that has never failed over must spend **zero**
   subprocesses and zero probes, which is what the `original_order` gate buys.
8. **The anti-flap gate owns "how many notifications".** A report — and therefore an
   alert — fires only on the healthy→incident edge. Do not add a rate limiter; do not
   fire on every failing tick.
9. **`-ordernetworkservices` rewrites the service order to exactly the list it is
   given.** A name dropped from that list is a network service deleted from the system.
   The argv is built in one place, `failover.apply_service_order`. It checks every order
   with `service_order.is_order_intact` — same length, same set, no duplicates, nothing
   that looks like a flag — then lists the order again right before the write and
   refuses if it changed, then reads the order back. Refusing is always the safe answer.
   The failover switch, failback and the CLI all call that function. Never build that
   argv anywhere else, and never bypass the guard, including on the manual-switch path.
10. **Interface-bound probing uses `IP_BOUND_IF`, not source-address binding.** On Darwin
    the route lookup follows the destination, so a socket bound to the Wi-Fi address
    still leaves through whichever interface owns the route — the obvious implementation
    silently measures the wrong path. `IP_BOUND_IF` is 25, `IPV6_BOUND_IF` is 125; both
    are in Darwin's headers and were confirmed against live interfaces.

## Before you claim a change works

```bash
ruff check . && ruff format --check . && python3 -m pytest -q   # <TEST_COUNT> tests, offline
```

That is the CI gate (`.github/workflows/ci.yml`). An autouse fixture in
`tests/conftest.py` stubs the privilege probe (`sudo -n -k -l`, `ifconfig -l`,
`route -n get default`) and the `log show` readers that app wiring would otherwise
start. `test_privileges`, `test_system_log` and `test_log_watcher` are exempt, because
they test those functions and inject their own runners.

There is **no `scripts/check_docs.py`** in this repo, despite what earlier revisions of
this file claimed. Nothing machine-checks doc drift. Whenever tests are added, regenerate
every test count by hand from `python3 -m pytest -q --collect-only | grep -c '::'`. The
counts live in `docs/SCRIPTS.md` (the quick-start comment, the entry-point table, the
Tests section, and the per-file table with its total row), in `docs/TESTING.md`, and in
this file. Stale counts have shipped twice for exactly this reason.

Then exercise the paths the suite cannot, using the one-shot invocations in
`docs/SCRIPTS.md` — the prober, the ladder's read-only checks, the log watcher, the
domain learner and the failover dry run all behave differently against the real OS than
against fakes. Three live findings came from exactly that: macOS masks hostnames in the
unified log, the log's own subsystem label parsed as a domain, and source-address
binding does not pin an interface.

**Loading the menu bar app cannot be automated.** `rumps.App().run()` never returns and
needs a GUI session, so `python3 -m netdnsmonitor.app` is a manual check. Do not claim
it as verified, and never invoke it from a script or an agent expecting completion.

## House style

**Python** — 3.13, stdlib-first. `requirements.txt` carries four runtime deps and
stays that way: `rumps`, `anthropic`, `PyYAML`, `pyobjc-framework-Cocoa`, each
pinned exactly rather than floored, because `scripts/start.sh` re-runs
`pip install -r` on every start. `constraints.txt` pins every transitive dependency,
and every install path passes `-c constraints.txt`. Test and lint tooling (`pytest`, `ruff`) lives in
`requirements-dev.txt` and must stay out of the runtime file — `pytest` was once
in it, which installed it onto every end user's machine. Do not add `requests` for
something `urllib.request` does, and do not add a Slack or SMTP SDK. Type hints throughout.
Tests are `pytest` with plain functions, fakes injected as callables — no
`unittest.mock` patching of module internals unless there is no seam.
`.pre-commit-config.yaml` runs `ruff check --fix` and `ruff format` before each commit;
its `rev` must match the `ruff` pin in `requirements-dev.txt`.

**Comments explain *why*, especially where the obvious implementation is wrong.** The
load-bearing examples: the inert `setdefaulttimeout`, the bracket-stripped log line, the
`quit()`-then-`close()` SMTP fallback, the control domain's role in pruning, the clamp on
the learn interval, why source-address binding does not work, and why the pre-failover
order is written before the switch rather than after it succeeds. Do not narrate *what*.

**Do not overclaim in a comment either.** A docstring here once said the `None`/`False`
split stopped the policy layer mistaking a missing interface for a broken one; it did
not — both refuse the same switches, and the split is about what gets *reported*. A
comment that is wrong about why is as expensive as code that is wrong.

## Known-unverified areas

- **The privileged network-order write has never been executed.** `networksetup
  -ordernetworkservices` is covered only by fakes. Adjacent evidence says it will work
  unprompted on this machine — `scselect -n` wrote to root-owned `preferences.plist`
  from a non-root admin account with no password prompt, using the same
  `system.services.systemconfiguration.network` right — but that is a prior, not proof.
  The menu bar's "Switch to backup now" button is the intended way to find out.
- **No live Slack or SMTP delivery has been confirmed.** Both channels are covered by
  tests with injected transports; neither has been observed delivering a real message.
- **Auto-learned domains find nothing on a stock macOS install** — the unified log masks
  hostnames. Measured: 758 error-like lines, 198 explicitly masked, 0 learnable domains.
  Do not present the feature as working without stating that.
- **A long `log_lookback` still exceeds the `log show` timeout.** `log_watcher` allows
  `LOG_SHOW_TIMEOUT_SECONDS` (10s), and a 30m lookback measured 10.15s. If `log show`
  times out or fails, the watcher returns one line starting with
  `[net-dns-monitor] no log evidence:`, so the report says the log was not read. An
  empty list means `log show` ran and matched nothing. Raising the lookback therefore
  produces the no-evidence line instead of evidence.
- **The sudoers grant's current code has not been verified live.** A file
  `/etc/sudoers.d/net-dns-monitor` dated 2026-08-19 (1129 bytes, root-only) exists on
  the owner's Mac, so an earlier version of the grant did run. The current code would
  write a different size for today's interfaces, so that file predates it. Inspect it
  with `sudo cat` before relying on either version. When the user clicks **Grant
  elevated permissions**, `privileges.py` writes `/etc/sudoers.d/net-dns-monitor`
  (root:wheel, 0440). It gives the user `NOPASSWD` for two complete commands:
  `/usr/bin/killall -HUP mDNSResponder`, and `/usr/sbin/ipconfig set <interface> DHCP`
  for each interface enumerated at grant time. With the grant, `flush_dns_cache`
  restarts mDNSResponder and `renew_dhcp_lease` runs through `sudo -n`. Without it,
  the flush reports `partial` and the renewal reports `NEEDS_PRIVILEGE`.
  `toggle_network_service` is never automated and returns `NOT_AUTOMATED`. Fakes cover
  all of this. `switch_to_backup_network` does not use the grant: it is genuinely
  attempted, and reports `NEEDS_PRIVILEGE` only when the write is actually refused.
- **The canonical line is branch `feat/appstore-prep`**
  (`.claude/worktrees/appstore-prep`), and the owner will merge it into `master`. `master`
  (050e905) already contains the reconciled `dns-resolution-monitor` head (02c40dd),
  but not the optimizer pass or the App Store work. The other worktrees under
  `.claude/worktrees/` and the `docs/scripts-manual` branch are older and are not what
  should run. `scripts/net-dns-monitor-service` resolves `SOURCE_BUNDLE` from
  `NDM_SOURCE_BUNDLE`, then the path its last install or update recorded in
  `~/Library/Application Support/net-dns-monitor/source-bundle`, then its own checkout's
  `dist/`; `scripts/install.sh` passes `NDM_SOURCE_BUNDLE`. Reports predating the reconcile were produced by an older tree,
  so check the report's date before concluding the current code behaves the way it
  suggests.
- **Two router implementations exist, and which one is canonical is an owner
  decision.** Do not delete either. `netdnsmonitor/router.py` is the app's router: bootpd
  DHCP on 192.168.10.x and pf NAT in the `com.apple/netdnsmonitor_nat` anchor, off by
  default (`router_enabled: false`). The app never starts it at launch; only
  **Router → Start** and the router window start it, behind the macOS admin dialog. The
  `router/` stack is separate: dnsmasq DHCP and unbound on 192.168.4.0/24
  (`dnsmasq/`, `unbound/`), with NAT in the `com.apple/custom_nat` anchor, installed as
  the `com.custom.router.nat` LaunchDaemon. Both want UDP 67 and
  `net.inet.ip.forwarding`, so `Router.start` and `Router.stop` refuse while
  `/Library/LaunchDaemons/com.custom.router.nat.plist` exists.
- **The NAT LaunchDaemon installed on the owner's machine runs a user-writable script
  as root.** Its `ProgramArguments` still points at `router/scripts/enable_nat.sh` in
  the main checkout (`~/dev/net-dns-monitor`), and launchd runs it every 60s. The fixed
  `router/scripts/install_persistent_nat.sh` installs a root-owned copy at
  `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh` and points the daemon
  there. Until the owner re-runs that installer as root, any process running as the
  checkout's owner can edit the script and have it run as root.
- **The Mac App Store build is a reduced edition, and its release mode has never been
  run.** `netdnsmonitor/distribution.py` detects the App Sandbox from the environment
  and names the features the sandbox or App Review forbid: the failover switch, the
  privileged repairs, the unified log, the router, the shell console and the
  LaunchAgent login item. Each must report itself unavailable, never fail in a way that
  looks like a network fault. `credentials.py` adds a Keychain lookup after the environment, and
  `ai_consent.py` records permission before anything goes to Anthropic.
  `docs/APP_STORE_SUBMISSION.md` is the authoritative document for the store build:
  what was measured, what is wired, and what is not verified.
- **Two consoles were merged into one.** The GUI console is the arbitrary-shell one
  (`console.py` + `console_window.py`), reachable from the menu bar and from the
  dashboard button, both going through the single controller at `App.console`.
  `cli_console.py` is a separate thing: the REPL behind `netdns console`, a terminal
  surface over the `commands.py` catalogue. Do not merge them; they answer different
  questions.

## Related

`AGENTS.md` points here. `docs/SCRIPTS.md` is the operator's manual for every entry
point; `docs/ARCHITECTURE.md` is the shape of the system; `docs/known-issues.md` is the
current defect list; `docs/APP_STORE_SUBMISSION.md` covers the Mac App Store build;
`router/docs/ROUTER.md` describes the `router/` stack.
