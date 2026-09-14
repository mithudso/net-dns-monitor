# Known issues

Six lists. "By design" is behaviour that looks like a bug and is not: changing
it would make the app claim more than it knows. "Unproven" is code that has never
been observed working against the real system. "Confirmed limitations" are
measured and currently unfixed. "Blocked on an owner decision" has a known fix
direction that changes intended behaviour, so it waits for the owner. "Gaps" is
what is missing. "No longer issues" records entries that earlier revisions
listed.

Last reviewed 2026-09-14, after the optimizer commit `b07eee5`.

Measurements below are dated where they were taken. The masked-log counts, the
`log_watcher` timing, the `IP_BOUND_IF` tunnel finding and the `scselect`
privilege evidence come from earlier sessions and were not re-taken in this
review. Treat them as priors, and re-measure before relying on any of them.

## By design (not bugs)

- **The DNS cache flush is partial without the grant, and says so.**
  `dscacheutil -flushcache` runs fine unprivileged. `killall -HUP mDNSResponder`
  does not, because mDNSResponder runs as another user, and the system rejects a
  signal to a process you do not own regardless of the command's own permissions.
  Confirmed empirically. `repair_executor.py` reports `"partial: ..."` rather
  than a false `"ok"`. With the `privileges.py` grant installed, the executor
  retries the HUP through `sudo -n` and reports `ok` only if that succeeds.
- **`toggle_network_service` is never automated.** It returns
  `NOT_AUTOMATED: ...`, not `NEEDS_PRIVILEGE`, because the grant would not help.
  Down-then-up cannot be one command, and two commands risk leaving the machine
  offline with no network to fix it over.
- **`renew_dhcp_lease` runs only under the grant.** Without the grant it returns
  `NEEDS_PRIVILEGE: ...` and runs nothing. With the grant it runs
  `sudo -n /usr/sbin/ipconfig set <interface> DHCP` on the interface that holds
  the default route. If no Ethernet or Wi-Fi interface holds that route (for
  example a VPN holds it on `utun`), it returns `cannot renew: ...`.
- **`None` is not `False` anywhere in a probe result.** `None` means *not
  probed*. `classify` maps it to `unclassified` rather than guessing, and an
  absent network interface reads `None` rather than "unreachable". An unplugged
  cable is not a dead link, and reporting it as one sends someone after the wrong
  fault.
- **An unreadable log is reported, not hidden.** If `log show` times out, exits
  nonzero or cannot run, `log_watcher` returns one line starting
  `[net-dns-monitor] no log evidence: log show ...`. `[]` means the log was read
  and no line matched. `domain_learner` skips the sentinel line.
- **Notifications fire on incident onset only.** Recovery produces no report
  (see `state_machine.py`), so there is no "back to normal" message. The menu bar
  icon is the recovery signal. The anti-flap gate owns how many notifications get
  sent; do not add a rate limiter on top.
- **Auto-learned domains are the one exception to "no auto-detected targets",
  and a narrow one.** `domain_learner.py` learns only from *failed* resolutions
  already in the unified log. It never reads browser history or another app's
  data. Every learned name is validated, capped, and pruned once shown to be dead.
- **`app.py` is wiring.** The `test_app_*_wiring.py` files exercise it, but no
  test runs the `rumps` run loop itself, and none can. New decision logic belongs
  in a testable module.

## Unproven

Each item below is covered by tests with injected fakes. That proves the logic
and proves nothing about the world.

- **The privileged network-order write has never been executed.**
  `networksetup -ordernetworkservices` is covered only by fakes. Adjacent
  evidence says it should work unprompted on this machine: `scselect -n` wrote to
  a root-owned `preferences.plist` from a non-root admin account with no password
  prompt, using the same `system.services.systemconfiguration.network` right.
  That is a prior, not proof. The menu bar's "Switch to backup now" is the
  intended way to find out.
- **The sudoers grant has never been exercised live.** Grant, Revoke, the
  mDNSResponder restart under the grant, and `renew_dhcp_lease` through
  `sudo -n` are covered only by tests with an injected `run_fn`. No test writes
  `/etc/sudoers.d/net-dns-monitor`.
- **No live Slack or SMTP delivery has been confirmed.** Both channels are
  covered with injected transports. Neither has been observed delivering a real
  message.
- **The Mac App Store release path has never run with real certificates.** This
  Mac has no Apple Distribution or Mac Installer Distribution certificate, so
  `build_appstore.py release` (release signing, provisioning-profile embedding,
  `productbuild` signing) has not run. `adhoc` mode ran end to end. The GUI app
  has not been launched sandboxed; only `sandbox_probe` has. See
  `docs/APP_STORE_SUBMISSION.md` §2.
- **The app's router mode is covered only as text.** `b07eee5` rewrote
  `router.py`. `tests/test_router.py` asserts on the generated root script as a
  string and never runs it. UNVERIFIED: whether the rewritten start and stop
  scripts have run against a real machine.

## Confirmed limitations

Measured, reproducible, and currently unfixed.

- **An interface-bound probe cannot reach an internet target while a tunnel is
  up.** Measured 2026-08-08 on this machine: an ordinary unbound connect to
  `1.1.1.1:443` and `8.8.8.8:443` succeeds, while the same targets bound to `en9`
  or `en0` with `IP_BOUND_IF` fail. Ten `utun` interfaces were up. A socket pinned
  to a physical NIC bypasses the tunnel and reaches nothing.

  This is a property of the setup, not a defect, and it is why
  `failover_probe_targets` exists: aim the interface probe at something reachable
  off-tunnel, normally each link's own gateway. Configured that way on this
  machine, the probe reports Wi-Fi reachable, and automatic failover works.

  Do **not** solve it by repointing `external_targets`. That list also drives
  incident detection, and a gateway answers straight through an ISP outage, so
  the app would stop reporting the outages it exists to report.

  Two things to know when choosing targets. An off-link gateway *blackholes*
  rather than refusing (measured at a flat 2.00s), so the probe budget must cover
  every listed target; `failover_probe_timeout_seconds` sets it. And TCP/53 is
  open on one gateway here but not guaranteed anywhere; check that the port
  answers before trusting it.

- **Auto-learned domains find nothing on a stock macOS install.** The unified log
  masks hostnames by default. mDNSResponder's resolver lines carry
  `<mask.hash: '...'>` or an opaque token where the queried name would be.
  Measured on this machine: 758 error-like lines, 198 explicitly masked, 0
  learnable domains. Unmasking (`sudo log config --mode "private_data:on"`) is a
  system-wide privacy change and is not recommended lightly. Treat `domains` as
  the real probe list and this feature as opportunistic.

- **A long `log_lookback` produces no log evidence.** `log show` runs with a
  fixed 10s timeout (`log_watcher.LOG_SHOW_TIMEOUT_SECONDS`, not configurable). A
  30m lookback measured 10.15s. When the read times out, the report carries the
  line `[net-dns-monitor] no log evidence: log show timed out after 10s (lookback
  30m)` instead of excerpts. The default `5m` measured 2.25s.

- **The failover indicator can name a dead adapter as active.** The "Active:"
  row shows the head of the network *service order*
  (`NetworkFailover.snapshot()["active_service"]`), not the live default route.
  On this machine the order leads with an unplugged adapter while traffic goes out
  a lower-priority one, and the indicator says the unplugged one is active.
  Nothing decides on this row, but it reads as wrong to anyone checking.

- **`external_targets: []` gives a permanent `unclassified` state.** With no
  external target, the prober reports `external_reachable: None`, so every tick
  classifies as `unclassified`. The anti-flap gate counts that as failing (see
  the blocked item below), so the app latches an incident with its alert and
  escalation. `load_config` accepts the empty list; nothing validates it.

- **Notifications use the deprecated `NSUserNotificationCenter`.**
  `rumps.notification` in `rumps` 0.4.0 posts through `NSUserNotificationCenter`,
  which Apple deprecated in macOS 11. `alert.py` records that it still returned a
  real centre on macOS 26.4, but it does not raise when the system declines to
  show a banner. The menu's "Test network alert" item is the only check that a
  banner appears.

## Blocked on an owner decision

- **`state_machine.tick()` still runs on the `rumps` run loop.** `app.tick()`
  calls it from the `poll_interval_seconds` timer. On an incident edge that tick
  also runs the ladder commands (5s timeout each), `log show` (10s timeout) and
  the escalation call. The escalation call alone can freeze the menu bar for its
  30s request timeout (`anthropic_escalator.DEFAULT_TIMEOUT_SECONDS`) plus the
  name lookup of `api.anthropic.com`, which no timeout bounds: the HTTP client
  resolves the name before it applies the timeout. On a DNS incident that lookup
  goes through the broken resolver.
  `default_client()` now sets `max_retries=0`, so SDK retries no longer multiply
  that wait. Moving the pipeline to a worker changes the order of report, alert
  and failback, so it waits for the owner.
- **Peer messages are unauthenticated.** `peer_net.py` accepts any well-formed
  datagram from a sender on an on-link IPv4 subnet or loopback. If the interface
  list cannot be read, it accepts every sender. Nothing proves that a message came
  from a copy of this app, so a host on the LAN can report false peer state and
  move the `localize.py` verdict. Authentication (for example a shared HMAC key)
  waits for the owner.
- **`resolution_log` and `stall_log` grow without bound.**
  `resolution_log.append_resolution_findings` appends to a JSONL file on every
  batch, and `stall_log.select_stalled_domains` reads the whole file each cycle.
  Compaction would break the promise in `resolution_log.py` that the file can be
  tailed and grepped like any other log.
- **Unclassified ticks feed the anti-flap gate.** `StateMachine.tick()` counts
  every classification other than `healthy` as a failure. A run of `unclassified`
  ticks therefore declares an incident, with its alert and escalation, and runs no
  ladder. `tests/test_state_machine.py::test_unclassified_probe_result_escalates_without_a_ladder`
  pins this. `load_config` rejects one trigger (empty `domains` with no
  `control_domain`); an empty `external_targets` is another (see above).
- **`LOCAL_NETWORK` verdict when a peer answers without reporting state.** If a
  peer answered but the peers gave no single answer about internet reachability,
  `localize.localize` returns `local_network` at medium confidence. The reason
  text now lists this machine's route, firewall or VPN, the router and the ISP as
  still possible. Whether the verdict should be `inconclusive` instead waits for
  the owner.
- **Which router stack is canonical.** The app's router mode (`router.py`,
  `bootpd` on `192.168.10.0/24`) and the `router/` stack (`dnsmasq` and `unbound`
  on `192.168.4.0/24`) conflict. `Router` refuses to start or stop while
  `/Library/LaunchDaemons/com.custom.router.nat.plist` exists. Neither stack is
  deleted. See `docs/ARCHITECTURE.md` → Router.
- **The dashboard window content does not reflow on small screens.**
  `dashboard.py` lays out fixed-size content (`WINDOW_HEIGHT = 950`) in a
  resizable window with no autoresizing, so on a small display the bottom of the
  content (the results pane) can sit off screen. The fix moves the content into an
  `NSScrollView`. That change needs a manual visual check, which the suite cannot
  do.
- **Failback from a record taken with a third service at the head says "failed
  back to preferred".** `NetworkFailover._do_failback` restores the recorded
  pre-failover order when it still matches the current services and does not
  start with a backup. If a third service (neither preferred nor a backup) led
  that record, failback puts that service back at the head. The outcome still
  reads `ok: ... (failed back to preferred '<preferred>')`.
- **Automatic failback can return to a dead ISP link when probe targets are
  gateways.** If `failover_probe_targets` point at each link's own gateway, a
  preferred-link probe that succeeds proves only that the LAN answers. During an
  ISP outage the gateway still answers. After a manual switch to a backup, three
  good gateway probes and the cooldown make failback move the machine back onto
  the dead link. The next incident's failover step then refuses with "the outage
  is not specific to this path", which is false, and the failback cleared the
  record, so nothing moves again. Options for the owner: give the preferred link
  a separate target set that lies beyond its gateway; disable automatic failback
  after a manual switch; or at least reword the refusal reason. Found by the
  blind re-audit on 2026-09-14.

## Gaps

- **Nothing machine-checks doc drift.** There is no `scripts/check_docs.py`,
  despite what earlier revisions of `CLAUDE.md` claimed. The test total appears by
  hand in `docs/SCRIPTS.md` (the gate command, the quick reference, the Tests
  section and its per-file table), `docs/TESTING.md` and `CLAUDE.md`. This command
  lists the places that match the current total:

  ```bash
  grep -rn "$(python3 -m pytest -q --collect-only | grep -c '::')" docs/ CLAUDE.md
  ```

  Stale counts have shipped three times for exactly this reason, which is the
  argument for a checker rather than a more careful habit.
- **`prober.default_resolve` and `prober.default_connect` are never exercised
  against a real socket.** Every prober test injects `resolve_fn` or
  `connect_fn`. That keeps the suite offline and fast. It also means only the
  one-shot invocations in `docs/SCRIPTS.md` catch a change to the real resolver
  path.

## No longer issues

Earlier revisions of this file listed these. They no longer apply.

- `log_watcher` returned `[]` on a timeout, indistinguishable from "no errors
  found". Fixed in `b07eee5`: it now returns the `no log evidence` sentinel line.
- `renew_dhcp_lease` and `toggle_network_service` were listed as doing nothing.
  The first runs under the grant; the second returns `NOT_AUTOMATED`.
- `mini_window.py` was listed as having no test coverage. Commit `02c40dd` added
  `tests/test_mini_window.py`, which covers `mini_text`.

## Found by the repo dossier

The repo dossier (`crawl-repo-to-llms`, generated at `22b52bf`) flagged these.
Each was re-checked against the code on 2026-09-14.

- **`unbound/pf_unbound.conf` is applied by nothing, and it contradicts
  `unbound/unbound.conf`.** The file holds two `rdr pass` rules that send UDP
  and TCP port 53 on `192.168.4.1` to port 53535. No script, doc or test
  references it: `git grep pf_unbound` finds only the file itself.
  `unbound/unbound.conf` listens on `interface: 192.168.4.1`, `port: 53`, and
  nothing listens on 53535. If someone loaded these rules, every DNS query from
  a `router/` stack client would go to a closed port. `unbound/install.sh`
  flushes the anchor `com.apple/unbound_dns` and loads nothing into it. Whether
  to delete or fix the file belongs to the router-stack owner decision above.
- **Two LaunchAgents can start the app at login.** The menu's Start at Login
  item writes `~/Library/LaunchAgents/com.netdnsmonitor.plist`
  (`app.LOGIN_AGENT_LABEL`, `RunAtLoad` true). `net-dns-monitor-service install`
  writes `com.mitchhudson.net-dns-monitor.plist` (`app.SERVICE_AGENT_LABEL`).
  The app recognises both: `login_item_installed` shows the item as on when
  either file exists, and `toggle_login` does not add its own agent while the
  service agent exists. The service script does not know the other label. If
  Start at Login was turned on first and the service is installed afterwards,
  both agents exist and launchd starts two copies at login. The app has no
  single-instance guard. `net-dns-monitor-service status` warns about copies it
  finds with `pgrep -x Net-DNS-Monitor`. UNVERIFIED: whether that matches a
  source-run copy started by the `com.netdnsmonitor` agent.
- **`netdns failover backup|preferred` and `netdns priority --promote` rewrite
  the service order without `--yes`.** `cli.cmd_run` refuses a catalogue
  command marked `mutates` unless `--yes` is given. `cli.cmd_failover` calls
  `NetworkFailover.switch_now`, and `cli.cmd_priority` calls `promote_service`,
  with no confirmation; `build_parser` gives neither subcommand a `--yes`
  option. The `netdns console` REPL asks for `yes` before `promote`, `switch`
  and `preferred`. The write is still guarded by `service_order.is_order_intact`
  and the read-back. Whether one-shot switches should require `--yes` waits for
  the owner; `docs/runbooks/manual-failover.md` documents the commands as they
  are.
