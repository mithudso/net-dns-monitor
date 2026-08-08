# Known issues

Two lists. The first is behaviour that looks like a bug and is not — changing
any of it would make the app claim more than it knows. The second is what is
genuinely unproven or missing.

Last reviewed 2026-08-08, after the four worktree lines were reconciled.

## By design (not bugs)

- **The DNS cache flush is partial, and says so.** `dscacheutil -flushcache`
  runs fine unprivileged; `killall -HUP mDNSResponder` does not, because
  mDNSResponder runs as another user and a signal to a process you do not own is
  rejected regardless of the command's own permissions. Confirmed empirically.
  `repair_executor.py` reports `"partial: ..."` rather than a false `"ok"`.
  With the `privileges.py` grant installed, this one completes.
- **Two repairs still do nothing but say so.** `renew_dhcp_lease` and
  `toggle_network_service` return `NEEDS_PRIVILEGE: ...`. A real fix needs an
  `SMAppService` privileged helper that does not exist. Toggling an interface
  stays unautomated for a second reason as well: down-then-up cannot be one
  command, and two risks leaving the machine offline with no network to fix it
  over.
- **`None` is not `False` anywhere in a probe result.** `None` means *not
  probed*; `classify` maps it to `unclassified` rather than guessing, and an
  absent network interface reads `None` rather than "unreachable". An unplugged
  cable is not a dead link, and reporting it as one sends someone after the
  wrong fault.
- **Notifications fire on incident onset only.** Recovery produces no report
  (see `state_machine.py`), so there is no "back to normal" message. The menu
  bar icon is the recovery signal. This is the anti-flap gate owning how many
  notifications get sent; do not add a rate limiter on top.
- **Auto-learned domains are the one exception to "no auto-detected targets",
  and a narrow one.** `domain_learner.py` learns only from *failed* resolutions
  already in the unified log — evidence the machine produced itself — never from
  browser history or another app's data. Every learned name is validated,
  capped, and pruned once shown to be dead.
- **`app.py` is thin wiring and stays that way.** It is exercised by the
  `test_app_*_wiring.py` files, but the `rumps` run loop itself is not and
  cannot be. New decision logic belongs in a testable module.

## Unproven

Things the code does that have never been observed working against the real
system. Each is covered by tests with injected fakes, which proves the logic and
proves nothing about the world.

- **The privileged network-order write has never been executed.**
  `networksetup -ordernetworkservices` is covered only by fakes. Adjacent
  evidence says it should work unprompted on this machine — `scselect -n` wrote
  to a root-owned `preferences.plist` from a non-root admin account with no
  password prompt, using the same
  `system.services.systemconfiguration.network` right — but that is a prior, not
  proof. The menu bar's "Switch to backup now" is the intended way to find out.
- **No live Slack or SMTP delivery has been confirmed.** Both channels are
  covered with injected transports; neither has been observed delivering a real
  message.

## Confirmed limitations

Measured, reproducible, and currently unfixed.

- **Interface-bound probing returns "unreachable" for every physical interface
  while a tunnel is up.** Measured 2026-08-08 on this machine: an ordinary
  unbound connect to `1.1.1.1:443` and `8.8.8.8:443` succeeds, while the same
  targets bound to `en9` or `en0` with `IP_BOUND_IF` fail. Ten `utun`
  interfaces were up at the time. A socket pinned to a physical NIC bypasses
  the tunnel and reaches nothing.

  The consequence is that **automatic failover is inert**, not dangerous:
  `attempt_failover` refuses with *"backup interface did not answer either --
  switching would trade one dead path for another"*, so nothing thrashes. The
  manual "Switch to backup now" still works, because a manual switch skips the
  policy and keeps only the execution guards.

  Two ways out, neither chosen by default because a probe target is a claim
  about the network: point `external_targets` at addresses reachable off-tunnel
  (the LAN gateways are the obvious candidates), or turn the tunnel off.

- **Auto-learned domains find nothing on a stock macOS install.** The unified
  log masks hostnames by default — mDNSResponder's resolver lines carry
  `<mask.hash: '...'>` or an opaque token where the queried name would be.
  Measured on this machine: 758 error-like lines, 198 explicitly masked, 0
  learnable domains. Unmasking (`sudo log config --mode "private_data:on"`) is a
  system-wide privacy change and is not recommended lightly. Treat `domains` as
  the real probe list and this feature as opportunistic.

- **`log_watcher` returns `[]` on subprocess timeout, which is
  indistinguishable from "no errors found."** A 30m `log_lookback` measured
  10.15s against a hardcoded 10s timeout, so raising the lookback silently
  produces empty evidence rather than an error.

- **The failover indicator can name a dead adapter as active.** It reads the
  network *service order*, not the live default route. On this machine the
  order leads with an unplugged adapter while traffic goes out a lower-priority
  one, and the indicator says the unplugged one is active. Cosmetic — nothing
  decides on it — but it reads as wrong to anyone checking.

## Gaps

- **Nothing machine-checks doc drift.** There is no `scripts/check_docs.py`,
  despite what earlier revisions of `CLAUDE.md` claimed. The test counts in
  `docs/SCRIPTS.md` (two places plus a per-file table) must be regenerated by
  hand from `python3 -m pytest -q --collect-only | grep -c '::'`. Stale counts
  have shipped three times for exactly this reason.
- **`mini_window.py` has no test coverage whatsoever.** Nothing in `tests/`
  imports it. `mini_text` is a pure function that decides what the collapsed
  window says and could be tested today; the window shell around it is AppKit
  and would follow the pattern in `test_dashboard.py`. Found 2026-08-08 while
  rewriting `docs/TESTING.md`, which until then implied it was covered.
- **`default_resolve` and `default_connect` are never exercised against a real
  socket.** Every prober test injects `resolve_fn`/`connect_fn`, which is what
  keeps the suite offline and fast, and also means a change to the real resolver
  path is caught only by the one-shot invocations in `docs/SCRIPTS.md`.
