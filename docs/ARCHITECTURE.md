# Architecture

## System context

`net-dns-monitor` is a single-process macOS menu bar app. It has no server
component, no database, and no multi-user concerns — everything runs inside
one `rumps` process on the user's machine, polling on a timer.

```
 ┌─────────────────────────────────────────────────────────────┐
 │                         app.py (rumps)                       │
 │  menu bar icon/title, failover indicator, menu items, and    │
 │  six timers on six cadences (see app.py's own docstring)     │
 └───────────────────────────┬────────────────────────────────-┘
                              │ tick()
                              ▼
 ┌─────────────────────────────────────────────────────────────┐
 │                     state_machine.StateMachine                │
 │  orchestrates one full incident lifecycle per tick            │
 └───┬──────────┬──────────────┬──────────────┬─────────────┬──┘
     │          │              │              │             │
     ▼          ▼              ▼              ▼             ▼
 prober.py  classifier.py  flap_gate.py   ladder.py    escalation.py
 (reachability +   (network/DNS/    (debounce so a   (which repair  (redact +
  DNS resolution)   healthy split)   single blip      steps to run   escalate-
                                     isn't an          for this       or-not
                                     incident)         classification) gate)
     │                                                     │             │
     ▼                                                     ▼             ▼
 dns_query.py                                    repair_executor.py  anthropic_escalator.py
 (raw UDP query                                  (dispatches ladder  (Claude API call,
  against a public                                steps to real      only reached if
  resolver)                                       macOS commands)    escalation.py says so)
                                                        │
                                                        ▼
                                                  log_watcher.py
                                              (`log show` tail/filter)
                              │
                              ▼
                        report.py / report_storage.py
                  (build the incident report, write .json + .md)
                              │
                              ▼
                          status.py
                  (menu bar icon/title from current state)
```

## Data flow — one incident

1. `state_machine.tick()` calls `prober()` for a reachability/DNS snapshot.
2. `classifier.classify()` turns that into `HEALTHY` / `NETWORK` / `DNS` /
   `UNCLASSIFIED`.
3. `flap_gate.FlapGate` debounces: an incident is only declared after
   `failure_threshold` consecutive bad ticks, and only cleared after
   `success_threshold` consecutive healthy ticks.
4. On a `healthy -> incident` transition, `state_machine` runs
   `ladder.ladder_for(classification)` — an ordered list of `check` and
   `repair` steps appropriate to that classification — through
   `repair_executor`.
5. It re-probes (the recheck) to see whether the ladder actually fixed
   things.
6. `escalation.should_escalate()` decides, from ladder-completed +
   repair-attempted-or-n/a + recheck-still-failing, whether to call Claude.
   If so, `escalation.redact()` strips `sensitive_strings` from the bundle
   first.
7. `report.build_report()` assembles everything (classification, probe
   results, log excerpts, ladder results, repair outcome, recheck result,
   escalation response) into one report dict; `report_storage` writes it as
   timestamped `.json` + `.md` under `reports_dir`.
8. `status.py` derives the menu bar icon/title from the current state so the
   user sees 🟢/🔴 without opening anything.

## Key design decisions

- **All external effects are injected callables.** `prober`, `repair_executor`,
  `escalator`, and `log_watcher` are passed into `StateMachine.__init__` as
  functions, not imported and called directly. This is what makes every
  decision path unit-testable with fakes — see `docs/TESTING.md`.
- **Escalation only fires after the loop closes**, never on first detection —
  see the docstring at the top of `state_machine.py`. This avoids paying for
  an LLM call before the cheap offline ladder has had a chance to resolve
  things.
- **A privileged repair is either genuinely attempted or reported as refused,
  never silently skipped.** This started as "all privileged repairs are
  stubbed", and two still are (`renew_dhcp_lease`, `toggle_network_service`,
  which report `NEEDS_PRIVILEGE`). The others changed: `privileges.py` can
  install a narrow `/etc/sudoers.d` grant that lets the DNS cache flush
  complete, and `failover.py` attempts the switch and reads the service order
  back before claiming anything. See `docs/known-issues.md`.
- **No auto-detected targets, with one bounded exception.** `domains` and
  `internal_targets` are explicit, user-supplied config (`config.yaml`, which is
  the shipped default rather than a sample). The app never reads browser history
  or other app data. `domain_learner.py` is the exception and is deliberately
  narrow: it learns only from *failed* resolutions already recorded in the
  unified log — evidence the machine produced itself — and every learned name is
  validated, capped, and pruned once it is shown to be dead.

## ADRs (informal)

- **Why `rumps` instead of a full native app / Swift menu bar app?** Fast to
  build and test in Python, matches the rest of the codebase's language, and
  a menu bar utility doesn't need a full app bundle's capabilities.
- **Why stub privileged repairs instead of a helper tool?** Out of scope for
  the MVP; a proper fix is a `SMAppService` privileged helper, noted as
  follow-up work in the README and `repair_executor.py`.

## Beyond the core

The diagram above is the incident-detection core and is still accurate for it.
Everything below was added afterwards and hangs off the same `app.py` shell.
This section is a map, not a second diagram — each module's own docstring is the
authority on why it is shaped the way it is.

**Surfaces.** `dashboard.py` is the main window (stats, graphs, a troubleshooting
button grid, and a system-log pane); `mini_window.py` is its collapsed form;
`settings_window.py` edits `config.yaml`; `dock_icon.py` draws the Dock tile.
`graphs.py` renders the history offscreen so it stays pixel-testable.

**The console.** `console.py` holds the decisions of an arbitrary-shell console —
built-ins, `cd`, and a runner guarded by a timeout, a process-group kill, a
`/dev/null` stdin and an output cap. `console_window.py` is its AppKit shell and
holds no decisions. It opens from the menu bar and from a dashboard button, both
through one controller, so the two share a working directory and a history.

**The CLI.** `cli.py` is the `netdns` entry point, `commands.py` its catalogue of
diagnostic commands (each marked for whether it mutates), and `cli_console.py`
the REPL behind `netdns console`. This is a terminal surface and is deliberately
*not* the GUI console: it offers a vetted catalogue, where the GUI console offers
a shell.

**Failover.** `failover.py` switches to a backup network service and back;
`failover_policy.py` decides whether a switch is allowed (cooldowns, rate caps,
which classifications qualify); `service_order.py` owns the one command that
rewrites the system's network service order and refuses any list that is not a
permutation of the current one; `interface_probe.py` measures a specific
interface using `IP_BOUND_IF`; `throughput.py` ranks candidate backups.

**Notifications.** `notifications.py` builds Slack and email channels, opt-in by
their credential being present in the environment. `app.py` redacts on the run
loop and sends on a worker, because a timer callback must not block on network
I/O at the moment the network is known to be broken.

**Evidence and lifecycle.** `forensic_log.py` records down/up episodes;
`history.py` keeps the rolling sample window behind the graphs;
`resolution_prober.py` / `resolution_log.py` / `stall_log.py` run and record the
stalled-domain batch; `domain_learner.py` learns probe targets from the unified
log and prunes dead ones; `system_log.py` and `query_log.py` read macOS's own
logs; `peers.py` / `peer_net.py` / `localize.py` ask other copies of the monitor
on the LAN where a fault actually is; `privileges.py` owns the narrow
`/etc/sudoers.d` grant.
