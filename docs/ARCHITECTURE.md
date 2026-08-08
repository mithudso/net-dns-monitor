# Architecture

## System context

`net-dns-monitor` is a single-process macOS menu bar app. It has no server
component, no database, and no multi-user concerns — everything runs inside
one `rumps` process on the user's machine, polling on a timer.

```
 ┌─────────────────────────────────────────────────────────────┐
 │                         app.py (rumps)                       │
 │  menu bar icon/title, "Open last report" menu item, timer    │
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
- **Privileged repairs are stubbed, not attempted.** `repair_executor.py`
  reports `NEEDS_PRIVILEGE` for steps that need elevated rights, rather than
  trying and silently failing. See `docs/known-issues.md`.
- **No auto-detected targets.** `domains` and `internal_targets` are
  explicit, user-supplied config (`config.example.yaml`) — the app never
  reads browser history or other app data to guess what to monitor.

## ADRs (informal)

- **Why `rumps` instead of a full native app / Swift menu bar app?** Fast to
  build and test in Python, matches the rest of the codebase's language, and
  a menu bar utility doesn't need a full app bundle's capabilities.
- **Why stub privileged repairs instead of a helper tool?** Out of scope for
  the MVP; a proper fix is a `SMAppService` privileged helper, noted as
  follow-up work in the README and `repair_executor.py`.
