# Testing

1079 tests, offline, ~25s. `pytest.ini` points `testpaths` at `tests/`, so a
bare `python3 -m pytest` from the repo root is the whole suite.

```bash
python3 -m pytest -q                        # the gate
python3 -m pytest -v                        # per-test names
python3 -m pytest tests/test_failover.py -q # one file
```

## The rule the suite is built on

**The engine does not touch the network — the injected callable does.** Every
side effect (probe, subprocess, LLM call, SMTP, webhook, clock, filesystem)
enters as a parameter with a real default. That is what lets the whole decision
surface be exercised offline: the suite opens no sockets, spawns no `networksetup`,
and calls no API.

The pattern, from `make_repair_executor`:

```python
def make_repair_executor(run_fn: RunFn = subprocess.run, ...):
```

Production gets the default. Tests pass a fake. Adding a module means adding its
test file in the same commit, following the nearest existing file rather than
inventing a third shape.

## What is tested, and where it lives

Rather than a per-module table — which rots, and did: the previous version of
this file listed 15 files when there are 53 — the shape of it:

**Decision modules** own the interesting logic and are tested directly, with
fakes for anything external. `classifier`, `flap_gate`, `ladder`, `escalation`,
`report`, `status`, `failover_policy`, `service_order`, `console` and
`stall_log` are the pure ones; several have no fakes at all because they touch
nothing.

Four modules have **no test file of their own**: `app.py` (covered by the
wiring tests below), `cli.py` and `commands.py` (both exercised through
`test_cli_console.py`), and `mini_window.py` — which is not covered at all.
Nothing in `tests/` so much as imports it, including `mini_text`, which decides
what the collapsed window says and is a pure function that could be tested
today. That is a gap, not a design choice; see `docs/known-issues.md`.

**Effect modules** wrap one external thing and are tested by injecting it:
`prober` (connect + resolve), `dns_query` (UDP socket), `log_watcher` and
`system_log` (`log show`), `repair_executor` (`subprocess.run`, `os.listdir`),
`anthropic_escalator` (the client), `notifications` (HTTP and SMTP transports),
`interface_probe` (the bound connect), `throughput`, `ping`, `peer_net`,
`privileges`, and the storage modules (`report_storage`, `history`,
`forensic_log`, `resolution_log`, `peers`) against `tmp_path`.

**Wiring** is the `test_app_*_wiring.py` set — the behaviour that only exists
once `app.py` glues tested modules together: notification on a fresh report,
the learned-domain probe path that self-prunes, dashboard and console entry
points, ping alerting, privilege prompts, failover, resolution batches. These
build a real `NetDnsMonitorApp` against a nonexistent config path and replace
its state machine with a fake.

**AppKit surfaces** are built for real rather than mocked — `NSWindow`
construction works headlessly, and the properties that matter (retain policy,
button wiring, frame arithmetic, pixel output) are exactly the ones that fail
silently in a bundle. `show()` is never called: it would flash a window across
the screen on every run. See `test_dashboard.py`, `test_console_window.py`,
`test_dock_icon.py`, `test_graphs.py`.

To regenerate the per-file distribution in `docs/SCRIPTS.md`:

```bash
python3 -m pytest -q --collect-only | grep '::' | sed 's/::.*//' | sort | uniq -c | sort -rn
```

## What the suite cannot cover

Green tests are not evidence for any of this. Each needs the one-shot
invocations in `docs/SCRIPTS.md` or a manual check.

- **The `rumps` run loop.** `App().run()` never returns and needs a GUI session.
  `tick()` and the builders are covered with fakes; the loop is not. Never
  invoke `python3 -m netdnsmonitor.app` from a script or an agent expecting it
  to complete.
- **Whether an AppKit window opens and takes keystrokes.** The window tests
  cover construction and wiring. That a console actually appears, accepts
  typing, and prints output was verified separately by driving
  `ConsoleWindowController` against a live `NSApplication` — not by the suite.
- **`default_resolve` / `default_connect` against a real socket.** Always
  injected, which is what keeps the suite offline.
- **The privileged network-order write, and live Slack/SMTP delivery.** See
  `docs/known-issues.md` → Unproven.
- **Anything about the real OS's answers.** Three live findings came from
  exactly this gap: macOS masks hostnames in the unified log, the log's own
  subsystem label parsed as a domain, and source-address binding does not pin an
  interface. Fakes agreed with the code in all three cases.

## Coverage standard

No numeric line-coverage gate. The standard is behavioural: every module has
real assertions on its public functions, not import or smoke checks. A test that
executes a line without asserting on the result of executing it does not count,
and reviewing for that is worth more here than a percentage.

Two properties are worth testing explicitly because they fail silently:

- **Anything that must not block the run loop.** Assert the caller *returned*,
  not that a thread was started — a thread is the implementation, returning is
  the requirement. `test_tick_does_not_wait_for_a_slow_notifier` is the model:
  block the collaborator outright, assert the tick came back, then release.
- **Anything whose failure looks like success.** A repair that silently does
  nothing, a notification that never sent, an empty log read that reads as "no
  errors". These need an assertion on the reported outcome, not on the absence
  of an exception.
