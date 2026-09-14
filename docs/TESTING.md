# Testing

<TEST_COUNT> tests, offline, in tens of seconds. `pytest.ini` sets
`testpaths = tests`, so a bare `python3 -m pytest` from the repo root is the whole
suite.

```bash
python3 -m pytest -q                        # the gate
python3 -m pytest -v                        # per-test names
python3 -m pytest tests/test_failover.py -q # one file
```

Install the test tooling through the constraints file, so the local tree matches
CI:

```bash
pip install -r requirements-dev.txt -c constraints.txt
```

## CI gates

`.github/workflows/ci.yml` runs on every push and pull request, in two jobs, both
on Python 3.13:

| Job | Runner | Gate |
|---|---|---|
| `lint` | `ubuntu-latest` | `ruff check .` |
| `lint` | `ubuntu-latest` | `ruff format --check .` |
| `test` | `macos-latest` | `python -m pytest -q`, after `pip install -r requirements-dev.txt -c constraints.txt` |

The test job needs macOS because the suite imports AppKit and builds real
windows and images. The lint job installs only the `ruff` version pinned in
`requirements-dev.txt`. `.pre-commit-config.yaml` runs the same two `ruff`
checks before a commit; it does not run the tests.

The local verify loop is the same three commands:

```bash
ruff check . && ruff format --check . && python -m pytest -q
```

## The rule the suite is built on

**The engine does not touch the network — the injected callable does.** Every
side effect (probe, subprocess, LLM call, SMTP, webhook, clock, filesystem)
enters as a parameter with a real default. That lets the whole decision surface
run offline. The suite opens no connection off the machine, runs no
`networksetup`, `sudo`, `osascript` or `log show`, and calls no API. Two files
start local work on purpose: `test_console.py` runs `/bin/sh` children to test
timeouts and process-group kills, and `test_peer_net.py` sends UDP over loopback.

The pattern, from `make_repair_executor`:

```python
def make_repair_executor(run_fn: RunFn = subprocess.run, ...):
```

Production gets the default. Tests pass a fake. Adding a module means adding its
test file in the same commit, following the nearest existing file rather than
inventing a new shape.

## `tests/conftest.py`

Four autouse fixtures apply to every test. Each keeps the suite from reaching
something real on the developer's machine.

| Fixture | What it does | Why |
|---|---|---|
| `isolate_home` | Sets `HOME` to a per-test `tmp_path / "home"` | Config defaults point into `~/Library/Application Support/net-dns-monitor/`. Without this, a test that builds `NetDnsMonitorApp` writes to the real reports, resolution log and forensic journal. |
| `no_real_dock_icon` | Replaces `set_dock_icon` in `netdnsmonitor.dock_icon` and `netdnsmonitor.app` with a no-op | The real call takes about 2s and changes the developer's Dock tile. `test_dock_icon.py` covers the rendering offscreen. |
| `no_real_keychain_or_distribution` | Replaces `credentials.make_keychain_backend` with an empty in-memory Keychain; unsets `APP_SANDBOX_CONTAINER_ID` and `NETDNS_DISTRIBUTION` | Every constructed app reads all three credentials, so it would otherwise query the real login Keychain. Either variable, exported in a developer's shell, would switch direct-build tests onto the App Store paths. Store-build tests pass `capabilities=` explicitly. |
| `no_real_system_probes` | Replaces `privileges.granted_commands_now`, `is_granted`, `dhcp_interfaces` and `primary_interface` with answers for an ungranted machine; replaces `netdnsmonitor.app.make_log_watcher` and `system_log.make_log_reader` with readers that return nothing | `app.py` calls these without an injected runner, so app-wiring tests would otherwise run `sudo -n -k -l`, `ifconfig -l`, `route -n get default` and `log show`. |

`no_real_system_probes` skips the privilege stubs in `test_privileges.py` and
the log stubs in `test_system_log.py` and `test_log_watcher.py`. Those files test
the real functions with an injected `run_fn`. A test that needs other answers
patches over the stubs, as `test_app_privilege_wiring.py` does.

The probe and the log read run on daemon threads. A thread that starts late can
outlive its test's patch and reach the real function. The stubs return at once,
which keeps that window small; it is not closed.

## What is tested, and where it lives

This section describes the shape of the suite rather than listing every file.
A per-module table went stale before, and did.

**Decision modules** own the interesting logic and are tested directly, with
fakes for anything external. `classifier`, `flap_gate`, `ladder`, `escalation`,
`report`, `status`, `failover_policy`, `service_order`, `console`, `stall_log`,
`ping_monitor`, `localize`, `distribution` and `mini_window.mini_text` are the pure ones;
several need no fakes at all because they touch nothing.

Three modules have **no test file of their own**. `app.py` is covered by the
wiring tests below. `commands.py` is exercised through `test_cli.py` and
`test_cli_console.py`. `credentials_prompt.py` holds modal AppKit dialogs; the app
takes its functions as parameters, and the wiring tests pass fakes, so no test
opens one.

**Effect modules** wrap one external thing and are tested by injecting it:
`prober` (connect and resolve), `dns_query` (UDP socket), `log_watcher` and
`system_log` (`log show`), `repair_executor` (`subprocess.run`, `os.listdir`),
`anthropic_escalator` (the client), `notifications` (HTTP and SMTP transports),
`interface_probe` (the bound connect), `throughput` (resolver and socket factory),
`net_stats`, `ping`, `peer_net`, `privileges`, `router` (`run_fn` and
`exists_fn`; the root script is asserted on as a string), `router_window`,
`credentials` (the Keychain backend), `cli` (`run_fn`, `probe_fn`,
`executor_factory`, `load_config_fn`), and the storage modules (`report_storage`,
`history`, `forensic_log`, `resolution_log`, `peers`, `ai_consent`) against
`tmp_path`.

**Wiring** is the `test_app_*_wiring.py` set: the behaviour that exists only once
`app.py` glues tested modules together. It covers the notification on a fresh
report, the learned-domain probe path that self-prunes, dashboard and console
entry points, ping alerting, privilege prompts, failover, resolution batches,
peers, settings save and reload, the Router menu and Start at Login item, and the
Mac App Store edition (`test_app_appstore_wiring.py` passes `capabilities=`
explicitly). These tests build a real `NetDnsMonitorApp` against a nonexistent
config path and replace its collaborators with fakes.

**AppKit surfaces** are built for real rather than mocked. `NSWindow`
construction works headlessly, and the properties that matter (retain policy,
button wiring, frame arithmetic, pixel output) are exactly the ones that fail
silently in a bundle. `show()` is never called: it would flash a window across
the screen on every run. See `test_dashboard.py`, `test_console_window.py`,
`test_dock_icon.py`, `test_graphs.py`.

**Files that are never run.** `test_router_scripts.py` and
`test_router_configs.py` check the `router/` shell scripts and the `dnsmasq` and
`unbound` configs as text, because the scripts reconfigure pf, launchd and the
network as root. `test_appstore_build.py` loads `scripts/appstore/build_appstore.py`
by path and tests only its pure helpers; it runs no py2app, `codesign` or
`productbuild`.

To regenerate the per-file distribution in `docs/SCRIPTS.md`:

```bash
python3 -m pytest -q --collect-only | grep '::' | sed 's/::.*//' | sort | uniq -c | sort -rn
```

## What the suite cannot cover

Green tests are not evidence for any of this. Each needs the one-shot
invocations in `docs/SCRIPTS.md` or a manual check.

- **The `rumps` run loop.** `App().run()` never returns and needs a GUI session.
  `tick()` and the builders are covered with fakes; the loop is not. Never invoke
  `python3 -m netdnsmonitor.app` from a script or an agent expecting it to
  complete.
- **Whether an AppKit window opens and takes keystrokes.** The window tests cover
  construction and wiring. That a console actually appears, accepts typing, and
  prints output was verified separately by driving `ConsoleWindowController`
  against a live `NSApplication`, not by the suite.
- **`prober.default_resolve` and `prober.default_connect` against a real
  socket.** Always injected, which is what keeps the suite offline.
- **Anything privileged or delivered.** The network-order write, the sudoers
  grant, the router scripts, live Slack and SMTP delivery, and App Store release
  signing. See `docs/known-issues.md` → Unproven.
- **Anything about the real OS's answers.** Three live findings came from exactly
  this gap: macOS masks hostnames in the unified log, the log's own subsystem
  label parsed as a domain, and source-address binding does not pin an interface.
  Fakes agreed with the code in all three cases.

## Coverage standard

The target is meaningful coverage of the important paths, and of every changed or
risky path, with assertions on behaviour. It is not a line-coverage percentage.
The repo runs no coverage tool: `requirements-dev.txt` pins only `pytest` and
`ruff`, and `ci.yml` has no coverage step.

A test counts when it asserts on the result of what it executes. A test that runs
a line without asserting on its result does not count, and reviewing for that is
worth more here than a percentage. A change to a decision path, a side-effect
seam or an outcome string needs a test that would fail if the behaviour changed.

Two properties are worth testing explicitly because they fail silently:

- **Anything that must not block the run loop.** Assert the caller *returned*,
  not that a thread was started. A thread is the implementation; returning is the
  requirement. `test_tick_does_not_wait_for_a_slow_notifier` is the model: block
  the collaborator outright, assert the tick came back, then release.
- **Anything whose failure looks like success.** A repair that silently does
  nothing, a notification that never sent, an unreadable log that reads as "no
  errors". These need an assertion on the reported outcome, not on the absence of
  an exception.
