# Code deep optimizer, second run — 2026-10-05

Tracking: TASK-408. Baseline: `6b1280c` (2212 tests). Final: 2521 tests.
The first run is `docs/macos-networking-audit.md` (2026-10-04, TASK-379). It
grouped files into five bundles and deep-read 33 modules. This run fanned out one
read-only diagnostic agent per file, or per small named group, over a 50-file
triage set. Files the first run had not deep-read came first.

## Scope

35 diagnostic dispatch units covered 52 source files: every runtime module the
first run left out of its deep-read set, plus `notifications`, `alert`,
`state_machine`, `flap_gate`, `escalation`, `system_log`, `log_watcher`,
`settings_window`, `dashboard`, `status`, `router_window`, `mini_window`,
`peers`, `localize` and `ai_consent`. `app.py` (3299 lines) had two agents.
One more unit ran the repository-scope passes (M3, T2, T3, T4, cross-file M2).

Not re-read this run: the remaining modules from the first run's deep-read set,
including `cli`, `cli_console`, `commands`, `distribution`, `dock_icon`,
`domain_learner`, `forensic_log`, `graphs`, `history`, `net_stats`,
`query_log`, `report_storage`, `resolution_log`, `resolution_prober` and
`stall_log`. They are the follow-up set for a third run.

## Severity by iteration

| Iteration | Critical | High | Medium | Notes |
|---|---:|---:|---:|---|
| 1 (diagnose) | 0 | 8 | 133 | 112 code/doc rows plus 21 test-gap rows, counted per unit. About 8 rows are the same defect seen from two files (for example, an unencodable domain was found in `config.py`, `prober.py` and `app.py`). |
| 1 (after fixes) | 0 | 0 | 6 BLOCKED, 1 skipped | Every other row is fixed with a regression test, or retracted. |
| 2 (fresh review of the iteration-1 diff) | 0 | 0 | 7 | Defects the fixes introduced or left half-done. All are fixed with tests that failed first. |
| Final | 0 | 0 | 6 BLOCKED | Plus the 3 BLOCKED residuals from the first run. |

## High findings (all fixed)

| Pass | Location | Finding | Fix |
|---|---|---|---|
| C1 | `netdnsmonitor/console.py` `_drain` | Output cut at 64 KB carried no truncation marker, so a 2 MB result looked complete. | Each stream records its dropped bytes. `format_result` marks the truncation and gives each stream its own budget. |
| C1/S3 | `netdnsmonitor/config.py`, `prober.py`, `app.py` tick guard | A configured domain that IDNA cannot encode raised on every tick. The gate never advanced, so the title stayed green while nothing was measured. | `config.domain_problem` refuses such names at load. A tick that raises `failure_threshold` times in a row titles "check failing". |
| C2 | `netdnsmonitor/config.py` | Boolean switches were never type-checked: `failover_enabled: "false"` enabled failover. | Every key with a bool default must be a real bool. |
| C3/S3 | `netdnsmonitor/service_order.py` | `str.splitlines()` also splits on U+2028 and similar separators. A service name containing one was truncated, every guard still passed, and the argv omitted a real service. | The parser splits on `\n` only. Both counterexamples are pinned. |
| C3/S5 | `netdnsmonitor/config.py`, `ping.py`, `app.py` | The config accepted a ping host that `ping_once` refuses. The `ValueError` killed the heartbeat silently, so an outage never alerted. | One `host_problem` predicate is used at load and in `ping_once`. `ping_heartbeat` records a refusal per host and tries the next. |
| C1 | `scripts/start.sh` | It printed "escalation enabled" from the shell environment, but `open -n` does not pass that environment to the app. | The text now says the value applies to this shell only and points to the Keychain. |
| C1 | `router/scripts/enable_nat.sh` | Under `pipefail`, the wait-for-default-route loop exited on its first iteration and printed nothing. | `\|\| true` inside the substitution. A stubbed-loop test covers it. |

The Medium rows are in the per-unit notes and in each fix's regression test.
Grouped by theme:

- **None is not False.** Each case below now reports "not probed" or
  "inconclusive" instead of a failure:
  - A recheck that raised was reported as `recheck_ok False`.
  - Abandoned resolution lookups were counted as failing.
  - Ping exit 68 sends no echo but counted as packet loss.
  - Absent interfaces, ENXIO and EMFILE were reported as dead links.
  - Unencodable DNS names returned `False`.
  - `sandbox_probe` turned every error into a refusal.
  - Peer junk values became definite booleans.
- **Never claim what did not happen.** Each case below now reports what
  actually happened:
  - A HUP sent to mDNSResponder was reported as "restarted".
  - A timed-out repair was reported as "requires privilege".
  - A timed-out `ipconfig set` was reported as failed when the true state is
    unknown.
  - "Granted." printed after a re-probe that showed nothing was granted.
  - A non-https Slack URL was reported as "in use now".
  - The store build offered settings it cannot apply.
  - `install.sh`, `unbound/install.sh`, `test_router.sh` and the service
    script made success claims without checking.
  - The cooldown reason said "since the last switch" after a refused write.
- **Privilege and parsing safety.**
  - `sudo -l` parsing accepted a second runas column and negated commands.
  - `\d` matched non-ASCII digits in sudoers interface names.
  - The `includedir` guard was unanchored.
  - The router accepted a /0 netmask or a public LAN address, and could take
    over the default-route interface.
  - Stop forced IP forwarding off.
  - The NAT helper was replaced non-atomically.
  - The NAT installer did not refuse while the app's router was live.
- **Failures that left no trace.** Failed Slack and email deliveries, osascript
  exit codes, a dead ping worker, and Keychain read errors are now visible.
  Keychain errors show as `unreadable (OSStatus N)` instead of "not set".
- **Robustness.**
  - The failover state file loader now catches `OverflowError` and
    `RecursionError`, as does `peers.load_record`.
  - A CLI switch made mid-attempt was clobbered by the app's stale record.
  - DNS replies with a wrong transaction id ended the receive early.
  - The console leaked a child process when a reader thread failed to start.
  - A child that escaped the session held the console for its whole life.
  - `__CLEAR__` in command output wiped the transcript.
  - A peer could flood the registry from one source address.
  - Throughput readings from tiny samples, and duplicate measurements of one
    device, are fixed.
  - The indexer deleted chunks before the upsert. The watcher had no debounce,
    and it now runs handlers one at a time.
  - Rotation changed the journals' file mode.
  - The release build validated its inputs only after a full py2app run.
- **Escalation.**
  - The fallback model was `claude-sonnet-5`. It is now `claude-sonnet-5-5`.
  - A refusal, an empty response or a `max_tokens` stop was presented as a
    diagnosis.
  - The probe and ladder fields in the outbound bundle were unbounded.

## BLOCKED (owner decision)

Owner answers on 2026-10-05 (TASK-416): the console now strips the three
credentials; `netdns ladder` exits 3 for a partial outcome; the app router
starts bootpd with `launchctl load -F`, so DHCP never stays enabled across a
reboot; the Settings note lists four keys plus a count and keeps its full text
in a tooltip. The "62 keys need a restart" report came from a Sep 17 build that
predates the changed-keys comparison. The connection-refused question is still
open, and the indexer watcher stays running.

| Location | Question |
|---|---|
| `netdnsmonitor/interface_probe.py:93` | Should a TCP RST (connection refused) through the interface count as "reachable"? `prober.default_connect` treats refusal as a failure, so the two stay consistent today. |
| `netdnsmonitor/console.py` `child_env` | Should the shell console strip `ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL` and `SMTP_PASSWORD` from child processes? A test pins pass-through today. |
| `netdnsmonitor/cli.py:55` `LADDER_FAILURE_PREFIXES` | Should `NOT_AUTOMATED:` and the new `unknown:` outcome make `netdns ladder --repair` exit non-zero? |
| `netdnsmonitor/router.py` | Should the router use `launchctl load -F`/`unload` instead of `-w`, which writes the persistent override? This cannot be verified offline. |
| `netdnsmonitor/settings_window.py` status label | The label is 260x30 and probably clips long messages. This needs a GUI check. |
| `scripts/net-dns-monitor-service` | A recorded bundle path outranks the script's own checkout `dist/`. That order is documented, so the script now prints the origin rather than changing it. |

Skipped as a feature: a configurable DHCP DNS server list for the app router.
Left as Low: escalator response blocks without a `type` attribute are now
ignored, which affects test doubles only.

The first run's three residuals remain:
- `app.py::_tick` runs the synchronous incident pipeline.
- libc resolver workers cannot be cancelled.
- `stall_log` seeding and retention (TASK-335).

## Verify gate

| Command | Baseline | Final | Verdict |
|---|---|---|---|
| `.venv/bin/ruff check .` | clean | clean | PASS |
| `.venv/bin/ruff format --check .` | clean | clean | PASS |
| `.venv/bin/python -m pytest -q` | 2212 passed | 2521 passed | PASS |
| `.venv/bin/python scripts/check_docs.py --collect-tests` | pass | pass | PASS |
| `bash -n` on every edited shell script | n/a | clean | PASS |
| Leak check: full suite with a recorder on `rumps.notification` | 9+ tests posted real banners | 0 | PASS |

The local `.venv` is Python 3.14.7. CI runs 3.13 on macOS.

## Found during the run: the test suite posted real alerts

The owner reported "network failed" banners while the network was healthy. A
spy run showed that at least 9 app-wiring tests drove fake outages through the
real `alert` module, so every full `pytest` run posted real macOS
notifications. `tests/conftest.py` now stubs `rumps.notification` for every
test (KNOW-409).

## Disclosures

- **Off-machine traffic.** While probing `config.py`, one diagnostic agent sent
  two ICMPv6 echo requests to `2001:4860:4860::8888`. Two agents' probes ran
  local resolver lookups: `example.invalid.` and `-f`/`ip6-localhost`.
  - The `config.py` agent ran Keychain read, delete and update calls against
    a unique service name that held no item.
  - The repo-scope agent queried OSV.
  - No other traffic left the machine.
- **Stash incidents.** Two fix agents ran `git stash`/`git stash pop` in the
  shared checkout, and the coordinator ran one stash by mistake. Each pop
  restored cleanly, and the final file set matches the assigned owners.
  - One agent's extra `pop` attempts conflicted with the unrelated
    `docs/scripts-manual` stash and aborted. That stash is still intact.
  - Seven stray `patch*.py` scripts appeared in the repository root during
    that window. They were moved out and are not committed.
- **Test-first gaps.** Several fix agents wrote tests together with the fix
  instead of watching them fail first. Every new test passes. The scratch
  counterexample files had shown the defects failing before the fixes.
- **Not verified live.** Nothing here was checked against the running app: no
  privileged write, no launchd change, no NAT, and no Slack or SMTP delivery.

## Pass coverage

All 18 fix-track passes ran for every dispatch unit. Passes that do not apply
to a unit are recorded as N/A in that unit's notes, for example T4 on non-test
files and M3 on leaf modules. M3, T2, T3 and T4 also ran at repository scope:
- **Architecture:** decision modules import no `socket` or `subprocess`. The
  only import cycle is the lazy `cli` ↔ `cli_console` one.
- **Dependencies:** 38 of 39 pins are clean on OSV. `chromadb==1.5.9` has 8
  server-side advisories with no fixed version. This repo uses the embedded
  client, in dev tooling only.
- **Tooling:** tool pins agree across files. shellcheck is absent from CI.
- **Test speed:** no real sleeps could be replaced with fakes, and xdist would
  save about 20 s.

Status: CONVERGED. Every actionable row is closed. Six rows are BLOCKED on owner
decisions, so the run cannot exit CLEAN, and the blind re-audit was not required.
Iteration 3 was a self-review of the small round-2 delta, not an independent pass.

## Rollback

```
cp -R /Users/mitch/.claude/skill-consolidation/backups/code-deep-optimizer-net-dns-monitor-20261005-000312/. /Users/mitch/dev/net-dns-monitor/
rm /Users/mitch/dev/net-dns-monitor/tests/test_app_audit_fixes.py /Users/mitch/dev/net-dns-monitor/tests/test_record_demo.py /Users/mitch/dev/net-dns-monitor/tests/test_sandbox_probe.py /Users/mitch/dev/net-dns-monitor/tests/test_shell_scripts.py
```

Alternatively, `git revert` the commit that adds this file.
