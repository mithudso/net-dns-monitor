# Testing

## Strategy

Every decision module has a matching test file with all external effects
(network, subprocess, the Anthropic API, the filesystem clock) injected as
fakes — no test hits a real network, spawns a real macOS subprocess, or
calls the real Anthropic API.

| Module | Test file | What's faked |
|---|---|---|
| `classifier.py` | `test_classifier.py` | pure function, nothing to fake |
| `flap_gate.py` | `test_flap_gate.py` | pure state, nothing to fake |
| `ladder.py` | `test_ladder.py` | pure data, nothing to fake |
| `dns_query.py` | `test_dns_query.py` | UDP socket |
| `prober.py` | `test_prober.py` | TCP connect + DNS resolution |
| `log_watcher.py` | `test_log_watcher.py` | `log show` subprocess |
| `repair_executor.py` | `test_repair_executor.py` | `subprocess.run`, `os.path.isdir`, `os.listdir`, the DNS query fn |
| `escalation.py` | `test_escalation.py` | pure function, nothing to fake |
| `anthropic_escalator.py` | `test_anthropic_escalator.py` | the Anthropic client |
| `report.py` | `test_report.py` | pure builder, nothing to fake |
| `report_storage.py` | `test_report_storage.py` | filesystem writes (tmp dir) |
| `status.py` | `test_status.py` | pure function, nothing to fake |
| `state_machine.py` | `test_state_machine.py` | prober, repair_executor, escalator, log_watcher — all four injected |
| `config.py` | `test_config.py` | filesystem read (tmp dir) |
| `app.py` | `test_app_status_wiring.py` | partial — only the status-wiring glue is tested; the `rumps` run loop itself is not |

`app.py` is the one module without full coverage: it's thin wiring over the
tested modules above and needs a real macOS run loop to exercise fully. Keep
it that way — new decision logic belongs in a testable module, not in
`app.py`.

## Running tests

```bash
source .venv/bin/activate
python -m pytest -v
```

Config: `pytest.ini` points `testpaths` at `tests/`, collecting `test_*.py`.

## Coverage target

No numeric line-coverage gate is enforced (no CI in this repo yet — see
`docs/known-issues.md`). The standard instead: every module in the table
above with "what's faked" listed has real behavioral assertions on its
public functions, not just import/smoke checks. When adding a module, add
its test file in the same commit, following the injected-fake pattern of the
nearest existing test.

## Adding a test

1. Identify the external effect(s) the new code touches (subprocess,
   network, filesystem, API).
2. Take each as a parameter with a real-implementation default (see
   `make_repair_executor`'s `run_fn: RunFn = subprocess.run` pattern).
3. In the test, pass a fake/stub for that parameter and assert on the
   returned value or on calls made to the fake.
