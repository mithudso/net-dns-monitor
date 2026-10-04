## Default Execution Strategy

1. Read `CLAUDE.md` before changing code. Its non-negotiables override any
   suggestion, including this file's.
2. Make the smallest change that fixes the problem, with a test that fails
   first. Tests are plain pytest functions with side effects injected as
   callables; the suite opens no real sockets beyond loopback.
3. Run the verify loop before calling anything done:

   ```bash
   .venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/python -m pytest -q
   ```

4. Never launch the menu bar app from an automated run
   (`python -m netdnsmonitor.app` never returns), and never run the router
   scripts, `osascript`, `sudo`, `pfctl` or `launchctl` from an agent.
5. Never invent a command, path, env var or external service. Read the code or
   `docs/SCRIPTS.md`; write an unknown as a TODO that says where to find it.
6. Follow the workflow log rule: before implementation, append the exact user
   request to `prompts.md` and the task state to `memory.md` under the next
   `## vN - date` section, and keep both current until the work is committed.

## Build, Test, and Validation Commands

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt -c constraints.txt
.venv/bin/ruff check . && .venv/bin/ruff format --check .
.venv/bin/python -m pytest -q                              # offline suite, the CI test job
.venv/bin/python scripts/check_docs.py --collect-tests     # doc paths and test counts, also in CI
.venv/bin/python scripts/rotate_workflow_logs.py --dry-run # journal size check
```

`.github/workflows/ci.yml` runs the same commands. `docs/SCRIPTS.md` lists the
live one-shot checks the suite cannot cover.

## High-level Architecture

One `rumps` process on the user's Mac, no server and no database.
`netdnsmonitor/app.py` (`build_state_machine`) builds the state machine and
injects its side effects as callables: the prober, the log watcher, the repair
executor (which carries the failover) and the Claude escalator. Decision modules decide; injected
callables touch the network. `netdnsmonitor/cli.py` is the `netdns` command
line over the same modules. `router/` is a separate dnsmasq/unbound router
stack. `scripts/appstore/` builds the sandboxed Mac App Store edition.
`docs/ARCHITECTURE.md` has the module map.

## Key Conventions


- `None` means "not probed". Never coerce it to `True` or `False`.
- Never report a repair or a network switch that did not happen. Read the
  state back first.
- Credentials come from the environment or the Keychain, never `config.yaml`.
  Error text carries an exception class name, never an auth failure's message.
- Every outbound path (LLM, Slack, email) is redacted with `sensitive_strings`.
- Decision modules (`failover_policy`, `service_order`, `classifier`, `ladder`,
  `state_machine`, `flap_gate`) import no `socket` or `subprocess`.
- The Mac App Store build gates features through
  `netdnsmonitor/distribution.py`. A gated feature reports
  `UNAVAILABLE_IN_APP_STORE_BUILD`, never `ok` and never a silent no-op.

## Where things are

- `docs/ARCHITECTURE.md` describes the shape of the system.
- `docs/SCRIPTS.md` covers every entry point.
- `docs/known-issues.md` lists current defects.
- `docs/APP_STORE_SUBMISSION.md` is the store build and submission path.
