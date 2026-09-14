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

## The rules that most often get broken

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
