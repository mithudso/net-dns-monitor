## What and why

<!-- One paragraph: the problem, and why this change is the fix. -->

## Verification

- [ ] `ruff check . && ruff format --check . && python -m pytest -q` passes (count: ___)
- [ ] New or changed behaviour has a test that failed before the change
- [ ] Manual checks for paths the suite cannot reach (menu bar app, router, real network switch), described below
- [ ] Test counts in `docs/SCRIPTS.md` / `docs/TESTING.md` regenerated if tests were added
- [ ] App Store sandbox table re-checked if a subprocess or file path changed

## CLAUDE.md non-negotiables touched

<!-- Name any: None-vs-False, repair honesty, injected side effects, secrets, timer safety, redaction, shared deadline, anti-flap, service order guard, IP_BOUND_IF. -->
