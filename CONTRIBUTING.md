# Contributing

Thanks for helping. This app tells people what is wrong with their network, so
a confident wrong answer is the worst bug it can have. Read
[CLAUDE.md](CLAUDE.md) before writing code; its non-negotiables apply to human
contributors too.

## Set up

```bash
python3.13 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt -c constraints.txt
```

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers the rest.

## Before opening a pull request

```bash
.venv/bin/ruff check . && .venv/bin/ruff format --check . && .venv/bin/python -m pytest -q
```

- Add a test that fails without your change. Tests are plain pytest
  functions, and side effects are injected as callables.
- If you add or remove tests, regenerate the counts in `docs/SCRIPTS.md` and
  `docs/TESTING.md`. Get the total with
  `python -m pytest -q --collect-only | grep -c '::'`.
- Anything the suite cannot exercise (the menu bar app, the router, a real
  network switch) needs a manual check, described in the PR.
- If you touch a subprocess or file path, rebuild the Mac App Store probe
  (`scripts/appstore/build_appstore.py adhoc --with-probe`) and check the
  feature table in `docs/APP_STORE_SUBMISSION.md`.

## Reporting security issues

See [.github/SECURITY.md](.github/SECURITY.md). Please don't file them as
public issues.
