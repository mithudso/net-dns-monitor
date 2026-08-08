# Development

## Prerequisites

- **macOS.** The app shells out to `dscacheutil`, `killall`, `scutil`,
  `netstat`, `networksetup`, `route` and `log show`, draws a menu bar item and
  a Dock tile through AppKit, and pins sockets with Darwin's `IP_BOUND_IF`. It
  does not run on Linux or Windows.
- **Python 3.13.** Stdlib-first. `requirements.txt` carries exactly four runtime
  dependencies — `rumps`, `anthropic`, `PyYAML`, `pyobjc-framework-Cocoa` — and
  stays that way. Do not add `requests` for something `urllib.request` does, and
  do not add a Slack or SMTP SDK. All four are **pinned exactly**, not floored:
  `scripts/start.sh` re-runs `pip install -r` on every start, so a range would
  freeze different versions into two people's bundles.
- **Test and lint tooling lives in `requirements-dev.txt`** (`pytest`, `ruff`),
  never in `requirements.txt`. `pytest` used to be a runtime dep, which meant
  `start.sh` installed it onto every end user's machine.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt   # pulls requirements.txt in, adds pytest + ruff

mkdir -p ~/.config/net-dns-monitor
cp config.yaml ~/.config/net-dns-monitor/config.yaml
```

`config.yaml` in the repo root is the **shipped default**, not a sample — two
tests enforce that every key `load_config` reads appears in it with its real
value, and that every key has a field in the settings window. There is no
`config.example.yaml`; it was removed so the two could not drift apart.

Optional credentials, none of which belong in `config.yaml`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # enables LLM escalation
export SLACK_WEBHOOK_URL=https://...  # enables the Slack channel
export SMTP_PASSWORD=...              # if the mail relay authenticates
```

For a Slack incoming webhook the URL *is* the credential, which is why it lives
in the environment and is never echoed back in an error message. Email also
needs a non-empty `email_recipients` in the config; with an empty list that
channel stays inactive.

## Running

Three ways, for three purposes.

```bash
./scripts/start.sh                    # foreground, as a real .app bundle
./scripts/install.sh                  # build + install + LaunchAgent (idempotent)
python3 -m netdnsmonitor.cli --help   # the CLI; no GUI needed
```

`start.sh` is the development loop. `install.sh` is also the upgrade path after
a `git pull` — it rebuilds the bundle with py2app, reinstalls the LaunchAgent,
and **takes a running monitor down and back up**, so pick the moment.

```bash
net-dns-monitor-service status   # is it running, is it ticking
net-dns-monitor-service logs     # recent output
net-dns-monitor-service restart  # after editing config.yaml
```

Anything read once at startup — timer intervals, thresholds, the notifier, the
failover services — needs a restart. The settings window marks those fields.

**Loading the menu bar app cannot be automated.** `rumps.App().run()` never
returns and needs a GUI session, so `python3 -m netdnsmonitor.app` is a manual
check. Do not claim it as verified, and never invoke it from a script or an
agent expecting completion.

## Testing

The full gate, which is what CI runs:

```bash
ruff check . && ruff format --check . && python3 -m pytest -q
```

`ruff` is not optional here — the lint config selects `BLE` deliberately so the
`# noqa: BLE001` markers keep meaning something, and each one marks a place
where swallowing an exception is the considered choice.

See `docs/TESTING.md` for the strategy and for what the suite deliberately does
not cover. Then exercise the paths it cannot, using the one-shot invocations in
`docs/SCRIPTS.md` — the prober, the ladder's read-only checks, the log watcher,
the domain learner and the failover dry run all behave differently against the
real OS than against fakes.

## Workflow

- **Test-first.** Add or adjust a `tests/test_*.py` case before changing
  behaviour in the module it covers.
- **Keep `app.py` thin.** It is wiring. New decision logic belongs in a module
  the suite can reach; an `if` added to `app.py` or to an AppKit shell is an
  `if` nothing tests.
- **Inject external effects.** New code that shells out, hits the network or
  calls an API takes that dependency as a parameter with a real default. Every
  `make_*` factory in the codebase is the pattern.
- **Comments explain *why*, especially where the obvious implementation is
  wrong.** The load-bearing examples: the inert `setdefaulttimeout`, the
  bracket-stripped log line, the `quit()`-then-`close()` SMTP fallback, the
  control domain's role in pruning, the clamp on the learn interval, why
  source-address binding does not pin an interface, and why the pre-failover
  order is written before the switch rather than after it succeeds. Do not
  narrate *what*.
- **Do not overclaim in a comment either.** A wrong explanation of *why* costs
  as much as wrong code, and is harder to notice.

## The rules that are not style

Five things in `CLAUDE.md`'s non-negotiables have bitten this codebase already.
In short: never claim a repair that did not happen; `None` is not `False`;
decision modules import no `socket` or `subprocess`; no credential reaches a
return value, a report or an error string; and nothing may raise into a rumps
timer, because an escaping exception kills monitoring for the session silently.
Read that section before changing a repair path, a probe result, or a tick.

## Env vars

| Var | Required | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | No | Enables LLM escalation. Omitted, escalation is skipped and the report is still written. |
| `SLACK_WEBHOOK_URL` | No | Enables the Slack channel. The URL is the credential. |
| `SMTP_PASSWORD` | No | Only if the relay authenticates. |

## Troubleshooting

- **No menu bar icon.** `rumps` needs a GUI session — run from a real Terminal,
  not over SSH.
- **`log show` empty or permission-denied.** Grant Full Disk Access to the
  terminal or to the app in System Settings → Privacy & Security. An empty read
  is indistinguishable from "no errors found"; see `docs/known-issues.md`.
- **DNS flush reports `partial`.** Expected without the privilege grant. See
  `docs/known-issues.md`.
- **Failover says both links are unreachable while the network works.** Also
  expected on a machine with a VPN tunnel up, and explained in
  `docs/known-issues.md` → Confirmed limitations.
- **Config edit did nothing.** Most keys are read once at startup;
  `net-dns-monitor-service restart`.
