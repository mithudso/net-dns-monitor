# CLAUDE.md — net-dns-monitor

Instructions for agents working in this repository. Read before changing code.

## What this is

A macOS menu-bar app that watches network and DNS connectivity, runs an offline
troubleshooting ladder when something breaks, optionally fails over to a backup network,
escalates to Claude when the ladder cannot resolve it, writes an IT-ready incident
report, and alerts Slack/email. Python 3.13, stdlib-first, `rumps` for the menu bar.

**The danger here is a confident wrong diagnosis, not a lost trade.** This app tells a
human what is wrong with their network. A report that misattributes a DNS failure to the
network — or claims a repair worked when it silently did nothing — is worse than no
report, because someone will act on it.

## Non-negotiables

1. **Never claim a repair that did not happen.** `flush_dns_cache` returns `partial` when
   `dscacheutil` succeeds but the `mDNSResponder` HUP fails, because that is what
   happened. Two other repairs return `NEEDS_PRIVILEGE` and do nothing. Do not collapse
   these into "ok" — see `repair_executor.py`. The failover switch goes further and reads
   the service order *back* before claiming anything, because `networksetup` can exit 0
   without changing a thing; an unconfirmable switch is reported `failed:`, never `ok:`.
2. **`None` is not `False`.** In probe results, `None` means *not probed*; `classify`
   maps a `None` in either load-bearing field to `unclassified` rather than guessing. A
   change that makes an unknown look like a healthy or a failed reading is a correctness
   bug, not a simplification. An absent network interface is `None` for the same reason —
   an unplugged cable is not a dead link, and saying so sends someone after the wrong
   fault.
3. **The engine does not touch the network — the injected callable does.** Every side
   effect (probe, subprocess, LLM call, SMTP, webhook) enters as a parameter with a real
   default. That is what makes the whole decision surface testable offline; the test
   suite opens no sockets. Do not import `socket`/`subprocess` into a decision module.
   `failover_policy.py` and `service_order.py` are decision modules and must stay clean.
4. **No secret in a return value, a report, or an error string.** The Slack webhook URL
   *is* a credential, and `urllib`'s exception text can embed the full request URL.
   Credentials come from the environment (`ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL`,
   `SMTP_PASSWORD`), never `config.yaml`, and error paths return a status code or an
   exception *class name* — never the exception message from an auth failure.
5. **Nothing may raise into the rumps timer.** `tick()` is a timer callback; an escaping
   exception kills monitoring for the rest of the session, silently. It is wrapped, and
   the recovery path is wrapped too. Anything called from a tick must fail as data.
6. **Every outbound path is redacted; the on-disk report is not.** `sensitive_strings`
   is applied to the LLM bundle and to the notification text. The report keeps raw probe
   results and log excerpts because it stays on the machine — so never copy report
   internals into a notification or a prompt.
7. **All domain lookups in a tick share one deadline.** Sequential per-domain timeouts
   made the UI block additive (~42s with a full learned list). And note
   `socket.setdefaulttimeout()` does **not** bound `socket.getaddrinfo` — that timeout
   was inert until the lookup moved onto a worker thread. The same rule governs the
   failover path: a healthy tick that has never failed over must spend **zero**
   subprocesses and zero probes, which is what the `original_order` gate buys.
8. **The anti-flap gate owns "how many notifications".** A report — and therefore an
   alert — fires only on the healthy→incident edge. Do not add a rate limiter; do not
   fire on every failing tick.
9. **`-ordernetworkservices` rewrites the service order to exactly the list it is
   given.** A name dropped from that list is a network service deleted from the system.
   Every order is checked by `is_order_intact` — same length, same set, no duplicates,
   nothing that looks like a flag — before it can reach the command, and refusing is
   always the safe answer. Never build that argv list anywhere but `service_order.py`,
   and never bypass the guard, including on the manual-switch path.
10. **Interface-bound probing uses `IP_BOUND_IF`, not source-address binding.** On Darwin
    the route lookup follows the destination, so a socket bound to the Wi-Fi address
    still leaves through whichever interface owns the route — the obvious implementation
    silently measures the wrong path. `IP_BOUND_IF` is 25, `IPV6_BOUND_IF` is 125; both
    are in Darwin's headers and were confirmed against live interfaces.

## Before you claim a change works

```bash
python3 -m pytest -q                      # 1079 tests, offline, ~25s
```

There is **no `scripts/check_docs.py`** in this repo, despite what earlier revisions of
this file claimed. Nothing machine-checks doc drift, so the test counts in
`docs/SCRIPTS.md` (four places, plus a per-file table) must be regenerated by hand from
`python3 -m pytest -q --collect-only | grep -c '::'` whenever tests are added. Stale
counts have shipped twice for exactly this reason.

Then exercise the paths the suite cannot, using the one-shot invocations in
`docs/SCRIPTS.md` — the prober, the ladder's read-only checks, the log watcher, the
domain learner and the failover dry run all behave differently against the real OS than
against fakes. Three live findings came from exactly that: macOS masks hostnames in the
unified log, the log's own subsystem label parsed as a domain, and source-address
binding does not pin an interface.

**Loading the menu bar app cannot be automated.** `rumps.App().run()` never returns and
needs a GUI session, so `python3 -m netdnsmonitor.app` is a manual check. Do not claim
it as verified, and never invoke it from a script or an agent expecting completion.

## House style

**Python** — 3.13, stdlib-first. `requirements.txt` is four lines and stays that way:
`rumps`, `anthropic`, `PyYAML`, `pytest`. Do not add `requests` for something
`urllib.request` does, and do not add a Slack or SMTP SDK. Type hints throughout.
Tests are `pytest` with plain functions, fakes injected as callables — no
`unittest.mock` patching of module internals unless there is no seam.

**Comments explain *why*, especially where the obvious implementation is wrong.** The
load-bearing examples: the inert `setdefaulttimeout`, the bracket-stripped log line, the
`quit()`-then-`close()` SMTP fallback, the control domain's role in pruning, the clamp on
the learn interval, why source-address binding does not work, and why the pre-failover
order is written before the switch rather than after it succeeds. Do not narrate *what*.

**Do not overclaim in a comment either.** A docstring here once said the `None`/`False`
split stopped the policy layer mistaking a missing interface for a broken one; it did
not — both refuse the same switches, and the split is about what gets *reported*. A
comment that is wrong about why is as expensive as code that is wrong.

## Known-unverified areas

- **The privileged network-order write has never been executed.** `networksetup
  -ordernetworkservices` is covered only by fakes. Adjacent evidence says it will work
  unprompted on this machine — `scselect -n` wrote to root-owned `preferences.plist`
  from a non-root admin account with no password prompt, using the same
  `system.services.systemconfiguration.network` right — but that is a prior, not proof.
  The menu bar's "Switch to backup now" button is the intended way to find out.
- **No live Slack or SMTP delivery has been confirmed.** Both channels are covered by
  tests with injected transports; neither has been observed delivering a real message.
- **Auto-learned domains find nothing on a stock macOS install** — the unified log masks
  hostnames. Measured: 758 error-like lines, 198 explicitly masked, 0 learnable domains.
  Do not present the feature as working without stating that.
- **`log_watcher` returns `[]` on subprocess timeout**, which is indistinguishable from
  "no errors found". A 30m `log_lookback` measured 10.15s against a hardcoded 10s
  timeout, so raising the lookback silently produces empty evidence.
- **Two of the four repairs do nothing** (`renew_dhcp_lease`, `toggle_network_service`).
  A real fix needs an `SMAppService` privileged helper that does not exist.
  `switch_to_backup_network` is the exception: it is genuinely attempted, and reports
  `NEEDS_PRIVILEGE` only when the write is actually refused.
- **The four diverged worktrees have been reconciled** into this line
  (`.claude/worktrees/dns-resolution-monitor`), which is what the installed
  `~/Applications/Net-DNS-Monitor.app` is now built from. `master` and
  `docs/scripts-manual` are behind it and are not what runs. Reports on this machine
  predating the reconcile were produced by an older tree, so check the report's date
  before concluding the current code behaves the way it suggests.
- **Two consoles were merged into one.** The GUI console is the arbitrary-shell one
  (`console.py` + `console_window.py`), reachable from the menu bar and from the
  dashboard button, both going through the single controller at `App.console`.
  `cli_console.py` is a separate thing: the REPL behind `netdns console`, a terminal
  surface over the `commands.py` catalogue. Do not merge them; they answer different
  questions.

## Related

`AGENTS.md` points here. `docs/SCRIPTS.md` is the operator's manual for every entry
point; `docs/ARCHITECTURE.md` is the shape of the system; `docs/known-issues.md` is the
current defect list.
