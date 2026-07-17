# Known issues

## By design (not bugs)

- **DNS cache flush is only partial.** `dscacheutil -flushcache` runs
  unprivileged fine; `killall -HUP mDNSResponder` fails because
  mDNSResponder runs as a different user and rejects a signal from a
  process that doesn't own it. Confirmed empirically. `repair_executor.py`
  reports this outcome as `"partial: ..."` rather than a false `"ok"`. See
  `README.md` → Honest scope.
- **Privileged repairs are stubbed.** `renew_dhcp_lease` and
  `toggle_network_service` return `NEEDS_PRIVILEGE: ...` instead of running,
  because a sandboxed menu-bar app can't perform them. Fixing this needs a
  privileged `SMAppService` helper — not implemented in this MVP.
- **`app.py` has no automated test coverage.** It's a thin `rumps` shell that
  needs a real macOS run loop; all decision logic it wires together is
  tested in the modules it calls.
- **No auto-detection of "sites you care about."** `domains` in the config
  starts empty by design — the app won't read browser history to guess.

## Gaps / TODO

- No CI workflow yet (no `.github/workflows/`) — tests are run locally only.
- No `.env.example` — the only env var is `ANTHROPIC_API_KEY`, documented in
  `docs/DEVELOPMENT.md` instead since it's a single optional key with no safe
  placeholder value to demonstrate.
- No packaged `.app` bundle / installer — run via `python -m
  netdnsmonitor.app` from a checked-out clone only.
