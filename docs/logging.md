# Logging and observability

The app does not log through Python's `logging` module. It keeps evidence in
files it owns, and it writes a small set of lines to stderr. This page lists
each record, when it is written, what it may contain, and where it lives in
each build.

Checked against the working tree on 2026-09-14, at commit `a6aab33`.

## The one `logging` call site

`netdnsmonitor/router.py` creates `log = logging.getLogger(__name__)` and calls
`log.info` twice: when the router starts and when it stops. No module in
`netdnsmonitor/`, `scripts/` or `tests/` calls `logging.basicConfig` or adds a
handler. Python's last-resort handler prints only `WARNING` and above, so both
`log.info` records are dropped. If you need those lines, print them or add a
handler; do not assume they reach the launchd log.

## Records on disk

Every path below is a config key with a default under
`~/Library/Application Support/net-dns-monitor/`. `load_config` expands `~` on
every read.

| Record | Writer | When it is written | Bound |
|---|---|---|---|
| Incident report, `<reports_dir>/<started_at>.json` and `.md` | `report_storage.save_report` | Once per incident, on the healthy-to-incident edge of the anti-flap gate. Recovery writes nothing. | None. One pair per incident. |
| Forensic journal, `forensic_log_path` (`forensic-log.jsonl`) | `ForensicRecorder._append_journal` | Each event as it happens: `down`, `up`, `step`, `observation`, `recheck`, `escalation`. | Before an append, if the file is larger than 50 MiB (`MAX_JOURNAL_BYTES`), it is renamed to `<path>.1`. One previous generation is kept. |
| Episode documents, `<forensic_episodes_dir>/<started_at>-episode.json` and `.md` | `ForensicRecorder._write_episode` | When an episode closes: pings answer again and the gate is not in `incident`. | At most 5000 `observation` events per episode (`MAX_EPISODE_OBSERVATIONS`). The document states how many were omitted; the journal keeps all of them. |
| Resolution log, `resolution_log_path` (`resolution-log.jsonl`) | `resolution_log.append_resolution_findings` | After each stalled-domain batch that produced findings (every `resolution_interval_seconds`, 300 s). One `checked_at` per batch. | Compacted after 50,000 lines to one completed record per domain: the slowest elapsed time with the newest completed `checked_at`. Abandoned records are dropped. The selector streams the file each batch; retained size scales with distinct historical domains, so 50,000 is a trigger, not a hard limit. |
| Heartbeat history, `history_path` (`history.jsonl`) | `SampleHistory._persist` | Every ping heartbeat (5 s). | Rewritten to the last `history_max_samples` (720) when the file holds more than twice that. Write failures are silent by design. |

State files, written with `report_storage._atomic_write` (temp file, then
`os.replace`, mode 0600):

| File | Writer | Content |
|---|---|---|
| `peers.json` (`peer_record_path`) | `peers.save_record` | Known LAN peers. Saved on each `peer_tick` and at most every 30 s from the UI tick. |
| `learned_domains.json` (`learned_domains_path`) | `LearnedDomainStore` | At most `max_learned_domains` (20) names. |
| `failover.json` (`failover_state_path`) | `FailoverStore.save` | The pre-failover service order, switch times, the service this app enabled, and whether automatic failback is paused by a manual switch. |
| `ai-consent.json` | `ai_consent.ConsentStore` | Consent record. Only the store build constructs the store. |
| `<config path>.bak-<epoch>` | `settings_window.save_config` | A copy of `config.yaml` taken before the Settings window writes it. |

What the on-disk records contain:

- Reports and episode documents keep raw probe results, raw log excerpts and
  step outcomes. They are not redacted, because they stay on the machine.
- The forensic `down` event for a gate incident carries
  `probe results: {...}` in its `detail` field, unredacted.
- A report's `escalation` field holds either Claude's analysis or an error of
  the form `<Class> (HTTP N)`.

## Records kept in memory only

| Record | Where it shows |
|---|---|
| `system_log.LogBuffer` (at most `log_view_max_entries`, 3000) | The dashboard log pane. Never written to disk. |
| `NetDnsMonitorApp.last_tick_error` | `status.build_status_report` prints it as `last tick error: ...`. The tick guard stores `<Class>: <message>`. A failed report save stores `report not saved: <Class>`, and a failed resolution batch stores `resolution batch failed: <Class>`. |
| `ForensicRecorder.journal_error` | The class name of the latest failed journal append, or `None` after a success. No window, menu or CLI reads it today. |
| `NetDnsMonitorApp.last_notification_results` | Per-channel delivery results (`delivered`, or an `error` string). |

## The no-evidence line

`log_watcher.make_log_watcher` never returns `[]` for a log it could not read.
It returns one line that starts with `NO_EVIDENCE_PREFIX` (`[net-dns-monitor]`):

| Cause | Line |
|---|---|
| `log show` exceeded 10 s | `[net-dns-monitor] no log evidence: log show timed out after 10s (lookback <log_lookback>)` |
| Nonzero exit | `[net-dns-monitor] no log evidence: log show exited N` |
| Missing binary, decode error, other subprocess error | `[net-dns-monitor] no log evidence: log show failed: <Class>` |
| Mac App Store build | `[net-dns-monitor] UNAVAILABLE_IN_APP_STORE_BUILD: reading the system log is not available ...` (from `app.unified_log_unavailable_watcher`) |

`[]` means `log show` ran and no line matched. The line goes into the report's
`log_excerpts` and into the escalation bundle. `domain_learner` skips lines
with the prefix.

## stderr

Lines the app writes to stderr on purpose:

| Line | Source | How often |
|---|---|---|
| `[alert] Ping to <host> failed -- <error>` and `[alert] Ping to <host> recovered` | `alert._log` | On each alert edge. |
| `[forensic] cannot append to journal <path> (<Class>); further failures are not printed until an append succeeds` | `ForensicRecorder._append_journal` | Once per failure edge. `journal_error` latches until an append succeeds. |
| `[peers] discovery unavailable: <error>` | `NetDnsMonitorApp._start_peer_network` | Each `peer_tick` whose UDP bind fails (every `peer_announce_seconds`). `<error>` is `str(exc)`. |
| `<action_id> raised <Class>` plus stack frames | `dashboard._report_action_failure` | When a dashboard click handler raises. The exception message is not printed. |
| `Net-DNS-Monitor could not start: <problem>` and `Config file: <path>` | `app.main` | When the config does not load. `<problem>` is `ConfigError: <message>` for a `ConfigError`. For a `ValueError`, `TypeError`, `OSError` or YAML error it is the class name only. |
| Tracebacks | `traceback.print_exc()` in `app.py`, `alert.py`, `peer_net.py`, `settings_window.py` | When a guarded worker or callback raises. A traceback includes the exception message. |
| `config error: <exc>` | `cli.main` | When the CLI cannot load the config. The message is printed in full; a YAML syntax error quotes file content. |

Where stderr goes:

| How the app was started | Destination |
|---|---|
| `net-dns-monitor-service` (supervised direct build) | `~/Library/Logs/net-dns-monitor.launchd.log`, set as both `StandardOutPath` and `StandardErrorPath`. Append-only and never rotated. `net-dns-monitor-service logs` shows the last 40 lines; `logs -f` follows it. |
| `scripts/start.sh` | `<checkout>/net-dns-monitor.log`, through `open -n ... --stdout --stderr`. |
| The menu's Start at Login agent (`com.netdnsmonitor`) | The plist sets no output path. UNVERIFIED: that launchd then discards both streams. |
| `python3 -m netdnsmonitor.app` in a terminal | The terminal. |
| Mac App Store build | UNVERIFIED. The GUI app has never been launched sandboxed. |

`net-dns-monitor-service` also appends its own supervision decisions, one
timestamped line each, to `~/Library/Application Support/net-dns-monitor/keepalive.log`.

## What never goes into a record

- **Credentials.** `ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL` and `SMTP_PASSWORD`
  come from the environment or the Keychain (`credentials.CredentialStore`),
  never from `config.yaml`. `CredentialStore.describe` reports where a value was
  found, never the value. Keychain failures carry the OSStatus number only.
- **Exception messages from calls that carry a credential.** These sites keep
  the class name, a status code, or fixed text:

  | Site | What is kept |
  |---|---|
  | `anthropic_escalator.make_escalator` | `<Class> (HTTP N)` |
  | `router_window.ai_config_check` | `AI Check Failed: <Class>` |
  | `notifications.make_slack_notifier` | `HTTP N from Slack webhook`, `Slack webhook unreachable`, or the status and the first 80 characters of the body. Never the URL. |
  | `notifications.make_email_notifier` | `SMTP authentication rejected`, `SMTP send failed (<Class>)`, `SMTP connect to <host>:<port> failed` |
  | `notifications.make_notifier` | `channel raised <Class>` |
  | `state_machine` step and escalation guards | `failed: step raised <Class>`, `escalation raised <Class>` |
  | `router.Router._run_admin` | The script exit code and a fixed description. Stderr is not echoed. |
  | `dashboard._report_action_failure` | Class name and frames |

Messages do reach records at other sites, none of which handles a credential:
`repair_executor` puts `str(exc)` into a step outcome, `ping_once` into its
`error`, `resolution_prober.default_resolve` into the resolution log,
`PeerNetwork.start` into `start_error`, and the tick guard into
`last_tick_error`. Keep new credential-bearing calls to the class-name rule.

## Redaction

`sensitive_strings` is applied only on the way out:

- `state_machine._outbound_bundle` redacts the escalation bundle, then caps log
  excerpts at 200 lines of 300 characters.
- `app._tick` redacts the notification text before it is handed to the Slack
  and email worker. `notifications.format_notification` also omits
  `probe_results` and `log_excerpts`.
- `router_window.redact_prompt` redacts the router AI check prompt and replaces
  MAC addresses with `[MAC]`.

Reports, episode documents, the journal and the resolution log are not
redacted. The default `sensitive_strings` is `[]`, so redaction removes nothing
until someone configures it.

## Where each file lives in each build

| File | Direct build and source run | Mac App Store build |
|---|---|---|
| `config.yaml` | `~/.config/net-dns-monitor/config.yaml` (`app.DEFAULT_CONFIG_PATH`; the CLI takes `--config`) | The same expression inside the container: `~/Library/Containers/<bundle id>/Data/.config/net-dns-monitor/config.yaml` |
| Reports, journal, episodes, resolution log, history, state files | `~/Library/Application Support/net-dns-monitor/` | `~/Library/Containers/<bundle id>/Data/Library/Application Support/net-dns-monitor/` |
| launchd log | `~/Library/Logs/net-dns-monitor.launchd.log` (supervised only) | Not used |
| `keepalive.log` | `~/Library/Application Support/net-dns-monitor/keepalive.log` (supervised only) | Not used |
| `start.sh` log | `<checkout>/net-dns-monitor.log` | Not used |

The container paths come from one measurement: `sandbox_probe` reported its home
as `~/Library/Containers/com.net-dns-monitor.app.sandbox-probe/Data` and wrote
under `Data/Library/Application Support/net-dns-monitor`. The GUI app uses the
same `os.path.expanduser` calls, but it has not been launched sandboxed.
`settings_window.save_config` writes paths back in `~` form, so a saved config
keeps pointing inside the container.

In the test suite, `tests/conftest.py` (`isolate_home`) sets `HOME` to a
per-test temporary directory, so no test writes to the real data directory.
