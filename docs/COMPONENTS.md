# Components

One entry per module in `netdnsmonitor/`. Each entry gives the module's purpose,
the names other modules import from it, its imports, its side effects and how
they are injected, and the tests that cover it.

How the fields were derived, on 2026-09-14 at commit `a6aab33`:

- **Used by** lists every `from netdnsmonitor.<module> import <name>` and every
  `<module>.<name>` attribute access in another package module, found by parsing
  the source with `ast`. A name that starts with `_` is private but still
  crosses a module boundary; changing it breaks the importer.
- **Imports** lists package modules, third-party packages, and the standard
  library modules that carry a side effect (`subprocess`, `socket`, `threading`
  and similar). Pure standard library imports are left out.
- **Tests** lists every file in `tests/` that names the module
  (`netdnsmonitor.<module>` or `from netdnsmonitor import <module>`). App wiring
  tests appear under the modules they reach through `app.py`.
- **Side effects** follows the project rule: every effect enters as a parameter
  with a real default. The parameter names are given so a test can find the seam.

`docs/external-calls.md` lists each external call with file and line.
`docs/ARCHITECTURE.md` shows how the modules fit together during an incident.

### `netdnsmonitor/__init__.py`

Empty package marker. No imports, no side effects.

## Incident core

### `netdnsmonitor/state_machine.py`

Runs one poll: probe, classify, feed the anti-flap gate, and on the healthy-to-incident edge run the ladder, recheck, read log excerpts, escalate if still failing, and build the report. Holds `lock` (an `RLock`) around the pipeline.

- **Used by:** `app` (`StateMachine`).
- **Imports:** package: `classifier`, `escalation`, `flap_gate`, `ladder`, `report`; stdlib with effects: `threading`.
- **Side effects:** None of its own. `prober`, `repair_executor`, `escalator` and `log_watcher` are constructor arguments. Every injected call fails as data: a raising step becomes `failed: step raised <Class>`, a raising recheck becomes `unclassified`. Redacts and caps the outbound bundle (200 lines x 300 characters).
- **Tests:** `tests/test_state_machine.py`.

### `netdnsmonitor/classifier.py`

`classify(external_reachable, dns_ok)` returns `Classification.HEALTHY`, `NETWORK`, `DNS` or `UNCLASSIFIED`. `None` in either input gives `UNCLASSIFIED`.

- **Used by:** `app` (`Classification`, `classify`); `cli` (`classify`); `ladder` (`Classification`); `report` (`Classification`); `state_machine` (`Classification`, `classify`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_app_failover_wiring.py`, `tests/test_classifier.py`, `tests/test_ladder.py`, `tests/test_report.py`, `tests/test_report_storage.py`.

### `netdnsmonitor/flap_gate.py`

`FlapGate` counts consecutive failures and successes and moves between `healthy` and `incident` only at the configured thresholds.

- **Used by:** `state_machine` (`FlapGate`).
- **Imports:** package: none.
- **Side effects:** Pure. Coerces each threshold with `int()` and clamps it to at least 1; `None` raises `TypeError` at construction.
- **Tests:** `tests/test_flap_gate.py`.

### `netdnsmonitor/ladder.py`

The ordered troubleshooting steps per classification (`NETWORK_LADDER`, `DNS_LADDER`, `FAILOVER_STEP`) as `LadderStep` data; `ladder_for` and `step_by_name` look them up.

- **Used by:** `app` (`ladder_for`, `step_by_name`); `cli` (`ladder_for`); `repair_executor` (`LadderStep`); `state_machine` (`DEFAULT_FAILOVER_CLASSIFICATIONS`, `LadderStep`, `ladder_for`).
- **Imports:** package: `classifier`.
- **Side effects:** Pure data.
- **Tests:** `tests/test_app_appstore_wiring.py`, `tests/test_app_dashboard_wiring.py`, `tests/test_app_failover_wiring.py`, `tests/test_app_privilege_wiring.py`, `tests/test_ladder.py`, `tests/test_repair_executor.py`.

### `netdnsmonitor/repair_executor.py`

`make_repair_executor` returns `executor(step, classification)`, which maps each ladder step name to a macOS action and returns an outcome string (`ok`, `partial:`, `failed:`, `NEEDS_PRIVILEGE:`, `NOT_AUTOMATED:`, `cannot renew:`, or unavailable text). Before a DHCP renewal it reads `ipconfig getpacket` and renews only an interface that holds a lease.

- **Used by:** `app` (`make_repair_executor`); `cli` (`make_repair_executor`).
- **Imports:** package: `dns_query`, `ladder`, `privileges`; stdlib with effects: `subprocess`.
- **Side effects:** Subprocesses through `run_fn` (default `subprocess.run`, 5 s each). UDP DNS through `query_fn` (default `dns_query.query_public_dns`). `/etc/resolver` reads through `resolver_dir_exists_fn` and `resolver_listdir_fn`. Privilege answers through `is_granted_fn`, `primary_interface_fn`, `dhcp_granted_fn`, which default to "not granted". `failover_fn` and `unavailable_fn` come from `app.build_state_machine`.
- **Tests:** `tests/test_app_failover_wiring.py`, `tests/test_cli.py`, `tests/test_repair_executor.py`.

### `netdnsmonitor/escalation.py`

`should_escalate` decides whether an incident goes to Claude (ladder done, repair attempted or not applicable, recheck still failing). `redact` replaces every `sensitive_strings` entry, longest first, in nested values.

- **Used by:** `app` (`redact`); `router_window` (`redact`); `state_machine` (`redact`, `should_escalate`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_escalation.py`.

### `netdnsmonitor/anthropic_escalator.py`

`make_escalator(client)` returns the escalator: it builds a tagged, escaped evidence prompt (`build_prompt`), sends it with `SYSTEM_PROMPT`, and returns `{"model", "analysis"}` or `{"error", "model"}`. `default_client` builds an `anthropic.Anthropic` with `max_retries=0`.

- **Used by:** `app` (`default_client`, `make_escalator`); `router_window` (`DEFAULT_MODEL`, `DEFAULT_TIMEOUT_SECONDS`, `default_client`).
- **Imports:** package: none; third-party: `anthropic`.
- **Side effects:** Network call through the injected `client`. `anthropic` is imported only inside `default_client`. Errors keep the class name and HTTP status only.
- **Tests:** `tests/test_anthropic_escalator.py`, `tests/test_router_window.py`.

### `netdnsmonitor/report.py`

`build_report` assembles the incident report dict; `render_markdown` renders it for a human.

- **Used by:** `report_storage` (`render_markdown`); `state_machine` (`build_report`).
- **Imports:** package: `classifier`.
- **Side effects:** Pure.
- **Tests:** `tests/test_app_failover_wiring.py`, `tests/test_report.py`, `tests/test_report_storage.py`.

### `netdnsmonitor/report_storage.py`

`save_report` writes `<started_at>.json` and `.md` into `reports_dir`. `_atomic_write` (temp file, UTF-8, `os.replace`, mode 0600) is also the writer for every state file in the package.

- **Used by:** `ai_consent` (`_atomic_write`); `app` (`save_report`); `domain_learner` (`_atomic_write`); `failover` (`_atomic_write`); `forensic_log` (`_atomic_write`); `history` (`_atomic_write`); `peers` (`_atomic_write`); `settings_window` (`_atomic_write`).
- **Imports:** package: `report`; stdlib with effects: `tempfile`.
- **Side effects:** File writes. No seam; tests pass a `tmp_path` directory.
- **Tests:** `tests/test_report_storage.py`.

## Probes and measurements

### `netdnsmonitor/prober.py`

`make_prober` returns `prober()`, which races TCP connects to the external and internal targets and resolves every domain against one shared deadline. Returns `external_reachable`, `internal_reachable`, `dns_ok` (each `None` when not probed) and per-domain `domain_results`.

- **Used by:** `app` (`make_prober`); `cli` (`make_prober`).
- **Imports:** package: none; stdlib with effects: `socket`, `threading`.
- **Side effects:** Sockets and `getaddrinfo` through `connect_fn` and `resolve_fn` (defaults `default_connect`, `default_resolve`), on daemon threads. Raises `ValueError` at construction for a timeout that is not above 0.
- **Tests:** `tests/test_prober.py`.

### `netdnsmonitor/dns_query.py`

`query_public_dns(domain)` sends one A query to a public resolver (default `1.1.1.1:53`). A matching, complete reply with a usable A answer, including a CNAME chain, returns `True`. A valid negative or NODATA reply returns `False`. A malformed, mismatched, truncated or missing reply returns `None`. Unsupported input names return `False`. This direct-server result does not establish native scoped resolver behavior.

- **Used by:** `repair_executor` (`query_public_dns`).
- **Imports:** package: none; stdlib with effects: `socket`.
- **Side effects:** UDP socket through `send_recv_fn` (default `_default_send_recv`).
- **Tests:** `tests/test_dns_query.py`.

### `netdnsmonitor/interface_probe.py`

`make_interface_prober(targets)` returns `probe(device)`: TCP reachability through one named interface with `IP_BOUND_IF` (25) or `IPV6_BOUND_IF` (125). Returns `None` when the device is absent or nothing could be tried.

- **Used by:** `cli` (`make_interface_prober`); `failover` (`make_interface_prober`); `throughput` (`IPV6_BOUND_IF`, `IP_BOUND_IF`, `default_device_index`).
- **Imports:** package: none; stdlib with effects: `socket`.
- **Side effects:** Sockets through `connect_fn` (default `default_bound_connect`) and `index_fn` (default `default_device_index`).
- **Tests:** `tests/test_interface_probe.py`.

### `netdnsmonitor/throughput.py`

`make_throughput_meter` returns a per-interface Mbps meter: a bounded HTTPS download from `speed.cloudflare.com` pinned to the interface. `measure_all` runs several meters under one deadline. An unmeasurable link reads `None`, never 0.

- **Used by:** `cli` (`make_throughput_meter`); `failover` (`make_throughput_meter`, `measure_all`).
- **Imports:** package: `interface_probe`; stdlib with effects: `socket`, `ssl`, `threading`.
- **Side effects:** DNS, sockets and TLS through `getaddrinfo_fn`, `socket_factory`, `tls_wrap`, `device_index_fn`, `clock`; the meter takes `measure_fn` and `resolve_fn`.
- **Tests:** `tests/test_throughput.py`.

### `netdnsmonitor/ping.py`

`ping_once(host)` sends one ICMP echo with `/sbin/ping` and returns `{"ok", "rtt_ms", "error"}`. Never raises.

- **Used by:** `app` (`ping_once`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`).
- **Tests:** `tests/test_ping.py`.

### `netdnsmonitor/ping_monitor.py`

`PingMonitor.record` turns a stream of ping results into down state, loss percentage over a window, and whether an alert fires now.

- **Used by:** `app` (`PingMonitor`).
- **Imports:** package: none.
- **Side effects:** Pure; time passed in as `now`.
- **Tests:** `tests/test_app_dashboard_wiring.py`, `tests/test_app_ping_wiring.py`, `tests/test_ping_monitor.py`.

### `netdnsmonitor/net_stats.py`

`read_interface_counters` sums `en*` byte counters from `netstat -ibn`; `ThroughputMeter.sample` turns two readings into bits per second.

- **Used by:** `app` (`ThroughputMeter`, `read_interface_counters`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`).
- **Tests:** `tests/test_net_stats.py`.

### `netdnsmonitor/resolution_prober.py`

`resolve_domains_parallel` resolves a batch of domains in a thread pool under one batch deadline and returns per-domain findings with elapsed time.

- **Used by:** `app` (`resolve_domains_parallel`).
- **Imports:** package: none; stdlib with effects: `concurrent`, `socket`.
- **Side effects:** `getaddrinfo` through `resolve_fn` (default `default_resolve`, which applies no per-lookup timeout). Thread pool.
- **Tests:** `tests/test_resolution_prober.py`.

### `netdnsmonitor/resolution_log.py`

`append_resolution_findings` appends one JSONL line per finding, all with one `checked_at`.

- **Used by:** `app` (`append_resolution_findings`).
- **Imports:** package: none.
- **Side effects:** File append and, above 50,000 lines, per-domain compaction retaining maximum finite elapsed time and newest completed lookup. No seam; tests pass a path.
- **Tests:** `tests/test_resolution_log.py`.

### `netdnsmonitor/stall_log.py`

`select_stalled_domains` reads the resolution log and returns every domain that has ever stalled, least recently checked first.

- **Used by:** `app` (`select_stalled_domains`).
- **Imports:** package: none.
- **Side effects:** File read through `opener` (default `_open_lenient`).
- **Tests:** `tests/test_stall_log.py`.

## System log

### `netdnsmonitor/log_watcher.py`

`make_log_watcher(lookback)` returns `watcher()`: error-like lines from `log show`, or one `[net-dns-monitor] no log evidence: ...` line when the log could not be read.

- **Used by:** `app` (`NO_EVIDENCE_PREFIX`, `make_log_watcher`); `domain_learner` (`NO_EVIDENCE_PREFIX`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`, 10 s).
- **Tests:** `tests/test_app_appstore_wiring.py`, `tests/test_domain_learner.py`, `tests/test_log_watcher.py`.

### `netdnsmonitor/system_log.py`

Reads the network parts of the unified log for the dashboard pane: `make_log_reader`, `parse_lines`, `coalesce`, `summarize`, noise filtering, and `LogBuffer`, an in-memory de-duplicating buffer.

- **Used by:** `app` (`LogBuffer`, `coalesce`, `format_entry`, `is_error`, `is_noise`, `make_log_reader`, `summarize`); `config` (`DEFAULT_NOISE_PATTERNS`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`, 45 s). `tests/conftest.py` stubs `make_log_reader` outside `test_system_log.py`.
- **Tests:** `tests/conftest.py`, `tests/test_app_log_wiring.py`, `tests/test_system_log.py`.

### `netdnsmonitor/query_log.py`

`make_query_log_reader` returns raw DNS query lines from `log show`, `[]` for a successful empty read, or `None` when the log could not be read; `extract_top_domains` counts the most-queried names. Used by the dashboard's prewarm action.

- **Used by:** `app` (`extract_top_domains`, `make_query_log_reader`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`, 10 s).
- **Tests:** `tests/test_query_log.py`.

### `netdnsmonitor/domain_learner.py`

Learns monitored domains from failed resolutions in the unified log. `extract_failed_domains` and `is_probeable_domain` validate names; `LearnedDomainStore` persists at most `max_learned_domains`; `prune_dead_domains` evicts a learned name that fails while an anchor resolves; `make_domain_learner` returns the prober's domain source.

- **Used by:** `app` (`LearnedDomainStore`, `make_domain_learner`, `prune_dead_domains`).
- **Imports:** package: `log_watcher`, `report_storage`; stdlib with effects: `threading`.
- **Side effects:** The log scan runs through `spawn` (default a daemon thread) and the injected `log_watcher`. File writes through `report_storage._atomic_write`. Time through `clock`.
- **Tests:** `tests/test_domain_learner.py`.

## Failover and privilege

### `netdnsmonitor/failover.py`

Executes failover by rewriting the service order. `apply_service_order` is the only writer of `networksetup -ordernetworkservices` (permutation guard, re-list, read-back). `NetworkFailover` runs automatic failover, failback and manual `switch_now`, and builds `snapshot` for the menu. `FailoverStore` persists the pre-failover order and switch times. `build_failover` reads the config.

- **Used by:** `app` (`BACKUP`, `PREFERRED`, `build_failover`, `failover_backup_names`, `failover_probe_targets`, `failover_probe_timeout`, `failover_trigger_classifications`); `cli` (`BACKUP`, `PREFERRED`, `apply_service_order`, `build_failover`, `default_run`, `failover_probe_targets`, `failover_probe_timeout`).
- **Imports:** package: `failover_policy`, `interface_probe`, `report_storage`, `service_order`, `throughput`; stdlib with effects: `subprocess`, `threading`.
- **Side effects:** Subprocesses through `run_fn` (default `default_run`, 5 s). Interface probes through `interface_prober`, all services under one deadline (`_probe_all`, using `throughput.measure_all`); throughput through `throughput_meter`. Time through `time_fn`. State file through `_atomic_write`.
- **Tests:** `tests/test_app_failover_wiring.py`, `tests/test_cli.py`, `tests/test_failover.py`.

### `netdnsmonitor/failover_policy.py`

`decide` chooses failover, failback or nothing from reachability, streaks, cooldown and the hourly switch budget. `rank_candidates` and `best_candidate` order backups by reachability and measured throughput.

- **Used by:** `failover` (`BACKUP`, `Candidate`, `FAILBACK`, `FAILOVER`, `PREFERRED`, `best_candidate`, `decide`, `next_preferred_streak`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_failover_policy.py`, `tests/test_throughput.py`.

### `netdnsmonitor/service_order.py`

`parse_service_order` parses `networksetup -listnetworkserviceorder`; `promote` builds a new order; `is_order_intact` refuses any order that is not a permutation of the current one.

- **Used by:** `cli` (`parse_service_order`, `promote`); `failover` (`find_service`, `is_order_intact`, `parse_service_order`, `promote`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_cli_console.py`, `tests/test_failover.py`, `tests/test_service_order.py`.

### `netdnsmonitor/privileges.py`

The sudoers grant: builds and validates `/etc/sudoers.d/net-dns-monitor` (`sudoers_body`), installs or removes it behind the admin dialog (`grant`, `revoke`), and reads what is granted from `sudo -n -k -l` (`granted_commands_now`, `covers`, `is_granted`, `own_rule_listed`). Also `dhcp_interfaces`, `primary_interface` and the window's `status_rows`. `_osascript_admin` is the one admin-dialog wrapper, also used by `router`.

- **Used by:** `app` (`IPCONFIG`, `MDNS_HUP`, `SUDO`, `covers`, `dhcp_interfaces`, `explanation`, `grant`, `granted_commands_now`, `granted_interfaces_from`, `is_granted`, `own_rule_listed`, `primary_interface`, `revoke`, `status_rows`); `cli` (`IPCONFIG`, `covers`, `granted_commands_now`, `is_granted`, `primary_interface`); `repair_executor` (`IPCONFIG`, `MDNS_HUP`, `SUDO`); `router` (`_CANCELLED_RE`, `_osascript_admin`).
- **Imports:** package: none; stdlib with effects: `subprocess`.
- **Side effects:** Subprocesses through `run_fn` (default `subprocess.run`). `tests/conftest.py` stubs the four probes outside `test_privileges.py`.
- **Tests:** `tests/conftest.py`, `tests/test_app_appstore_wiring.py`, `tests/test_app_privilege_wiring.py`, `tests/test_cli.py`, `tests/test_privileges.py`.

## Alerts, records and peers

### `netdnsmonitor/notifications.py`

`format_notification` builds the short alert text (no probe results, no log excerpts). `make_slack_notifier`, `make_email_notifier` and `make_notifier` send it and return per-channel result dicts.

- **Used by:** `app` (`format_notification`, `make_email_notifier`, `make_notifier`, `make_slack_notifier`).
- **Imports:** package: none; stdlib with effects: `http`, `smtplib`, `ssl`, `urllib`.
- **Side effects:** HTTPS through `post_fn` (default `_post_json`, `urllib`). SMTP through `smtp_factory` (default `smtplib.SMTP`). Errors carry status codes or class names only.
- **Tests:** `tests/test_notifications.py`.

### `netdnsmonitor/alert.py`

`network_failed` and `network_recovered`: bounce the Dock, post a notification, and print an `[alert]` line when the ping heartbeat fails or recovers.

- **Used by:** `app` (`network_failed`, `network_recovered`).
- **Imports:** package: none; third-party: `AppKit`, `rumps`; stdlib with effects: `subprocess`.
- **Side effects:** AppKit through `app_fn`. Notification through `rumps.notification`, with an osascript fallback through `run_fn`. stderr lines.
- **Tests:** `tests/test_alert.py`, `tests/test_app_ping_wiring.py`.

### `netdnsmonitor/forensic_log.py`

`ForensicRecorder.note` appends every down, up, step, observation, recheck and escalation event to a JSONL journal and writes an episode document when the network recovers. `render_episode_markdown` renders it. Rotates the journal above 50 MiB and caps observations per episode at 5000.

- **Used by:** `app` (`DOWN`, `ESCALATION`, `ForensicRecorder`, `OBSERVATION`, `RECHECK`, `STEP`, `UP`).
- **Imports:** package: `report_storage`.
- **Side effects:** File writes through `writer` (default `_atomic_write`) and direct appends. Time through `clock`. One stderr line per journal failure edge (`journal_error`).
- **Tests:** `tests/test_app_dashboard_wiring.py`, `tests/test_app_log_wiring.py`, `tests/test_forensic_log.py`.

### `netdnsmonitor/history.py`

`SampleHistory` keeps the last `max_samples` heartbeat samples for the graphs, appends each to JSONL, compacts the file, and reloads it at start with a gap marker.

- **Used by:** `app` (`SampleHistory`).
- **Imports:** package: `report_storage`.
- **Side effects:** File appends and `_atomic_write`. Time through `clock`. Write failures are silent.
- **Tests:** `tests/test_history.py`.

### `netdnsmonitor/peers.py`

`PeerRegistry` records other copies of the app, buckets them by recency, and gives `localization_view` and `addresses_to_probe`. `save_record` and `load_record` persist it. `sanitise` cleans received strings.

- **Used by:** `app` (`PeerRegistry`, `load_record`, `save_record`); `peer_net` (`PeerRegistry`, `sanitise`).
- **Imports:** package: `report_storage`; stdlib with effects: `threading`.
- **Side effects:** Thread lock. Time through `clock`. File writes through `writer`.
- **Tests:** `tests/test_app_peer_wiring.py`, `tests/test_localize.py`, `tests/test_peer_net.py`, `tests/test_peers.py`.

### `netdnsmonitor/peer_net.py`

`PeerNetwork` announces this instance over UDP broadcast, probes known peers, answers pongs and feeds `PeerRegistry`. `build_message` and `parse_message` define protocol `ndm-peer/1`.

- **Used by:** `app` (`PeerNetwork`, `broadcast_addresses`).
- **Imports:** package: `peers`; stdlib with effects: `socket`, `subprocess`, `threading`.
- **Side effects:** UDP socket and a daemon reader thread (tests run it over loopback). `ifconfig` through `run_fn`. Seams: `broadcast_fn`, `local_networks_fn`, `status_fn`, `state_fn`, `on_change`.
- **Tests:** `tests/test_app_peer_wiring.py`, `tests/test_peer_net.py`.

### `netdnsmonitor/localize.py`

`localize` compares this machine's probe with fresh peer readings and returns a verdict (`local_machine`, `local_network`, `local_dns`, `dns_outage`, `upstream_outage`, `inconclusive`) with confidence and reason.

- **Used by:** `app` (`localize`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_localize.py`, `tests/test_peers.py`.

## Configuration, credentials and distribution

### `netdnsmonitor/config.py`

`load_config` merges `config.yaml` over `DEFAULT_CONFIG`, expands `PATH_KEYS`, and validates (`validate_config`, `normalize_config`, `target_problem`). Raises `ConfigError` (a `ValueError` with `.key`).

- **Used by:** `app` (`ConfigError`, `load_config`); `cli` (`load_config`); `settings_window` (`ConfigError`, `DEFAULT_CONFIG`, `PATH_KEYS`, `normalize_config`, `target_problem`, `validate_config`).
- **Imports:** package: `system_log`; third-party: `yaml`.
- **Side effects:** Reads the YAML file. Otherwise pure.
- **Tests:** `tests/test_app_appstore_wiring.py`, `tests/test_app_failover_wiring.py`, `tests/test_app_privilege_wiring.py`, `tests/test_app_settings_wiring.py`, `tests/test_cli.py`, `tests/test_config.py`, `tests/test_settings_window.py`.

### `netdnsmonitor/credentials.py`

`CredentialStore` finds `ANTHROPIC_API_KEY`, `SLACK_WEBHOOK_URL` and `SMTP_PASSWORD`: environment first, then Keychain. `describe` reports only where a value came from. `make_keychain_backend` loads the `SecItem*` functions from Security.framework through PyObjC.

- **Used by:** `app` (`CredentialStore`, `NAMES`, `make_keychain_backend`).
- **Imports:** package: none; third-party: `Foundation`, `objc`.
- **Side effects:** Keychain through `backend_factory` (default `make_keychain_backend`). Environment through `env`. `tests/conftest.py` replaces the backend with an in-memory Keychain.
- **Tests:** `tests/conftest.py`, `tests/test_app_appstore_wiring.py`, `tests/test_app_router_wiring.py`, `tests/test_credentials.py`.

### `netdnsmonitor/credentials_prompt.py`

`prompt_for_secret` and `confirm`: the modal dialogs behind the Credentials and Claude-permission menu items.

- **Used by:** `app` (`confirm`, `prompt_for_secret`).
- **Imports:** package: none; third-party: `AppKit`.
- **Side effects:** Modal `NSAlert`. The app takes both as constructor arguments (`secret_prompt`, `choice_prompt`), so no test opens one.
- **Tests:** None.

### `netdnsmonitor/ai_consent.py`

`ConsentStore` records explicit, versioned, revocable permission to send incident data to Anthropic. `gate_escalator` wraps an escalator so it sends nothing without a current grant. `DISCLOSURE` is the text shown before asking.

- **Used by:** `app` (`ConsentStore`, `DISCLOSURE`, `gate_escalator`).
- **Imports:** package: `report_storage`.
- **Side effects:** JSON file through `_atomic_write`. Time through `clock`.
- **Tests:** `tests/test_ai_consent.py`, `tests/test_app_appstore_wiring.py`.

### `netdnsmonitor/distribution.py`

`detect` returns `Capabilities` for this process: the store build (sandboxed, or `NETDNS_DISTRIBUTION=appstore`) switches off six features and requires AI consent. `unavailable` builds the fixed `UNAVAILABLE_IN_APP_STORE_BUILD` outcome text.

- **Used by:** `app` (`Capabilities`, `detect`, `unavailable`).
- **Imports:** package: none.
- **Side effects:** Reads the environment through `env`.
- **Tests:** `tests/test_app_appstore_wiring.py`, `tests/test_app_settings_wiring.py`, `tests/test_distribution.py`, `tests/test_repair_executor.py`.

## Menu bar app and windows

### `netdnsmonitor/app.py`

The rumps menu bar app (`NetDnsMonitorApp`, `main`). Wires every module to six timers plus a one-shot launch tick, builds the state machine, notifier, failover and escalator (`build_state_machine`, `build_notifier`, `build_escalator`), gates features on `distribution.Capabilities`, and owns the menu, the Start at Login agent and the worker queues.

- **Used by:** No other module imports it.
- **Imports:** package: `ai_consent`, `alert`, `anthropic_escalator`, `classifier`, `config`, `console`, `console_window`, `credentials`, `credentials_prompt`, `dashboard`, `distribution`, `dock_icon`, `domain_learner`, `escalation`, `failover`, `forensic_log`, `history`, `ladder`, `localize`, `log_watcher`, `mini_window`, `net_stats`, `notifications`, `peer_net`, `peers`, `ping`, `ping_monitor`, `privileges`, `prober`, `query_log`, `repair_executor`, `report_storage`, `resolution_log`, `resolution_prober`, `router`, `router_window`, `settings_window`, `stall_log`, `state_machine`, `status`, `system_log`; third-party: `AppKit`, `Foundation`, `rumps`, `yaml`; stdlib with effects: `plistlib`, `pwd`, `socket`, `subprocess`, `threading`.
- **Side effects:** Everything, through module seams: `router_factory`, `capabilities`, `credential_store`, `consent_store`, `secret_prompt`, `choice_prompt`, `url_opener`, `privacy_policy_url_fn`, `router_run_fn`; `main` takes `app_factory` and `startup_alert`. Direct `subprocess.run` for `/usr/bin/open`. `tests/conftest.py` patches the module-level lookups it cannot inject.
- **Tests:** `tests/conftest.py`, `tests/test_app_appstore_wiring.py`, `tests/test_app_console_wiring.py`, `tests/test_app_dashboard_wiring.py`, `tests/test_app_failover_wiring.py`, `tests/test_app_log_wiring.py`, `tests/test_app_notification_wiring.py`, `tests/test_app_peer_wiring.py`, `tests/test_app_ping_wiring.py`, `tests/test_app_privilege_wiring.py`, `tests/test_app_resolution_wiring.py`, `tests/test_app_router_wiring.py`, `tests/test_app_settings_wiring.py`, `tests/test_app_status_wiring.py`.

### `netdnsmonitor/status.py`

Menu bar title and status text: `status_state`, `build_title`, `format_stats`, `format_rate`, `build_status_report`, `build_failover_lines`.

- **Used by:** `app` (`STATS_UNKNOWN`, `build_failover_lines`, `build_status_report`, `build_title`, `format_stats`, `status_state`); `cli` (`REACHABILITY`); `graphs` (`format_rate`).
- **Imports:** package: none.
- **Side effects:** Pure.
- **Tests:** `tests/test_app_ping_wiring.py`, `tests/test_app_status_wiring.py`, `tests/test_status.py`.

### `netdnsmonitor/dashboard.py`

The dashboard window (`DashboardWindow`): statistics, settings in force, graphs, the log pane and buttons for each troubleshooting step. `dashboard_sections` and `render_dashboard_text` are the testable text; `install_main_menu` builds the application menu and a standard Edit menu.

- **Used by:** `app` (`DashboardWindow`, `dashboard_sections`, `install_main_menu`, `render_dashboard_text`); `settings_window` (`_label`, `_make_button_target`).
- **Imports:** package: `graphs`; third-party: `AppKit`, `objc`.
- **Side effects:** AppKit windows. Click failures print the class name and frames to stderr.
- **Tests:** `tests/test_app_appstore_wiring.py`, `tests/test_app_console_wiring.py`, `tests/test_app_dashboard_wiring.py`, `tests/test_app_log_wiring.py`, `tests/test_app_peer_wiring.py`, `tests/test_app_privilege_wiring.py`, `tests/test_dashboard.py`.

### `netdnsmonitor/graphs.py`

`render_series_graph` draws a history series as an `NSImage`; `scale`, `latest_label` and `format_bits` are the pure parts.

- **Used by:** `dashboard` (`format_bits`, `render_series_graph`).
- **Imports:** package: `status`; third-party: `AppKit`, `Foundation`.
- **Side effects:** AppKit drawing, offscreen.
- **Tests:** `tests/test_graphs.py`.

### `netdnsmonitor/mini_window.py`

`MiniWindow`: the small always-on-top panel. `mini_text` is its testable text.

- **Used by:** `app` (`MiniWindow`, `mini_text`).
- **Imports:** package: none; third-party: `AppKit`.
- **Side effects:** AppKit panel.
- **Tests:** `tests/test_mini_window.py`.

### `netdnsmonitor/dock_icon.py`

`set_dock_icon` draws the Dock tile from the status and round-trip time; `build_status_icon` and `dock_text` render it.

- **Used by:** `app` (`set_dock_icon`).
- **Imports:** package: none; third-party: `AppKit`.
- **Side effects:** AppKit `setApplicationIconImage_`, about 2 s per call; skipped when the tile would not change. `tests/conftest.py` stubs `set_dock_icon`.
- **Tests:** `tests/conftest.py`, `tests/test_dock_icon.py`.

### `netdnsmonitor/settings_window.py`

`SettingsWindow` edits every configurable key. `collect`, `format_field` and `parse_field` convert values; `save_config` validates, backs up and writes `config.yaml`; `restart_note` lists keys that need a restart.

- **Used by:** `app` (`NEEDS_RESTART`, `SERVICE_RESTART_HINT`, `STORE_RESTART_HINT`, `SettingsWindow`, `collect`, `restart_note`, `save_config`); `router_window` (`save_config`).
- **Imports:** package: `config`, `dashboard`, `report_storage`; third-party: `AppKit`, `yaml`; stdlib with effects: `shutil`.
- **Side effects:** AppKit window. `save_config` writes through `writer` (default `_atomic_write`) with `clock`, and copies a backup with `shutil.copyfile`.
- **Tests:** `tests/test_app_settings_wiring.py`, `tests/test_settings_window.py`.

### `netdnsmonitor/console.py`

The GUI console's logic with no window: `handle` takes a typed line (the built-ins `:help`, `:clear`, `:pwd`, `:history`, `:status`, `cd`, or a shell command), `run_command` runs it in `/bin/sh` with a timeout, output cap and process-group kill, `kill_running` ends live commands at quit.

- **Used by:** `app` (`kill_running`); `console_window` (`BANNER`, `CLEAR`, `ConsoleState`, `PROMPT`, `handle`, `run_command`).
- **Imports:** package: none; stdlib with effects: `signal`, `subprocess`, `threading`.
- **Side effects:** Subprocess (`subprocess.Popen`, shell) and signals. `handle` takes `runner` (default `run_command`); `child_env` takes `environ`.
- **Tests:** `tests/test_app_console_wiring.py`, `tests/test_console.py`, `tests/test_console_window.py`.

### `netdnsmonitor/console_window.py`

`ConsoleWindowController`: the arbitrary-shell console window, shared by the menu item and the dashboard button through `App.console`.

- **Used by:** `app` (`ConsoleWindowController`).
- **Imports:** package: `console`; third-party: `AppKit`, `Foundation`, `objc`; stdlib with effects: `threading`.
- **Side effects:** AppKit window; commands on a worker thread through `runner` (default `console.run_command`).
- **Tests:** `tests/test_app_console_wiring.py`, `tests/test_console_window.py`.

### `netdnsmonitor/router.py`

The app's own router mode. `Router.start` and `Router.stop` validate settings (`validate`), build a root script (`start_script`, `stop_script`, `bootpd_plist`, `pf_rule`) and run it behind the admin dialog. Both refuse while the `router/` stack's LaunchDaemon exists.

- **Used by:** `app` (`PF_ANCHOR`, `Router`); `router_window` (`DEFAULTS`).
- **Imports:** package: `privileges`; stdlib with effects: `logging`, `plistlib`, `subprocess`, `threading`.
- **Side effects:** Subprocess through `run_fn` (default `subprocess.run`, 180 s); file check through `exists_fn`. Uses `logging.getLogger` for two `info` records that no handler receives.
- **Tests:** `tests/test_router.py`.

### `netdnsmonitor/router_window.py`

The Router Management Console window (`RouterWindowController`): interface pickers, start and stop, ping, diagnostics (`collect_diagnostics`, `get_interfaces`, `bootpd_status`) and an AI config check (`ai_config_check`).

- **Used by:** `app` (`RouterWindowController`, `collect_diagnostics`, `get_interfaces`).
- **Imports:** package: `anthropic_escalator`, `escalation`, `router`, `settings_window`; third-party: `AppKit`, `Foundation`, `PyObjCTools`, `objc`, `yaml`; stdlib with effects: `subprocess`, `threading`.
- **Side effects:** Subprocesses through `run_fn`; Anthropic through `client_factory`; main-thread hop through `post`; workers through `spawn`; key through `api_key_getter` (default: `environ`). AppKit imported lazily.
- **Tests:** `tests/test_app_router_wiring.py`, `tests/test_router_window.py`.

## Command line

### `netdnsmonitor/cli.py`

The `python3 -m netdnsmonitor.cli` entry point (`main`, `build_parser`): `status`, `interfaces`, `bench`, `failover`, `priority`, `ladder`, `commands`, `run`, `guide`, `console`. `render_*` functions return text.

- **Used by:** `cli_console` (`build_context`, `interface_rows`, `list_services`, `promote_service`, `render_catalog`, `render_failover_status`, `render_interfaces`, `render_usage_guide`).
- **Imports:** package: `classifier`, `cli_console`, `commands`, `config`, `failover`, `interface_probe`, `ladder`, `privileges`, `prober`, `repair_executor`, `service_order`, `status`, `throughput`; third-party: `yaml`; stdlib with effects: `subprocess`.
- **Side effects:** Subprocesses through `run_fn` (default `failover.default_run` or `subprocess.run`); probes through `probe_fn`; ladder through `executor_factory`; config through `load_config_fn`; output through `out`.
- **Tests:** `tests/test_app_failover_wiring.py`, `tests/test_cli.py`, `tests/test_cli_console.py`.

### `netdnsmonitor/cli_console.py`

The `netdns console` REPL. `handle` is a pure function of line and state; `run_console` is the I/O loop. Asks for `yes` before a mutating catalogue command, `promote`, `switch` or `preferred`.

- **Used by:** `cli` (`run_console`).
- **Imports:** package: `cli`, `commands`; stdlib with effects: `subprocess`.
- **Side effects:** Subprocesses through `runner`; input through `input_fn`; output through `out`.
- **Tests:** `tests/test_cli_console.py`.

### `netdnsmonitor/commands.py`

`CATALOG` of `DiagnosticCommand` entries (argv, what it answers, `mutates`, `needs_admin`, `timeout`, notes); `resolve` fills placeholders.

- **Used by:** `cli` (`BY_KEY`, `CATALOG`, `missing_placeholder`, `resolve`); `cli_console` (`BY_KEY`, `CATALOG`, `missing_placeholder`, `resolve`).
- **Imports:** package: none.
- **Side effects:** Pure data.
- **Tests:** `tests/test_cli_console.py`.
