# Codebase overview

A map of every tracked file, grouped by directory. Read it to find where
something lives; read `docs/ARCHITECTURE.md` for how the parts work together and
`docs/COMPONENTS.md` for each module's API and seams.

Importance marks come from the repo dossier (`crawl-repo-to-llms`, generated at
`22b52bf`): **critical** means a change can break the build, the gate or every
user; **high** means a change can break a feature or mislead a reader. Unmarked
files are ordinary. The descriptions were re-checked against the working tree on
2026-09-14 (commit `a6aab33`).
`docs/high_signal_file_index.json` holds the same marks in machine-readable form.

## Root

| File | Mark | What it is |
|---|---|---|
| `CLAUDE.md` | high | Agent rules: what the app is, the non-negotiables, the verify loop, house style, known-unverified areas. |
| `AGENTS.md` | high | Pointer to `CLAUDE.md` for every coding agent, with a short command reference. |
| `GEMINI.md` | | Pointer to `CLAUDE.md` for Gemini CLI. |
| `README.md` | high | Product and developer README: scope, setup, run, CLI, features, layout. |
| `HOWTO.md` | high | Long-form install, configuration, usage and troubleshooting guide. |
| `CONTRIBUTING.md` | | Contributor setup, verify loop and pull request checklist. |
| `LICENSE` | | MIT License. |
| `memory.md` | | Versioned operator work log. |
| `prompts.md` | | Versioned record of the owner's requests. |
| `config.yaml` | critical | The shipped default configuration. `tests/test_config.py` checks it equals `config.DEFAULT_CONFIG`. |
| `requirements.txt` | critical | The four runtime dependencies, pinned exactly: `rumps`, `anthropic`, `PyYAML`, `pyobjc-framework-Cocoa`. |
| `requirements-dev.txt` | critical | `-r requirements.txt` plus `pytest` and `ruff`. Test tooling stays out of the runtime file. |
| `constraints.txt` | critical | Exact pins for every package in the tested environment, transitive ones included. Install with `-c constraints.txt`. |
| `setup.py` | critical | py2app spec that freezes `netdnsmonitor/app.py` into `Net-DNS-Monitor.app`. With `NETDNS_BUILD=appstore` it takes the store identity from `NETDNS_*` variables. |
| `pytest.ini` | high | `testpaths = tests`, `python_files = test_*.py`. |
| `ruff.toml` | high | Ruff lint and format settings: `target-version = "py313"`, line length 100, rule selection. |
| `.pre-commit-config.yaml` | | Ruff check and format hooks; the hook version matches `requirements-dev.txt`. |
| `.python-version` | | `3.13`. |
| `.env.example` | | Placeholder values for the three credential variables. |
| `.editorconfig`, `.gitattributes`, `.gitignore` | | Editor settings, line endings, ignored files (`build/`, `dist/`, `.venv/`, signing material). |

`build/`, `dist/` and `.venv/` are build output and local environments. Git
ignores them.

## `netdnsmonitor/`

The application package. Every side effect enters as an injected callable with
a real default.

| Module | Mark | What it does |
|---|---|---|
| `__init__.py` | | Empty package marker. |
| `app.py` | critical | The rumps menu bar app and `main`: timers, menu, windows, worker queues, store-build gates. |
| `cli.py` | critical | `python3 -m netdnsmonitor.cli`: status, interfaces, bench, failover, priority, ladder, commands, run, guide, console. |
| `config.py` | critical | `DEFAULT_CONFIG`, `load_config`, validation, `ConfigError`. |
| `report.py` | critical | The incident report data contract and its Markdown rendering. |
| `state_machine.py` | high | One poll: probe, classify, anti-flap gate, and on the incident edge the ladder, recheck, escalation and report. |
| `classifier.py` | high | `classify(external_reachable, dns_ok)`; `None` gives `unclassified`. |
| `flap_gate.py` | high | Consecutive-failure and consecutive-success debounce. |
| `ladder.py` | high | The troubleshooting steps per classification, as data. |
| `repair_executor.py` | high | Runs each ladder step against macOS and reports exactly what happened. |
| `escalation.py` | high | When to escalate, and `redact` for `sensitive_strings`. |
| `anthropic_escalator.py` | high | Sends the redacted evidence bundle to Claude. |
| `report_storage.py` | high | Writes reports; `_atomic_write` is the package's file writer. |
| `prober.py` | high | TCP reachability and DNS resolution under one shared deadline. |
| `interface_probe.py` | high | Reachability through one named interface with `IP_BOUND_IF`. |
| `status.py` | high | Menu bar title and status text. |
| `notifications.py` | high | Slack and email alerts. |
| `log_watcher.py` | high | Error lines from `log show` for the report, or the no-evidence line. |
| `failover.py` | high | Service-order failover, failback and manual switch; the only writer of `-ordernetworkservices`. |
| `failover_policy.py` | high | Pure failover and failback decisions and backup ranking. |
| `service_order.py` | high | Parses the service order; `is_order_intact` guards every write. |
| `privileges.py` | high | The sudoers grant: build, install, revoke, detect. |
| `router.py` | high | The app's bootpd and pf router mode. |
| `dashboard.py` | high | The dashboard window and application menu. |
| `console.py` | high | The GUI console's logic: built-ins and `/bin/sh` commands with timeout and process-group kill. |
| `console_window.py` | high | The GUI console window. |
| `cli_console.py` | high | The `netdns console` REPL over the command catalogue. |
| `commands.py` | high | The diagnostic command catalogue, with `mutates` and `needs_admin` flags. |
| `credentials.py` | high | Credentials from the environment, then the Keychain. |
| `distribution.py` | high | Detects the Mac App Store build and lists what it may do. |
| `ai_consent.py` | high | Explicit, versioned permission before data goes to Anthropic. |
| `alert.py` | | Dock bounce and notification when the ping heartbeat fails. |
| `credentials_prompt.py` | | Modal dialogs for credentials and Claude permission. |
| `dns_query.py` | | One UDP DNS query to a public resolver. |
| `dock_icon.py` | | Draws the Dock tile. |
| `domain_learner.py` | | Learns monitored domains from failed resolutions in the unified log. |
| `forensic_log.py` | | The forensic journal and per-episode documents. |
| `graphs.py` | | Line graphs of the heartbeat history. |
| `history.py` | | Rolling heartbeat history, persisted as JSONL. |
| `localize.py` | | Where an outage is, from this machine's and peers' readings. |
| `mini_window.py` | | The small always-on-top status panel. |
| `net_stats.py` | | Interface byte counters and throughput. |
| `peer_net.py` | | UDP peer discovery on the LAN. |
| `peers.py` | | The registry of peers and its record file. |
| `ping.py` | | One ICMP ping. |
| `ping_monitor.py` | | Down state, loss rate and alert decision from ping results. |
| `query_log.py` | | Most-queried domains from the unified log, for DNS prewarm. |
| `resolution_log.py` | | Appends stalled-domain findings to JSONL. |
| `resolution_prober.py` | | Resolves a batch of domains in parallel under one deadline. |
| `router_window.py` | | The Router Management Console window. |
| `settings_window.py` | | The settings window and `save_config`. |
| `stall_log.py` | | Picks every domain that has ever stalled from the resolution log. |
| `system_log.py` | | The dashboard's unified-log reader, parser and buffer. |
| `throughput.py` | | Per-interface HTTPS speed test pinned with `IP_BOUND_IF`. |

## `tests/`

Plain pytest functions with injected fakes. The suite runs offline;
`docs/TESTING.md` has the commands and the count (`2136`).

`tests/conftest.py` (high) holds four autouse fixtures. Each one keeps every
test away from something real:

| Fixture | What it does |
|---|---|
| `isolate_home` | Sets `HOME` to a per-test temporary directory, so config defaults resolve away from real user data. |
| `no_real_dock_icon` | Replaces `set_dock_icon` in `dock_icon` and `app`, so no test touches the real Dock. |
| `no_real_keychain_or_distribution` | Replaces `credentials.make_keychain_backend` with an in-memory `_MemoryKeychain`, and removes `APP_SANDBOX_CONTAINER_ID` and `NETDNS_DISTRIBUTION`, so every test is a direct build unless it passes `capabilities=`. |
| `no_real_system_probes` | Stubs `privileges.granted_commands_now`, `is_granted`, `dhcp_interfaces`, `primary_interface` (except in `test_privileges.py`), and `app.make_log_watcher` and `system_log.make_log_reader` (except in `test_system_log.py` and `test_log_watcher.py`). |

`tests/__init__.py` is an empty package marker. The test files, by what they
cover:

| Group | Files |
|---|---|
| Incident core | `test_state_machine.py`, `test_classifier.py`, `test_flap_gate.py`, `test_ladder.py`, `test_repair_executor.py`, `test_escalation.py`, `test_anthropic_escalator.py`, `test_report.py`, `test_report_storage.py` |
| Probes and measurements | `test_prober.py`, `test_dns_query.py`, `test_interface_probe.py`, `test_throughput.py`, `test_ping.py`, `test_ping_monitor.py`, `test_net_stats.py`, `test_resolution_prober.py`, `test_resolution_log.py`, `test_stall_log.py` |
| System log | `test_log_watcher.py`, `test_system_log.py`, `test_query_log.py`, `test_domain_learner.py` |
| Failover and privilege | `test_failover.py`, `test_failover_policy.py`, `test_service_order.py`, `test_privileges.py` |
| Alerts, records and peers | `test_notifications.py`, `test_alert.py`, `test_forensic_log.py`, `test_history.py`, `test_peers.py`, `test_peer_net.py` (real UDP over loopback), `test_localize.py` |
| Configuration, credentials, store build | `test_config.py`, `test_credentials.py`, `test_ai_consent.py`, `test_distribution.py` |
| Windows and text surfaces | `test_status.py`, `test_dashboard.py`, `test_graphs.py`, `test_mini_window.py`, `test_dock_icon.py`, `test_settings_window.py`, `test_console.py` (a few tests start real `/bin/sh` children), `test_console_window.py`, `test_router.py`, `test_router_window.py` |
| Command line | `test_cli.py`, `test_cli_console.py` |
| App wiring (`app.py` through `NetDnsMonitorApp`) | `test_app_appstore_wiring.py`, `test_app_console_wiring.py`, `test_app_dashboard_wiring.py`, `test_app_failover_wiring.py`, `test_app_log_wiring.py`, `test_app_notification_wiring.py`, `test_app_peer_wiring.py`, `test_app_ping_wiring.py`, `test_app_privilege_wiring.py`, `test_app_resolution_wiring.py`, `test_app_router_wiring.py`, `test_app_settings_wiring.py`, `test_app_status_wiring.py` |
| Files outside the package | `test_router_configs.py` (dnsmasq and unbound configs, non-comment lines), `test_router_scripts.py` (router shell scripts as text; none is run), `test_appstore_build.py` (pure helpers of `build_appstore.py`) |

No test runs the rumps run loop, a router script, `osascript` or `sudo`. Three
places start something real on the local machine: `test_console.py` starts
`/bin/sh` children, `test_app_failover_wiring.py` starts a Python child to check
imports, and `test_peer_net.py` sends UDP over loopback.

## `scripts/`

| File | Mark | What it is |
|---|---|---|
| `install.sh` | critical | One-step install and upgrade: preflight, `.venv`, pinned dependencies, default config, py2app bundle, then `net-dns-monitor-service install` with `NDM_SOURCE_BUNDLE` set. |
| `start.sh` | critical | Development launcher: checks the environment, rebuilds the bundle when stale, refuses a second copy, and launches with `open -n`. Output goes to `<checkout>/net-dns-monitor.log`. |
| `net-dns-monitor-service` | critical | The per-user launchd supervisor: `install`, `start`, `stop`, `restart`, `check`, `update`, `status`, `logs`, `uninstall`. Generates LaunchAgent `com.mitchhudson.net-dns-monitor` with `KeepAlive` on a flag file. |
| `com.mitchhudson.net-dns-monitor.plist` | | An empty plist. The real agent is generated by `net-dns-monitor-service`. |

### `scripts/appstore/`

| File | Mark | What it is |
|---|---|---|
| `build_appstore.py` | high | The Mac App Store pipeline in `adhoc` and `release` modes: py2app build, launcher rebuild, `itms-services` removal, linkage check, required `Info.plist` keys, optional `--icon` with an ICNS size check, signing, and in release a signed `.pkg`. |
| `make_icon.py` | | Draws the placeholder icon and writes an `.icns` with every size App Store Connect needs. |
| `sandbox_probe.py` | | Runs inside an ad-hoc sandboxed bundle and records which operations the sandbox allows, as JSON. |

## `packaging/appstore/`

| File | Mark | What it is |
|---|---|---|
| `entitlements.plist` | high | Main executable: `app-sandbox`, `network.client`, `network.server`. |
| `entitlements-helper.plist` | | Secondary executables: `app-sandbox`, `inherit`. |

## `router/`, `dnsmasq/`, `unbound/`

The standalone router stack: dnsmasq DHCP and Unbound DNS on `192.168.4.0/24`,
NAT in pf anchor `com.apple/custom_nat`. It is a separate implementation from
`netdnsmonitor/router.py`, and the two conflict. No test executes these scripts.

| File | Mark | What it is |
|---|---|---|
| `router/docs/ROUTER.md` | high | Architecture of the stack and how it differs from the app's Router menu. |
| `router/scripts/enable_nat.sh` | high | Root-only: frees UDP 67 from bootpd, turns on IP forwarding, detects the WAN interface, loads the NAT rule, enables pf. |
| `router/scripts/install_persistent_nat.sh` | high | Root-only: installs a root-owned copy of `enable_nat.sh` and LaunchDaemon `com.custom.router.nat` (every 60 s). |
| `router/scripts/test_router.sh` | | Read-only diagnostics for the stack; reads pf through `sudo -n`. |
| `dnsmasq/dnsmasq.conf` | | DHCP only on `192.168.4.1`, range `.50` to `.150`. |
| `unbound/unbound.conf` | | Unbound on `192.168.4.1:53` with DNS-over-TLS forwarding. |
| `unbound/install.sh` | | Installs Unbound and dnsmasq with Homebrew, validates and deploys both configs, restarts the services. |
| `unbound/pf_unbound.conf` | | A port 53 to 53535 redirect that nothing applies and that contradicts `unbound.conf`. See `docs/known-issues.md`. |
| `unbound/MAINTENANCE.md` | | Operating notes for Unbound: status, validation, cache flush, `dig`. |

## `docs/`

| File | Mark | What it is |
|---|---|---|
| `ARCHITECTURE.md` | high | System context, the incident data flow, design decisions, the two routers, the store edition. |
| `SCRIPTS.md` | high | Operator's manual for every entry point and one-shot invocation. |
| `TESTING.md` | high | Test commands, CI gates, the injection rule, fixtures, coverage gaps. |
| `DEVELOPMENT.md` | high | Developer prerequisites, setup, workflow and troubleshooting. |
| `SECURITY.md` | high | Threat model: assets, trust boundaries, mitigations, residual risks. |
| `known-issues.md` | high | The current defect list: by design, unproven, confirmed limitations, owner decisions, gaps. |
| `APP_STORE_SUBMISSION.md` | high | The authoritative guide to the Mac App Store build, from sandbox table to upload. |
| `INSTALLATION.md` | | Which of the three ways to run the app to choose, and its prerequisites. |
| `onboarding.md` | | Reading order for a first day. |
| `requirements.md` | | Functional and non-functional requirements. |
| `PRIVACY_POLICY.md` | | Draft privacy policy for the store listing. |
| `codebase-overview.md` | | This map. |
| `high_signal_file_index.json` | | Machine-readable index of the critical and high files and every package module. |
| `COMPONENTS.md` | | Per-module purpose, API, imports, side effects and tests. |
| `external-calls.md` | | Every external call with file, line, timeout, failure mode, store gate and fake. |
| `integrations-and-assumptions.md` | | External services, hardcoded assumptions, and differences between the builds. |
| `logging.md` | | The observability model: records, stderr, redaction, file locations. |

### `docs/runbooks/`

| File | Mark | What it is |
|---|---|---|
| `manual-failover.md` | high | Switch to a backup or back to preferred from the CLI or the menu, read the outcome, restore by hand. |
| `router-nat-recovery.md` | high | Diagnose and restore NAT for the `router/` stack, reinstall the LaunchDaemon, roll back. |
| `sudoers-grant.md` | high | Grant, verify and revoke `/etc/sudoers.d/net-dns-monitor`. |
| `app-store-release.md` | | Per-release checklist for App Store Connect. |

## `.github/`

| File | Mark | What it is |
|---|---|---|
| `workflows/ci.yml` | critical | The gate: `lint` on ubuntu (`ruff check .`, `ruff format --check .`) and `test` on macOS (`pip install -r requirements-dev.txt -c constraints.txt`, `python -m pytest -q`), Python 3.13. |
| `dependabot.yml` | | Monthly updates for pip and GitHub Actions. |
| `copilot-instructions.md` | | Copilot defaults; `CLAUDE.md` overrides it. |
| `SECURITY.md` | | How to report a vulnerability. |
| `PULL_REQUEST_TEMPLATE.md` | | Pull request checklist. |
| `ISSUE_TEMPLATE/bug_report.md`, `ISSUE_TEMPLATE/feature_request.md` | | Issue templates. The bug report asks which build (direct or Mac App Store); the feature request asks whether the idea works in the store build. |
