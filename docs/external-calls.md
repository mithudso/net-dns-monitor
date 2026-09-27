# External calls

This is the inventory of every call in `netdnsmonitor/` and `scripts/appstore/`
that leaves the Python process: subprocesses, sockets, HTTP, SMTP, the Anthropic
SDK, and the macOS framework calls with an effect outside the app (NSWorkspace,
the Keychain, notifications, the Dock). `docs/integrations-and-assumptions.md`
describes the services and hosts behind these calls.

Line numbers were checked against the working tree on 2026-09-14, at commit
`a6aab33`. Each number points at the call or at its
argument list. Numbers drift with every edit. If a number no longer matches,
search the file for the quoted argv.

## How to read the columns

| Column | Meaning |
|---|---|
| Timeout | The bound the code sets. `none` means the call blocks for as long as the OS lets it. |
| Failure reported as | `Data`: the call site turns the failure into a return value or text, and nothing is raised to its caller. `Exception`: the failure raises, or is printed as a traceback. |
| Mac App Store build | The capability in `netdnsmonitor/distribution.py` that switches the call off, or `not gated`. "Measured allowed" refers to the sandbox table in `docs/APP_STORE_SUBMISSION.md` §1. |
| Faked by | The test file that injects a fake for the call. `None` means no test runs or fakes it. |

## Where the gates are

`distribution.detect()` runs once, in `NetDnsMonitorApp.__init__`. If
`APP_SANDBOX_CONTAINER_ID` is non-empty or `NETDNS_DISTRIBUTION=appstore`, every
capability below is `False`. A gated feature is left out of the menu. Where it
can still be reached, it returns `distribution.unavailable(...)` text, which
starts `UNAVAILABLE_IN_APP_STORE_BUILD` and never reads as `ok`.

| Capability | What `netdnsmonitor/app.py` does when it is `False` |
|---|---|
| `shell_console` | `_menu_layout` omits "Open console". `open_console` and the dashboard button (`GATED_DASHBOARD_ACTIONS`) show the unavailable text. |
| `privileged_repairs` | `build_state_machine` passes `is_granted_fn=lambda: False` and `unavailable_fn`, so `flush_dns_cache` and `renew_dhcp_lease` run nothing. `_refresh_privilege_status` returns before the `sudo -n -k -l` probe. Grant and Revoke show the unavailable text. |
| `network_order_write` | `build_state_machine` replaces `failover_fn` with the unavailable text. `_tick` skips `attempt_failback`. `_menu_layout` omits both switch items, and `_manual_switch` returns first. The service-order read in `snapshot` still runs. |
| `unified_log` | `build_state_machine` uses `unified_log_unavailable_watcher`. `build_domains_source` builds no learner. `_log_view_enabled` returns `False`, so no log timer starts. `prewarm_dns` and the log buttons show the unavailable text. |
| `router` | `__init__` builds no `Router`. `_menu_layout` omits the Router submenu. Every router handler calls `_router_unavailable` first. |
| `launch_agent_login_item` | `_menu_layout` omits "Start at Login". `toggle_login` shows the unavailable text. |
| `requires_ai_consent` (`True` only in the store build) | `build_escalator` wraps the escalator in `ai_consent.gate_escalator`, which sends nothing without a current grant. |

The CLI (`python3 -m netdnsmonitor.cli`) does not read `distribution.py`. The
store bundle has no CLI entry point, so the CLI rows apply to the direct build
and to source runs only.

## Subprocesses in netdnsmonitor/

| Site | Call and target | Timeout | Failure reported as | Mac App Store build | Faked by |
|---|---|---|---|---|---|
| `netdnsmonitor/alert.py:109` | `/usr/bin/osascript -e 'display notification ...'`. Runs only when `rumps.notification` raised. | 10 s | Exception caught; traceback to stderr. | not gated. UNVERIFIED inside the sandbox. | `tests/test_alert.py` (`run_fn`) |
| `netdnsmonitor/app.py:678` | `/usr/bin/sudo -n /sbin/pfctl -a com.apple/netdnsmonitor_nat -s nat` (`router_nat_text`, Router > Troubleshoot). | 5 s (`ROUTER_COMMAND_TIMEOUT_SECONDS`) | Data: `not checked (<Class>)` or `not checked (sudo -n exit N; needs root)`. | Gated: `router`. The handler returns before any subprocess. | `tests/test_app_router_wiring.py` (`router_run_fn`) |
| `netdnsmonitor/app.py:2404` | `/usr/bin/open <forensic_episodes_dir>` (`_open_path`, dashboard action `open_forensic_dir`). | 10 s | Exception: traceback to stderr. The exit code is not read. | not gated. UNVERIFIED inside the sandbox. | None. `tests/test_app_dashboard_wiring.py` replaces `_open_path` whole. |
| `netdnsmonitor/app.py:2923` | `/usr/bin/open -t <config path>` (Router > Configure...). | 10 s | Data: notification `Could not open <path> (<Class>)` or `(open exited N)`. | Gated: `router`. | `tests/test_app_router_wiring.py` (`router_run_fn`) |
| `netdnsmonitor/cli.py:188` | `networksetup -listnetworkserviceorder` (`list_services`), through `failover.default_run`. | 5 s | Data: `[]`, printed as `failed: could not read the network service order`. | CLI only. The store bundle has no CLI entry point, and `cli.py` does not read `distribution.py`. | `tests/test_cli.py` |
| `netdnsmonitor/cli.py:215` | Catalogue argv from `commands.CATALOG` (`run_catalog_command`, `netdns run`). | Per command (`DiagnosticCommand.timeout`, default 5 s) | Data: last line `failed: timed out`, `failed: <Class>: <message>` or `failed: exit N`. | CLI only. | `tests/test_cli.py` (`run_fn`) |
| `netdnsmonitor/cli_console.py:62` | Catalogue argv from the `netdns console` REPL, through `failover.default_run`. | Per command | Data: `failed: <Class>: <message>`. | CLI only. | `tests/test_cli_console.py` (`runner`) |
| `netdnsmonitor/console.py:202` | `/bin/sh -c <typed line>` in a new session, stdin `/dev/null` (`run_command`, GUI console). | 20 s (`DEFAULT_TIMEOUT_SECONDS`), then SIGKILL to the process group | Data: `CommandResult`. A process that cannot start gives return code 127 and `<Class>: <message>`. | Gated: `shell_console`. The menu item is absent and the dashboard button prints the unavailable text. | `tests/test_console.py` (starts real `/bin/sh` children); `tests/test_console_window.py` (`runner`) |
| `netdnsmonitor/console.py:145` | SIGKILL to every live console process group (`kill_running`, registered for app quit). | none | `OSError` suppressed. | Registered in both builds; the set is empty when no command ran. | `tests/test_console.py` |
| `netdnsmonitor/failover.py:111` | `failover.default_run`: the runner behind every `networksetup` call below and behind the CLI. | 5 s default | Data: `SimpleNamespace(returncode=1, stderr=str(exc))`. | See each caller. | `tests/test_failover.py` |
| `netdnsmonitor/failover.py:143` | `networksetup -listnetworkserviceorder`, re-read right before a write (`apply_service_order`). | 5 s | Data: `failed: could not re-read ...` or `failed: the service order changed ...`. | Gated: `network_order_write`. The app never calls a switch in the store build. | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/failover.py:155` | `networksetup -ordernetworkservices <every service>`. The write. | 5 s | Data: `NEEDS_PRIVILEGE: ...` or `failed: networksetup exited N: <stderr>`. | Gated: `network_order_write`. | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/failover.py:169` | `networksetup -listnetworkserviceorder`, read-back after the write. | 5 s | Data: `failed: could not read the service order back ...` or `failed: networksetup reported success but the service order is unchanged`. | Gated: `network_order_write`. | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/failover.py:371` | `networksetup -listnetworkserviceorder` (`NetworkFailover._list_services`, used by `snapshot`). | 5 s | Data: `[]`, shown as `could not read the network service order`. | not gated (a read; measured allowed). | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/failover.py:448` | `networksetup -setnetworkserviceenabled <service> on` before promoting a disabled backup. | 5 s | Data: `NEEDS_PRIVILEGE: enabling ...` or `failed: could not enable ...`. | Gated: `network_order_write`. | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/failover.py:500` | `networksetup -setnetworkserviceenabled <service> off` on failback, for a service this app enabled. | 5 s | Data: a suffix such as `(could not re-disable ...)`. | Gated: `network_order_write`. | `tests/test_failover.py` (`run_fn`) |
| `netdnsmonitor/log_watcher.py:42` | `/usr/bin/log show --style compact --last <log_lookback> --predicate <mDNSResponder, DNS, network>` (incident evidence). | 10 s (`LOG_SHOW_TIMEOUT_SECONDS`) | Data: one line `[net-dns-monitor] no log evidence: log show ...`. `[]` means the read ran and matched nothing. | Gated: `unified_log`. `app.unified_log_unavailable_watcher` replaces it. | `tests/test_log_watcher.py` (`run_fn`) |
| `netdnsmonitor/net_stats.py:92` | `/usr/sbin/netstat -ibn` (`read_interface_counters`, every heartbeat). | 5 s | Data: `None`; the throughput reading stays blank. | not gated (measured allowed). | `tests/test_net_stats.py` (`run_fn`) |
| `netdnsmonitor/peer_net.py:216` | `/sbin/ifconfig` (`_ifconfig_output`, for broadcast addresses and local subnets). | 5 s | Data: `None`. Broadcast falls back to `255.255.255.255`; the sender filter accepts every sender. | not gated (measured allowed). | `tests/test_peer_net.py` (`run_fn`, `local_networks_fn`) |
| `netdnsmonitor/ping.py:99` | `/sbin/ping -c 1 -W <ms> -t <s> <ping_host>` (`ping_once`, every heartbeat). | `ceil(ping_timeout_seconds) + 2` s | Data: `{"ok": False, "error": ...}` with `str(exc)` or the first stderr line. | not gated (measured allowed). | `tests/test_ping.py` (`run_fn`) |
| `netdnsmonitor/privileges.py:191` | `/sbin/ifconfig -l` (`dhcp_interfaces`). | 5 s | Data: `[]`. | Gated: `privileged_repairs`. The launch probe is skipped. | `tests/test_privileges.py` (`run_fn`); stubbed for other modules by `tests/conftest.py` |
| `netdnsmonitor/privileges.py:219` | `/sbin/route -n get default` (`primary_interface`). | 5 s | Data: `None`. | Gated: `privileged_repairs`. | `tests/test_privileges.py`; stubbed by `tests/conftest.py` |
| `netdnsmonitor/privileges.py:466` | `/usr/bin/sudo -n -k -l` (`granted_commands_now`). | 5 s | Data: `[]`, which reads as not granted. | Gated: `privileged_repairs`. | `tests/test_privileges.py`; stubbed by `tests/conftest.py` |
| `netdnsmonitor/privileges.py:588` | `/usr/bin/osascript -e 'do shell script "..." with administrator privileges'`: installs or removes `/etc/sudoers.d/net-dns-monitor` (`_run_privileged`). | none (waits for the admin dialog) | Data: `{"ok", "cancelled", "message"}`. The message can carry osascript stderr or `could not run osascript: <exc>`. | Gated: `privileged_repairs`. Grant and Revoke print the unavailable text. | `tests/test_privileges.py`, `tests/test_app_privilege_wiring.py` (`run_fn`) |
| `netdnsmonitor/query_log.py:44` | `/usr/bin/log show --style compact --last <log_lookback> --predicate <mDNSResponder, DNS>` (dashboard `prewarm_dns`). | 10 s | Data: `[]`; the action prints `No queried domains found in the log`. | Gated: `unified_log` (`GATED_DASHBOARD_ACTIONS`). | `tests/test_query_log.py` (`run_fn`) |
| `netdnsmonitor/repair_executor.py:77` | The ladder runner (`run` inside `make_repair_executor`). | 5 s | Data: `SimpleNamespace(returncode=1, stderr=str(exc))`. | See each step. | `tests/test_repair_executor.py` (`run_fn`) |
| `netdnsmonitor/repair_executor.py:86` | `dscacheutil -flushcache` (`flush_dns_cache`). | 5 s | Data: `failed: <stderr>`. | Gated: `privileged_repairs` (`unavailable_fn` returns first). | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:89` | `killall -HUP mDNSResponder`. | 5 s | Data: `partial: ... requires elevated privilege`. | Gated: `privileged_repairs`. | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:97` | `/usr/bin/sudo -n /usr/bin/killall -HUP mDNSResponder`, only when the grant is detected. | 5 s | Data: `partial: cache flushed, but the granted sudo rule did not restart mDNSResponder (...)`. | Gated: `privileged_repairs`. | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:144` | `/usr/sbin/ipconfig getpacket <enN>`, unprivileged, before a renewal. The renewal runs only if the output has a `lease_time` line. | 5 s | Data: `failed: could not read the DHCP state of <enN> ... Nothing was changed.` or `cannot renew: <enN> holds no DHCP lease ...`. | Gated: `privileged_repairs`. | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:160` | `/usr/bin/sudo -n /usr/sbin/ipconfig set <enN> DHCP` (`renew_dhcp_lease`), only on an interface that holds a lease. | 5 s | Data: `NEEDS_PRIVILEGE: ...`, `cannot renew: ...` or `failed: ipconfig set ...`. | Gated: `privileged_repairs`. | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:180` | `scutil --nwi` (`check_interface_state`). | 5 s | Data: stderr text as the outcome. | not gated (measured allowed). | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:184` | `netstat -rn -f inet` (`check_default_route`). | 5 s | Data: stderr text. | not gated (measured allowed). | `tests/test_repair_executor.py` |
| `netdnsmonitor/repair_executor.py:188` | `scutil --dns` (`check_configured_dns_servers`). | 5 s | Data: stderr text. | not gated (measured allowed). | `tests/test_repair_executor.py` |
| `netdnsmonitor/router.py:326` | `/usr/bin/osascript` admin wrapper around `start_script` or `stop_script` (ifconfig, bootpd plist, launchctl, pfctl, sysctl) (`Router._run_admin`). | 180 s (`DEFAULT_TIMEOUT_SECONDS`) | Data: `ok:`, `cancelled:`, `refused:` or `failed: exit N; <fixed text>`. Stderr is not echoed. | Gated: `router`. The router is never built in the store build. | `tests/test_router.py` (`run_fn`; the script is asserted as text and never run) |
| `netdnsmonitor/router_window.py:65` | `_capture`: the runner for the three reads below. | 5 s (`COMMAND_TIMEOUT_SECONDS`) | Data: `(None, <Class>)` or `(None, "exit N")`, shown as `not checked (...)`. | Gated: `router` (the window opens only with the router capability). | `tests/test_router_window.py` (`run_fn`) |
| `netdnsmonitor/router_window.py:88` | `networksetup -listallhardwareports` (`get_interfaces`). | 5 s | Data: `[]`. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/router_window.py:145` | `netstat -rn -f inet` (`collect_diagnostics`). | 5 s | Data: `Routing table: not checked (...)`. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/router_window.py:151` | `sysctl net.inet.ip.forwarding` (`collect_diagnostics`). | 5 s | Data: `IP forwarding: not checked (...)`. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/router_window.py:131` | `/bin/launchctl print system/com.apple.bootpd` (`bootpd_status`). | 5 s | Data: `bootpd job: not checked (<Class>)`. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/router_window.py:194` | `netstat -rn -f inet` and `sysctl net.inet.ip.forwarding` again, as input to the AI check (`ai_config_check`). | 5 s | Data: `(not available: ...)` in the prompt. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/router_window.py:643` | `ping -c 4 <target>` (router window Ping; target validated by `ping_target`). | 20 s (`PING_TIMEOUT_SECONDS`) | Data: `Ping failed: <Class>` or `Ping failed:` plus output. | Gated: `router`. | `tests/test_router_window.py` |
| `netdnsmonitor/system_log.py:500` | `/usr/bin/log show --style compact --last <window> --predicate <network processes and subsystems, error levels>` (dashboard log pane). | 45 s (`log_view_timeout_seconds`) | Data: `{"entries": [], "error": <text>}`. The pane shows the text. | Gated: `unified_log`. No timer starts and the pane shows the unavailable text. | `tests/test_system_log.py` (`run_fn`); stubbed for other modules by `tests/conftest.py` |

## Sockets in netdnsmonitor/

| Site | Call and target | Timeout | Failure reported as | Mac App Store build | Faked by |
|---|---|---|---|---|---|
| `netdnsmonitor/dns_query.py:18` | UDP DNS query (type A) for `example.com` to `1.1.1.1:53` (`query_public_dns`, ladder step `resolve_against_public_resolver`). | 2 s | Data: `None` when no reply arrives; `False` for a malformed or mismatched reply. | not gated (measured allowed). | `tests/test_dns_query.py` (`send_recv_fn`) |
| `netdnsmonitor/interface_probe.py:45` | Interface index lookup (`default_device_index`). | none | Data: `None` when the interface is absent. | not gated. | `tests/test_interface_probe.py` (`index_fn`) |
| `netdnsmonitor/interface_probe.py:66` | TCP connect pinned to one interface with `IP_BOUND_IF` (25) or `IPV6_BOUND_IF` (125), to `failover_probe_targets` or `external_targets` (`default_bound_connect`). | One budget (`failover_probe_timeout_seconds`, else `probe_timeout_seconds`) sliced across targets | Data: `False`; `None` when no target could be tried. | not gated (measured allowed). `NetworkFailover._probe_all` runs one probe per configured service under one deadline (`throughput.measure_all`), from `snapshot` in both builds and from a switch. | `tests/test_interface_probe.py` (`connect_fn`) |
| `netdnsmonitor/peer_net.py:302` | UDP bind on all interfaces, port `peer_port` (45737), with `SO_BROADCAST` and `SO_REUSEADDR`, and deliberately without `SO_REUSEPORT` (`PeerNetwork.start`). A second copy on the same Mac fails to bind and runs with discovery off. | 1 s read timeout | Data: `start()` returns `False` and sets `start_error`; the app prints `[peers] discovery unavailable: <error>` to stderr. | not gated. Switched by `peer_discovery_enabled`. The store entitlements include `network.server`. | `tests/test_peer_net.py` (real UDP over loopback), `tests/test_app_peer_wiring.py` |
| `netdnsmonitor/peer_net.py:385` | Announce (broadcast) and probe (unicast) datagrams, protocol `ndm-peer/1`. | none | `OSError` skipped for that address. | not gated. | `tests/test_peer_net.py` (`broadcast_fn` returns `127.0.0.1`) |
| `netdnsmonitor/peer_net.py:401` | Reader loop on a daemon thread. | 1 s | Timeout: loop continues. Other `OSError`: 1 s backoff; a closed socket ends the thread and `alive()` turns `False`. | not gated. | `tests/test_peer_net.py` |
| `netdnsmonitor/prober.py:21` | TCP connect to `external_targets` (default `1.1.1.1:443`, `8.8.8.8:443`) and `internal_targets` (`default_connect`). | `probe_timeout_seconds` (2 s), one deadline for the whole probe | Data: `False`. An exception raised by an injected `connect_fn` is re-raised to the tick guard. | not gated (measured allowed). | `tests/test_prober.py` (`connect_fn`). The default is never exercised by a test. |
| `netdnsmonitor/prober.py:43` | System resolver lookup for `domains`, `control_domain` (`api.anthropic.com`) and learned domains (`default_resolve`). | Shared `probe_timeout_seconds` deadline; the lookup runs on a worker thread | Data: `False` for a failed or late lookup. | not gated (measured allowed). | `tests/test_prober.py` (`resolve_fn`). The default is never exercised by a test. |
| `netdnsmonitor/resolution_prober.py:61` | System resolver lookup for every ever-stalled domain (`default_resolve`). | No per-lookup bound; batch deadline `resolution_batch_deadline_seconds` (240 s) | Data: `(False, str(exc))`, appended to `resolution-log.jsonl`. | not gated. | `tests/test_resolution_prober.py` (`resolve_fn`) |
| `netdnsmonitor/throughput.py:98` | Resolve `failover_speedtest_host` (`speed.cloudflare.com`) once per family (`resolve_addresses`). | `failover_speedtest_timeout_seconds` (5 s), worker thread | Data: `[]`. | Runs only while a switch ranks backups, and from CLI `bench` / `interfaces --bench`. The store build never switches. | `tests/test_throughput.py` (`getaddrinfo_fn`) |
| `netdnsmonitor/throughput.py:161` | TCP connect to the resolved literal, port 443, pinned with `IP_BOUND_IF` (`_connect_bound`). | Slice of the 5 s budget per literal | Data: `None` (unmeasurable), never `0.0`. | As above. | `tests/test_throughput.py` (`socket_factory`) |
| `netdnsmonitor/throughput.py:127` | TLS handshake, then `GET /__down?bytes=2000000` (`default_measure`). | Remaining budget, re-armed before each step | Data: `None` on `OSError`, `ssl.SSLError`, `ValueError` or a non-2xx status. | As above. | `tests/test_throughput.py` (`tls_wrap`) |

## HTTP, SMTP and the Anthropic SDK

| Site | Call and target | Timeout | Failure reported as | Mac App Store build | Faked by |
|---|---|---|---|---|---|
| `netdnsmonitor/notifications.py:71` | HTTPS POST of `{"text": ...}` to the `SLACK_WEBHOOK_URL` (`_post_json`). | `notify_timeout_seconds` (5 s) | Data: `HTTP N from Slack webhook`, `Slack webhook unreachable`, or `Slack webhook returned status N body '...'`. The URL never appears. | not gated. Needs `slack_enabled` and the credential. | `tests/test_notifications.py` (`post_fn`), `tests/test_app_notification_wiring.py` |
| `netdnsmonitor/notifications.py:139` | `smtplib.SMTP(smtp_host, smtp_port)`, then `starttls` with a verifying context, `login`, `send_message`, `quit` (`make_email_notifier`). | `notify_timeout_seconds` (5 s) | Data: `SMTP connect to host:port failed`, `SMTP authentication rejected`, `SMTP send failed (<Class>)`, `refusing SMTP login without TLS`; partial refusals in `refused`. | not gated. Needs `email_enabled` and `email_recipients`. | `tests/test_notifications.py` (`smtp_factory`) |
| `netdnsmonitor/anthropic_escalator.py:84` | Claude Messages API: model `claude-haiku-4-5-20251001`, or `claude-sonnet-5` for `unclassified`; `max_tokens` 512; evidence in tagged user turn (`make_escalator`). The client is built with `max_retries=0`. | 30 s per request (`DEFAULT_TIMEOUT_SECONDS`). The lookup of `api.anthropic.com` runs before the timeout applies and is not bounded. | Data: `{"error": "<Class> (HTTP N)", "model": ...}`. `state_machine` wraps any raise as `escalation raised <Class>`. | Runs in both builds when a key exists. The store build also requires consent (`ai_consent.gate_escalator`). | `tests/test_anthropic_escalator.py` (fake `client`), `tests/test_app_appstore_wiring.py` |
| `netdnsmonitor/router_window.py:202` | Claude Messages API, `DEFAULT_MODEL`, `max_tokens` 1000; MAC addresses replaced and `sensitive_strings` redacted (`ai_config_check`). | 30 s | Data: `AI Check Failed: <Class>`. | Gated: `router`. No consent gate, because the window is absent from the store build. | `tests/test_router_window.py` (`client_factory`) |

## macOS frameworks

| Site | Call and target | Timeout | Failure reported as | Mac App Store build | Faked by |
|---|---|---|---|---|---|
| `netdnsmonitor/app.py:257` | `NSWorkspace.openURL_`: the bundled privacy-policy URL, or the last report as a `file://` URL (`open_url_with_workspace`). | none | Data: `False`, then a notification `failed: could not open ...`. | Both builds. Used instead of `webbrowser`, which sends Apple Events through osascript. | `tests/test_app_appstore_wiring.py`, `tests/test_app_dashboard_wiring.py` (`url_opener`) |
| `netdnsmonitor/credentials.py:98` | Keychain read: generic password, service `com.net-dns-monitor.credentials`, account = credential name. | none (a read can wait on a Keychain access prompt) | Data: OSStatus; `CredentialStore.get` returns `None`. A backend that cannot load degrades to environment-only. | Both builds. | `tests/test_credentials.py` (fake backend); every other test gets `_MemoryKeychain` from `tests/conftest.py` |
| `netdnsmonitor/credentials.py:104` | Keychain write: `SecItemAdd`, then `SecItemUpdate` on a duplicate; `SecItemDelete` for Remove. | none | Data: `failed: Keychain returned OSStatus N`. | Both builds. | `tests/test_credentials.py`; real round trip only in `scripts/appstore/sandbox_probe.py` |
| `netdnsmonitor/alert.py:99` | `rumps.notification`, which posts through `NSUserNotificationCenter` (network-failed alert). | none | Exception: traceback to stderr, then the osascript fallback. | Both builds. | `tests/test_alert.py` |
| `netdnsmonitor/alert.py:70` | Dock bounce (`requestUserAttention_`), cancelled on recovery. | none | Exception: traceback to stderr. | Both builds. | `tests/test_alert.py` (`app_fn`) |
| `netdnsmonitor/dock_icon.py:133` | Dock tile image (`set_dock_icon`). Measured at about 2 s per call on the main thread. | none | Exception suppressed (cosmetic). | Both builds. | Stubbed for every test by `tests/conftest.py` (`no_real_dock_icon`); `tests/test_dock_icon.py` renders offscreen |

## scripts/appstore/

| Site | Call and target | Timeout | Failure reported as | Mac App Store build | Faked by |
|---|---|---|---|---|---|
| `scripts/appstore/build_appstore.py:297` | `run`: every build step below that prints `+ <argv>`. | none | Exception: `CalledProcessError` aborts the build. | Build tool; not part of any app build. | None. `tests/test_appstore_build.py` covers the pure helpers only. |
| `scripts/appstore/build_appstore.py:301` | `capture`: `lipo -archs`, `otool -l`, `otool -L`, `otool -D`, `vtool -show-build`. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:338` | `python setup.py py2app` with `NETDNS_BUILD=appstore` and the `NETDNS_*` identity variables. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:381` | `xcrun --sdk macosx clang ...`: rebuilds the py2app launcher against the installed SDK. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:462` | `install_name_tool -delete_rpath` for rpaths outside the bundle. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:507` | `security cms -D -i <profile>` (release mode). | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:562` | `python scripts/appstore/make_icon.py <icon>`. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:607` | `xattr -cr <app>`. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:517` | `codesign --force --sign <identity> [--identifier] [--entitlements]`, inside-out; then `codesign --verify --strict --deep` and `codesign --display --entitlements`. | none | Exception. | Build tool. | None |
| `scripts/appstore/build_appstore.py:627` | `productbuild --component <app> /Applications --sign <installer identity> <pkg>`, then `pkgutil --check-signature` (release mode). `xcrun altool` commands are printed, not run. | none | Exception. | Build tool. | None |
| `scripts/appstore/make_icon.py:117` | `iconutil -c icns <iconset> -o <output>`. | none | Exception. | Build tool. | None |
| `scripts/appstore/sandbox_probe.py:66` | `READ_ONLY_COMMANDS`: ping, `networksetup -listnetworkserviceorder`, `scutil --nwi`, `scutil --dns`, `netstat -ibn`, `netstat -rn -f inet`, `ifconfig`, `route -n get default`, `log show`. | 20 s | Data: JSON `ok`, `returncode`, first stderr line; exceptions recorded as class name. | Runs only inside an ad-hoc sandboxed bundle built with `--with-probe`. A release build refuses to include it. | None |
| `scripts/appstore/sandbox_probe.py:79` | TCP connect `1.1.1.1:443`; also `getaddrinfo(api.anthropic.com)`, UDP DNS through `query_public_dns`, a UDP bind, and an interface-bound connect through `make_interface_prober`. | 5 s (connect) | Data: JSON via `timed`. | Probe only. | None |
| `scripts/appstore/sandbox_probe.py:97` | HTTPS GET `https://api.anthropic.com/`. Any HTTP status counts as success. | 8 s | Data: JSON. | Probe only. | None |
| `scripts/appstore/sandbox_probe.py:178` | Keychain add, read, delete round trip under service `com.net-dns-monitor.sandbox-probe`. | none | Data: JSON with each OSStatus. | Probe only. | None |
## Not listed

- File reads and writes under the data directory. `docs/logging.md` lists those
  files and where each one lives.
- `toggle_login` writes `~/Library/LaunchAgents/com.netdnsmonitor.plist`. It is a
  file write, not a call, and it is gated by `launch_agent_login_item`.
- Modal dialogs (`credentials_prompt.prompt_for_secret`, `credentials_prompt.confirm`,
  `app.show_startup_alert`) and window drawing (`dashboard.py`, `graphs.py`,
  `mini_window.py`, `settings_window.py`, `console_window.py`, `router_window.py`).
  They wait for a person and reach no other process.
- The router shell scripts (`router/scripts/`, `unbound/install.sh`). They are
  not Python and no test runs them; `docs/integrations-and-assumptions.md` lists
  their assumptions.
