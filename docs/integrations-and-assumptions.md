# Integrations and assumptions

This page lists the services the code talks to, the facts about macOS and the
network that the code takes as given, and how the three ways of running the app
differ. `docs/external-calls.md` has the call-by-call inventory with file and
line.

Checked against the working tree on 2026-09-14, at commit `a6aab33`. Defaults
below are `config.DEFAULT_CONFIG` values; `tests/test_config.py` checks that
`config.yaml` ships the same values.

## External services

| Service | Used by | Endpoint and defaults | On when | Credential | Status |
|---|---|---|---|---|---|
| Anthropic Messages API | `anthropic_escalator.make_escalator` (incident escalation); `router_window.ai_config_check` (router AI check) | `api.anthropic.com` through the `anthropic` SDK (`anthropic==0.117.0`). Model `claude-haiku-4-5-20251001`, or `claude-sonnet-5` for an `unclassified` incident. 30 s timeout per request, `max_retries=0`. The name lookup runs before the timeout applies and is not bounded. | An incident whose recheck still fails, and a key is found. The store build also needs consent in `ai-consent.json`. | `ANTHROPIC_API_KEY` | The escalation call runs on the rumps run loop (see `docs/known-issues.md`). It cannot help during a full outage, because it needs the network. |
| `api.anthropic.com` as the DNS control | `app.anchor_domains`, `domain_learner.prune_dead_domains`, `cli.cmd_status` | `control_domain: api.anthropic.com`, resolved every poll with `domains`. | Always, unless `control_domain` is `null`. | none | It is the name known to resolve. If it resolves and a learned name does not, the learned name is pruned. If it fails too, nothing is pruned. |
| Slack incoming webhook | `notifications.make_slack_notifier` | HTTPS POST of `{"text": ...}` to the webhook URL. Success is status 200 with body `ok`. 5 s (`notify_timeout_seconds`). | `slack_enabled: true` (default) and a webhook URL is found. | `SLACK_WEBHOOK_URL` (the URL is the credential) | UNVERIFIED: no live delivery has been observed. |
| SMTP relay | `notifications.make_email_notifier` | `smtp_host: localhost`, `smtp_port: 587`, `smtp_starttls: true`, `smtp_username: null`, `email_from: net-dns-monitor@localhost`. Login without TLS is refused. | `email_enabled: true` (default) and `email_recipients` is non-empty (default `[]`). | `SMTP_PASSWORD` | UNVERIFIED: no live delivery has been observed. |
| `speed.cloudflare.com` | `throughput.default_measure` | `failover_speedtest_host`, `failover_speedtest_path: /__down?bytes=2000000`, port 443, 5 s, at most 2,000,000 bytes, over a socket pinned with `IP_BOUND_IF`. | While a switch ranks backups, and for CLI `bench` and `interfaces --bench`. Set the host to `""` to turn it off. | none | Never on the poll path. |
| `1.1.1.1` and `8.8.8.8` | `prober` (TCP), `ping` (ICMP), `dns_query` (UDP), `interface_probe` (TCP) | `external_targets: [[1.1.1.1, 443], [8.8.8.8, 443]]`; `ping_host: 8.8.8.8` every 5 s; `query_public_dns("example.com")` to `1.1.1.1:53`; `failover_probe_targets: []`, which falls back to `external_targets`. | Always. The public-resolver query runs as a DNS ladder step. | none | A socket pinned to a physical interface cannot reach these while a tunnel holds the route (measured; see `docs/known-issues.md`). |
| Other copies of this app on the LAN | `peer_net.PeerNetwork` | UDP `peer_port: 45737` on all interfaces. Announce to each interface's broadcast address and `255.255.255.255` every `peer_announce_seconds` (300 s). Protocol tag `ndm-peer/1`. | `peer_discovery_enabled: true` (default). | none | Messages are not authenticated. The listener drops senders outside this machine's on-link IPv4 subnets, and accepts every sender if `ifconfig` cannot be read. It discloses the hostname and health state. The port is not shared (no `SO_REUSEPORT`), so a second copy on the same Mac fails to bind and runs with discovery off. |
| Upstream resolvers of the `router/` stack | `unbound/unbound.conf` | DNS over TLS to `9.9.9.9@853#dns.quad9.net` and `1.1.1.1@853#cloudflare-dns.com`, certificates from `/etc/ssl/cert.pem`. | While the `router/` stack runs. | none | Separate from the app. |
| App Store Connect | `scripts/appstore/build_appstore.py` (release mode) | `xcrun altool --validate-app` and `--upload-package`. The script prints these commands and runs neither. | Manual. | App Store Connect API key (outside the repo) | Release mode has never run. See `docs/APP_STORE_SUBMISSION.md`. |

## Hardcoded assumptions

### Interfaces and sockets

| Assumption | Where | If it is false |
|---|---|---|
| Ethernet and Wi-Fi interfaces are named `en<N>`. | `privileges._INTERFACE_RE` (`^en\d+\Z`) for the sudoers grant and `primary_interface`; `net_stats.INTERFACE_PREFIXES = ("en",)` for throughput; `sandbox_probe.interface_bound_connect`. | The grant covers no interface, `renew_dhcp_lease` answers `cannot renew: ...`, and throughput leaves that link out. A VPN holding the default route on `utun` gives `primary_interface() == None` by design. |
| `IP_BOUND_IF` is 25 and `IPV6_BOUND_IF` is 125. | `interface_probe.py`, reused by `throughput.py`. From Darwin's `netinet/in.h` and `netinet6/in6.h`. | Interface-bound probes and speed tests measure the wrong path or fail. Binding a source address is not a substitute: on Darwin the route follows the destination. |
| An absent interface raises `OSError` from `socket.if_nametoindex`. | `interface_probe.default_device_index` | An unplugged adapter would read as unreachable instead of `None`. |
| `ifconfig` prints the netmask in hex (`netmask 0xffffff00`) and `broadcast <addr>`. | `peer_net.local_networks`, `peer_net.broadcast_addresses` | The sender filter accepts every sender; broadcast falls back to `255.255.255.255`. |
| `route -n get default` prints `interface: <name>`. | `privileges.primary_interface`, `sandbox_probe.default_route_interface` | No DHCP renewal target. |

### macOS command output

| Assumption | Where | If it is false |
|---|---|---|
| `/usr/bin/log show --style compact` exists and prints one timestamped line per entry. | `log_watcher.py`, `query_log.py`, `system_log.parse_lines` | Reports carry the no-evidence line; the log pane shows the read error. The unified log masks hostnames by default, so learned domains find nothing on a stock install. |
| `networksetup -listnetworkserviceorder` prints `(N) Name` or `(*) Name`, followed by `(Hardware Port: X, Device: Y)`. Output is UTF-8. | `service_order._ENTRY_RE`, `service_order._PORT_RE`; `failover.default_run` decodes with `surrogateescape` so names round-trip. | `parse_service_order` returns `[]`, which every caller treats as unknown and refuses to write. |
| `networksetup -ordernetworkservices` rewrites the order to exactly the list given, and can exit 0 without a change. | `service_order.is_order_intact`, `failover.apply_service_order` (re-list before, read back after) | Without the guard, a dropped name removes a service; without the read-back, a no-op reads as `ok`. |
| A refused `networksetup` write prints one of `you must be running as root`, `permission denied`, `not permitted`, `administrator`, `authorization`. | `failover._PRIVILEGE_MARKERS` | A refusal reports as `failed:` instead of `NEEDS_PRIVILEGE:`. |
| `networksetup -listallhardwareports` prints `Hardware Port:` and `Device:` lines. | `router_window.parse_interfaces` | The router window lists no interfaces. |
| `netstat -ibn` link rows end with `Ibytes Opkts Oerrs Obytes Coll`. | `net_stats.IBYTES_FROM_END = -5`, `OBYTES_FROM_END = -2` | Throughput shows wrong or blank numbers. |
| BSD `ping` prints `time=<n> ms`; `-t 0` means no timeout. | `ping.RTT_PATTERN`; `ping_once` rounds `-t` up to at least 1. | RTT shows blank; a success still counts. |
| `ipconfig getpacket <enN>` exits 0 and prints a `lease_time` line when the interface holds a DHCP lease (RFC 2131: a lease grant carries a lease time; an INFORM reply does not). | `repair_executor._LEASE_LINE` | Exit 0 without the line: `renew_dhcp_lease` answers `cannot renew: ... holds no DHCP lease` and runs nothing. A nonzero exit: `failed: could not read the DHCP state ... Nothing was changed.` UNVERIFIED: which of the two an interface without DHCP produces. |
| `sudo -n -k -l` lists `NOPASSWD:` specs one per line. | `privileges.parse_granted_commands` | The grant reads as absent. |
| A cancelled admin dialog reports `(-128)` or `User canceled`; `do shell script` exits 1 and keeps the script's code as a trailing `(N)`. | `privileges._CANCELLED_RE`, `router._SCRIPT_EXIT_RE` | A cancel reports as a failure; the router's exit code reads as 1. |
| `/etc/sudoers` contains an `#includedir` or `@includedir` line for `/etc/sudoers.d`. | `privileges._install_script` (`MISSING_INCLUDEDIR`) | The grant refuses to install and says why. |

### Paths and system services

| Assumption | Where |
|---|---|
| Tools at absolute paths: `/sbin/ping`, `/usr/sbin/netstat`, `/sbin/ifconfig`, `/sbin/route`, `/sbin/pfctl`, `/usr/bin/log`, `/usr/bin/osascript`, `/usr/bin/sudo`, `/usr/bin/killall`, `/usr/sbin/ipconfig`, `/usr/bin/open`, `/bin/launchctl`. | `ping.py`, `net_stats.py`, `peer_net.py`, `privileges.py`, `log_watcher.py`, `query_log.py`, `system_log.py`, `alert.py`, `app.py`, `router.py`, `router_window.py` |
| Tools found through `PATH`: `networksetup`, `dscacheutil`, `killall`, `scutil`, `netstat`, `sysctl`, `ping`. `ping.py` records `PATH=/usr/bin:/bin:/usr/sbin:/sbin` measured on the running LaunchAgent, which covers all of them. UNVERIFIED for the store build. | `failover.py`, `cli.py`, `repair_executor.py`, `router_window.py` |
| launchd starts jobs with no `LANG`, so the process encoding is ASCII. Every subprocess read and file write pins UTF-8, and both LaunchAgent plists set `LANG=en_US.UTF-8`. | `report_storage._atomic_write`, `failover.default_run`, `scripts/net-dns-monitor-service`, `app.login_agent_plist` |
| bootpd: `/etc/bootpd.plist`, `/System/Library/LaunchDaemons/bootps.plist`, launchd label `com.apple.bootpd`. bootpd is socket-activated, so launchd holds UDP 67 while the job is loaded. | `router.py`, `router_window.bootpd_status`, `router/scripts/enable_nat.sh`, `router/scripts/test_router.sh` |
| Apple's `/etc/pf.conf` evaluates `nat-anchor "com.apple/*"`, so a rule in a `com.apple/` anchor applies without replacing the main ruleset. | `router.PF_ANCHOR` (`com.apple/netdnsmonitor_nat`), `router/scripts/enable_nat.sh` (`com.apple/custom_nat`), `unbound/install.sh` (flushes `com.apple/unbound_dns`) |
| pf stays enabled while any `pfctl -E` reference is held. The app router keeps its token in `/var/run/netdnsmonitor_pf.token`. | `router.PF_TOKEN_FILE` |
| The `router/` stack's LaunchDaemon exists at `/Library/LaunchDaemons/com.custom.router.nat.plist` when that stack is installed. While it exists, `Router.start` and `Router.stop` refuse. | `router.ROUTER_STACK_DAEMON` |
| The sudoers grant lives at `/etc/sudoers.d/net-dns-monitor`. | `privileges.SUDOERS_PATH` |
| The NAT helper lives at `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh`, root-owned. | `router/scripts/install_persistent_nat.sh` |
| Keychain items use service `com.net-dns-monitor.credentials`, one account per credential name. | `credentials.SERVICE` |
| Homebrew: `unbound/install.sh` runs `brew install unbound dnsmasq`, deploys to `$(brew --prefix)/etc/unbound/unbound.conf` and `$(brew --prefix)/etc/dnsmasq.conf`, and restarts both with `sudo brew services restart`. `router/scripts/test_router.sh` assumes `/opt/homebrew` (Apple silicon) when `brew --prefix` fails. | `unbound/install.sh`, `router/scripts/test_router.sh` |

### The two router stacks

The two stacks conflict: both serve DHCP on UDP 67 and both set
`net.inet.ip.forwarding`. Which one is canonical is an owner decision.

| | App router (`netdnsmonitor/router.py`) | `router/` stack |
|---|---|---|
| DHCP | bootpd, `/etc/bootpd.plist` | dnsmasq, `listen-address=192.168.4.1`, `dhcp-range=192.168.4.50,192.168.4.150,12h`, `port=0` |
| DNS | none | Unbound on `192.168.4.1` port 53, access for `127.0.0.0/8` and `192.168.4.0/24` |
| Subnet | `lan_ip: 192.168.10.1`, `lan_netmask: 255.255.255.0`, `dhcp_start: 192.168.10.100`, `dhcp_end: 192.168.10.200` | `192.168.4.0/24` |
| Interfaces | `wan_interface: en3`, `lan_interface: en0` (config defaults, also `router.DEFAULTS`); `start_script` assigns `lan_ip` to the LAN interface | WAN detected on each run from `route -n get default`. No script assigns `192.168.4.1`; the LAN interface must already carry it. |
| NAT anchor | `com.apple/netdnsmonitor_nat` | `com.apple/custom_nat` |
| Started by | Router > Start, or the router window, behind the admin dialog. Never at launch. `router_enabled: false` by default. | `router/scripts/install_persistent_nat.sh` (LaunchDaemon, every 60 s) and `unbound/install.sh` |

`unbound/pf_unbound.conf` holds a redirect to port 53535 that nothing applies;
see `docs/known-issues.md`.

## Environment differences

| | Source run | Direct build | Mac App Store build |
|---|---|---|---|
| How it starts | `python3 -m netdnsmonitor.app` from a Python 3.13 venv | `scripts/start.sh` (`open -n dist/Net-DNS-Monitor.app`), or `net-dns-monitor-service` (`~/Applications/Net-DNS-Monitor.app` under LaunchAgent `com.mitchhudson.net-dns-monitor`) | LaunchServices, inside the App Sandbox |
| `distribution.detect()` | `direct`, unless `NETDNS_DISTRIBUTION=appstore` is exported | `direct` | `appstore`: the sandbox sets `APP_SANDBOX_CONTAINER_ID`, and `setup.py` sets `LSEnvironment` `NETDNS_DISTRIBUTION=appstore` |
| Features | All | All | Gated: failover writes, root repairs, unified log, router, shell console, Start at Login. See `docs/APP_STORE_SUBMISSION.md` §1. |
| Config file | `~/.config/net-dns-monitor/config.yaml` in the real home | Same | The same expression inside the container, `~/Library/Containers/<bundle id>/Data/.config/net-dns-monitor/config.yaml`. The real-home file is blocked (measured by `sandbox_probe`). |
| Data directory | `~/Library/Application Support/net-dns-monitor/` | Same | Inside the container (see `docs/logging.md`) |
| Credentials | Environment first, then Keychain. The shell's exports reach the process. | Environment first, then Keychain. Under the LaunchAgent the plist sets only `LANG`, and no script runs `launchctl setenv`, so exported shell variables do not reach the app; save keys in the Keychain from the Credentials menu. UNVERIFIED: whether `open -n` from `start.sh` passes the shell's exports. | Keychain in practice: LaunchServices gives no shell environment. The missing-key text points at the Credentials menu. |
| Claude consent | Not asked; setting a key is the opt-in | Not asked | Required; stored in `ai-consent.json` |
| Sandbox and entitlements | None | None | `com.apple.security.app-sandbox`, `network.client`, `network.server` (`packaging/appstore/entitlements.plist`); helpers get `app-sandbox` and `inherit` |
| Bundle identifier | None | `com.net-dns-monitor.app` (`setup.py`) | `NETDNS_BUNDLE_ID`, passed by `build_appstore.py` |
| stderr | The terminal | `~/Library/Logs/net-dns-monitor.launchd.log` (supervised) or `<checkout>/net-dns-monitor.log` (`start.sh`) | UNVERIFIED |
| Start at Login item | Writes `com.netdnsmonitor.plist` running `sys.executable -m netdnsmonitor.app` with `WorkingDirectory` set to the checkout | Writes `com.netdnsmonitor.plist` running the bundle executable | Not offered; System Settings > General > Login Items |

In the test suite, `tests/conftest.py` makes every test a direct build with no
real side effects: `HOME` points at a temporary directory, the Keychain is an
in-memory fake, `APP_SANDBOX_CONTAINER_ID` and `NETDNS_DISTRIBUTION` are
removed, the Dock icon is stubbed, and the privilege probes and `log show`
readers are stubbed outside their own test modules.
