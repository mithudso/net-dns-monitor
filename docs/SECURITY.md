# Security model

This is the threat model for Net-DNS-Monitor. It lists the assets, the places
where input crosses a trust boundary, and the mitigation that exists in the code
today. Every mitigation names the file and symbol that implements it.

To report a vulnerability, follow [.github/SECURITY.md](../.github/SECURITY.md).
Open defects and owner decisions are in [known-issues.md](known-issues.md).

Reviewed on 2026-09-14 against branch `feat/appstore-prep`. A statement marked
**UNVERIFIED** was not confirmed against the code or a live system.

## Assets

| Asset | Where it lives | Consequence of loss |
|---|---|---|
| `ANTHROPIC_API_KEY` | Environment, or the Keychain through `credentials.py` | Someone else spends on the account. |
| `SLACK_WEBHOOK_URL` | Environment or Keychain | The URL is the credential. Its holder can post to the channel. |
| `SMTP_PASSWORD` | Environment or Keychain | Someone else uses the mail account. |
| Network configuration | The system service order, `/etc/bootpd.plist`, pf anchors, `net.inet.ip.forwarding` | A bad write takes this Mac or its LAN offline. A service name left out of `-ordernetworkservices` is removed from the order. |
| Root | `/etc/sudoers.d/net-dns-monitor`, the router's administrator scripts, the `com.custom.router.nat` LaunchDaemon | Full control of this Mac. |
| The LAN | DHCP, DNS and NAT from either router stack; peer discovery on UDP `peer_port` (default 45737) | Clients use the gateway and DNS server that DHCP names. |
| Report contents | Files under `~/Library/Application Support/net-dns-monitor/`: `reports/`, `forensic-log.jsonl`, `history.jsonl`, `resolution-log.jsonl`, `peers.json`, `failover.json` | Hostnames, IP addresses, probe results and unified-log excerpts, unredacted. |

## Attackers

| Attacker | Assumed capability |
|---|---|
| Local process running as the user | Runs code as the logged-in user. Writes the user's files. Writes lines into the unified log. Cannot write root-owned files. |
| LAN host | Sends UDP from a subnet this Mac is attached to, and forges source addresses inside it. Receives DHCP from a router stack on this Mac. |
| Network path | Reads and alters traffic between this Mac and the SMTP server, Slack or Anthropic. |
| Hostile or faulty service | Anthropic, Slack or the SMTP server returns content the app did not expect. |

Out of scope: an attacker who already has root, or who has the user's unlocked
GUI session. Either one already controls every asset above.

## Trust boundaries and entry points

| # | Boundary | Entry point | Files |
|---|---|---|---|
| 1 | User to root | Dashboard buttons "Grant elevated permissions (changes system state)" and "Revoke elevated permissions" | `netdnsmonitor/privileges.py`, `netdnsmonitor/app.py` |
| 2 | User to root | Router menu Start and Stop; Router Management Console | `netdnsmonitor/router.py`, `netdnsmonitor/router_window.py` |
| 3 | Root daemon to a script on disk | LaunchDaemon `com.custom.router.nat` | `router/scripts/install_persistent_nat.sh`, `router/scripts/enable_nat.sh` |
| 4 | User to network configuration | "Switch to backup now", "Switch back to preferred now", `netdns failover`, the `switch_to_backup_network` ladder step | `netdnsmonitor/failover.py`, `netdnsmonitor/service_order.py` |
| 5 | GUI to shell | "Open console" menu item; "Open console (arbitrary shell)" dashboard button | `netdnsmonitor/console.py`, `netdnsmonitor/console_window.py` |
| 6 | LAN to app | UDP socket on `peer_port` | `netdnsmonitor/peer_net.py`, `netdnsmonitor/peers.py` |
| 7 | This Mac to off-machine | Escalation bundle; Slack and email text; router AI check | `netdnsmonitor/escalation.py`, `netdnsmonitor/state_machine.py`, `netdnsmonitor/app.py`, `netdnsmonitor/router_window.py` |
| 8 | Untrusted evidence to LLM to human | Claude prompt and the analysis it returns | `netdnsmonitor/anthropic_escalator.py`, `netdnsmonitor/notifications.py` |
| 9 | App to mail and chat services | SMTP; Slack incoming webhook | `netdnsmonitor/notifications.py` |
| 10 | Secret store to process | Environment; Keychain | `netdnsmonitor/credentials.py`, `netdnsmonitor/config.py`, `netdnsmonitor/app.py` |
| 11 | App to App Sandbox | Mac App Store build | `netdnsmonitor/distribution.py`, `netdnsmonitor/ai_consent.py`, `packaging/appstore/` |

Each STRIDE table below lists only the categories that apply at that boundary.

### 1. Sudoers grant (`privileges.py`)

The grant writes `/etc/sudoers.d/net-dns-monitor` (`SUDOERS_PATH`), owned by
`root:wheel`, mode `0440`. It lets the user's account run these exact command
lines as root with no password:

```
/usr/bin/killall -HUP mDNSResponder
/usr/sbin/ipconfig set <enN> DHCP        (one line per Ethernet or Wi-Fi interface)
```

Mitigations in the code:

- **Validation before any prompt.** `sudoers_body` refuses, and does not escape,
  an account name outside `_USER_RE` (`^[A-Za-z0-9._-]+\Z`) and a name that
  `_RESERVED_USER_RE` matches (`ALL`, all-caps alias names, `Defaults`,
  `*_Alias`). It refuses an interface name outside `_INTERFACE_RE`
  (`^en\d+\Z`). `grant` builds the body before it runs anything.
- **Account name from the process, not the environment.** `app.py`
  `_run_grant` passes `pwd.getpwuid(os.getuid()).pw_name`.
- **Disclosure first.** `app.py` `_grant_privileges` prints
  `privileges.explanation(interfaces)` before the authentication dialog. It
  refuses to prompt until the launch probe has listed the interfaces, so the list
  shown is the list installed.
- **Inline script.** `_install_script` carries the body base64-encoded inside one
  newline-free script. `_osascript_admin` wraps it in
  `do shell script ... with administrator privileges`. No file is staged in a
  user-writable directory.
- **visudo before activation.** The script exits 3 if `/etc/sudoers` has no
  `includedir` line for `/etc/sudoers.d`. It stages the file with `mktemp` inside
  `/etc/sudoers.d` under a dot name, which sudo ignores. It sets `root:wheel`
  and `0440` and runs `visudo -cf`. On failure it deletes the staged file and
  exits 4. Only then does it rename the file to `SUDOERS_PATH`.
- **Scope.** No wildcard, no shell, no file-path argument. The script never edits
  `/etc/sudoers`.
- **Status is read from the rule, not from policy.** `status_command` runs
  `sudo -n -k -l`. `parse_granted_commands` counts only `NOPASSWD:` entries whose
  runas column includes `root` or `ALL`.
- **Revoke.** `revoke_command` runs `/bin/rm -f /etc/sudoers.d/net-dns-monitor`
  through the same administrator wrapper.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Tampering | A crafted account or interface name adds a second sudoers rule. | `sudoers_body` validation; base64 transport. | None known. |
| Tampering | The staged file is swapped between `visudo -cf` and `mv`. | Staging inside root-only `/etc/sudoers.d`. | None known. |
| Repudiation | Root commands run with no record. | sudo logs every use. | None known. |
| Denial of service | An invalid file breaks sudo for every user. | `visudo -cf` before the rename. | None known. |
| Elevation of privilege | Any process running as the user runs the granted commands as root with no prompt. | Exact command lines only. | Accepted by design. The worst effect is a restarted DNS responder or a renewed DHCP lease. The app itself renews only an interface that holds a DHCP lease, but another process using the grant skips that check: `ipconfig set <if> DHCP` replaces a hand-set IPv4 setup, and with no DHCP server the interface stays without IPv4 until the next network configuration change. |

### 2. Router administrator script (`router.py`)

The app's router mode configures `bootpd` DHCP on a LAN interface and pf NAT out
a WAN interface. It is a separate implementation from the `router/` stack; see
[router/docs/ROUTER.md](../router/docs/ROUTER.md).

Mitigations in the code:

- **Validation.** `validate` requires interface names that match `[a-z]+[0-9]+`,
  different WAN and LAN interfaces, IPv4 addresses for `lan_ip`, `dhcp_start` and
  `dhcp_end`, a valid netmask, a DHCP range inside the LAN network, and
  `dhcp_start` not after `dhcp_end`. On a `ValueError`, `Router.start` returns
  `refused: <reason>` and runs nothing.
- **Inline base64.** `start_script` embeds the `bootpd` plist and the pf rule
  base64-encoded. It stages the plist with `mktemp` inside `/etc` and renames it
  into place. The script runs through `privileges._osascript_admin`.
- **Anchor-scoped pf.** Rules load into `com.apple/netdnsmonitor_nat`
  (`PF_ANCHOR`). `stop_script` flushes that anchor only and never disables pf.
  `start_script` enables pf with `pfctl -E`.
- **Read-back.** Both scripts check the anchor and the `com.apple.bootpd` job
  after the change. `Router._run_admin` reports `ok` only on exit 0. On failure it
  reports the exit code, not stderr.
- **Refusal while the `router/` daemon exists.** `Router.start` and `Router.stop`
  return `CONFLICT_MESSAGE` while
  `/Library/LaunchDaemons/com.custom.router.nat.plist` exists. An `OSError` from
  the existence check also counts as a conflict.
- **No start at launch.** `NetDnsMonitorApp.__init__` constructs the `Router` when
  `router_enabled` is true and never starts it.
- **Bounded wait.** `DEFAULT_TIMEOUT_SECONDS` gives the authentication dialog
  180 s.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Tampering | A value typed into the router window runs as a root shell command. | `validate`; base64 transport. | None known. |
| Tampering | A script or plist in `/tmp` is swapped while the dialog is open. | No user-writable staging. | None known. |
| Denial of service | The app's stop flushes the other stack's NAT or turns off forwarding for it. | Own anchor only; refusal while `com.custom.router.nat` is installed. | Stop sets `net.inet.ip.forwarding=0` for the whole machine. |
| Denial of service | A partial start leaves the machine half-configured. | `set -e`; read-back; the outcome says earlier steps may have taken effect. | Earlier steps are not rolled back. |
| Spoofing | LAN clients receive a gateway and DNS servers from this Mac. | The operator starts the router by hand. | `bootpd_plist` hardcodes DNS servers `8.8.8.8` and `1.1.1.1`. |

### 3. Persistent NAT LaunchDaemon (`router/scripts/`)

`install_persistent_nat.sh` installs the root LaunchDaemon `com.custom.router.nat`.
The daemon runs `enable_nat.sh` at load and every 60 s. `enable_nat.sh` unloads
Apple's `bootps` job, moves `/etc/bootpd.plist` to `/etc/bootpd.plist.bak`, sets
`net.inet.ip.forwarding=1`, and loads a NAT rule for `192.168.4.0/24` into the
`com.apple/custom_nat` anchor. The rule goes out the interface that holds the
default route.

Mitigations in the installer:

- It copies `enable_nat.sh` to
  `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh` with
  `install -o root -g wheel -m 755` and points `ProgramArguments` there. A process
  running as the user cannot change what the daemon runs.
- It refuses when the helper directory or the helper path is a symlink.
- It stages the plist with `mktemp` inside `/Library/LaunchDaemons`, sets
  `root:wheel` and `644`, and checks it with `plutil -lint` before the rename.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Elevation of privilege | A user process edits the script that a root daemon runs. | Root-owned copy under `/Library/PrivilegedHelperTools`. | A daemon installed by an older installer still runs the checkout's script. See residual risk 1. |
| Tampering | A predictable `/tmp` plist is pre-created or swapped. | Staging inside `/Library/LaunchDaemons`. | None known. |
| Information disclosure | The daemon's logs expose configuration. | Logs are root-owned under `/var/log`. | Both logs are world-readable (`-rw-r--r--`). Nothing in this repository rotates them. |
| Spoofing | The NAT rule follows whatever interface holds the default route. | Re-detected on every run. | If a VPN tunnel holds the default route, LAN traffic goes out the tunnel. **UNVERIFIED** with a live tunnel. |

### 4. Network service order (`failover.py`, `service_order.py`)

Mitigations in the code:

- `failover.apply_service_order` is the only place that builds the
  `networksetup -ordernetworkservices` argv. It calls
  `service_order.is_order_intact` first: same length, same set, no duplicates,
  no name that starts with `-`.
- It lists the order again right before the write. It refuses if the order
  changed since the listing that the new order was built from.
- It reads the order back after the write and reports `ok:` only when the
  read-back matches.
- A refused write is reported `NEEDS_PRIVILEGE:`. The app never asks for
  administrator rights for this write.
- `FailoverStore.save` writes `failover.json` atomically with mode `0600`.
  `NetworkFailover._do_failback` restores a recorded order only when its set of
  names equals the current set. A tampered record can reorder services but
  cannot remove one.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Tampering | A malformed order removes a network service. | `is_order_intact`; re-list before the write. | One subprocess of window remains between the re-list and the write. |
| Tampering | A user process edits `failover.json`. | Set-equality check in `_do_failback`. | The process can choose which existing service leads after a failback, and can set `failback_paused` to hold automatic failback off. |
| Denial of service | Automatic switching flaps. | Cooldown, hourly cap and failback threshold in `failover_policy.decide`. | None known. |

### 5. Shell console (`console.py`)

The console runs arbitrary shell as the user, by design. It has the same reach
as Terminal.app.

Mitigations in the code:

- `run_command` starts `/bin/sh` with `stdin=subprocess.DEVNULL` and
  `start_new_session=True`. A command that prompts, such as `sudo` or `ssh`,
  fails instead of hanging.
- After 20 s (`DEFAULT_TIMEOUT_SECONDS`), `_kill_process_group` kills the whole
  process group. `_collect` also kills the group when a background job still
  holds the output pipes after the shell exits.
- `MAX_OUTPUT_BYTES` caps output at 64 KB.
- In the built app, `child_env` removes the py2app launcher variables
  (`FROZEN_ONLY_ENVIRONMENT`), so a child does not inherit the bundle's
  `PYTHONHOME`.
- `kill_running` kills every live command group. `app.py` registers it with
  `rumps.events.before_quit`.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Elevation of privilege | Console commands run as the user. | None, by design. There is no blocklist. | Anyone at the unlocked session can run any command the user can. With the sudoers grant installed, that includes the granted root commands. |
| Denial of service | A command that never exits, or floods output, wedges the app. | Timeout; process-group kill; output cap. | None known. |
| Tampering | Child processes outlive the app. | `kill_running` on quit. | A background job with its output redirected (`cmd > file 2>&1 &`) keeps running, by design. |

### 6. Peer discovery (`peer_net.py`)

The app broadcasts its hostname and health on UDP `peer_port` and listens for
other copies. `peer_discovery_enabled` defaults to `true`.

Mitigations in the code:

- **On-link sender filter.** `PeerNetwork._sender_allowed` drops a sender
  outside the IPv4 subnets attached to this Mac's interfaces. Loopback is always
  allowed. The subnet list comes from `ifconfig`. The listener re-reads it after
  60 s, or after 5 s when a sender is outside the list. If `ifconfig` cannot be
  read, the filter accepts every sender.
- **Size cap.** `_read_loop` reads `MAX_DATAGRAM + 1` bytes, and `parse_message`
  drops anything over 2048 bytes.
- **Parsing.** `parse_message` accepts only a JSON object with
  `proto == "ndm-peer/1"` and a known message type. It drops malformed input
  without logging.
- **Sanitising.** `peers.sanitise` strips non-printable characters and caps `id`
  at 64, `host` at 253 and `status` at 32 characters. `_tristate` turns `ext` and
  `dns` into `None` or a real `bool`.
- **Table cap.** `PeerRegistry` holds at most 200 peers (`MAX_PEERS`) and evicts
  the least recently seen.
- No packet field is used as a path, a command or an argument.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Spoofing | A LAN host claims a known peer's id, or forges an on-link source address. | None. Messages are not authenticated. | Open, pending an owner decision on message authentication. |
| Tampering | Forged `ext` and `dns` values change the fault-localization verdict. | Values are coerced and sanitised, then used as reported. | A forged peer can move the verdict. |
| Information disclosure | Any host that reaches the port learns this Mac's hostname and health. | `peer_discovery_enabled`; on-link filter for replies. | On by default. |
| Denial of service | A flood of fresh ids evicts real peers, or oversize packets consume CPU. | 200-peer cap; size cap; no `ifconfig` per packet. | 200 forged ids still evict every real peer. |

### 7. Outbound redaction (`escalation.redact`)

`escalation.redact` replaces each string in `sensitive_strings` with
`[REDACTED]`.

What it does:

- It matches exact substrings, **case-sensitively**.
- It builds one alternation, longest needle first, so a short needle cannot
  break a longer one. It ignores empty needles and converts non-string needles
  with `str()`.
- It walks strings, dict **keys and values**, lists and tuples. When two keys
  redact to the same text, both entries survive (`[REDACTED] (2)`).
- It leaves numbers, booleans and `None` unchanged.

Where it runs:

| Outbound path | Redaction site | Also applied |
|---|---|---|
| Escalation bundle to Anthropic | `StateMachine._outbound_bundle` | After redaction, log excerpts are capped at the last 200 lines and 300 characters per line. |
| Slack and email text | `app.py`, on the incident edge, before `_send_notification` | `format_notification` omits `probe_results` and `log_excerpts`. |
| Router AI check | `router_window.redact_prompt` | MAC addresses become `[MAC]` first. |

What is not redacted:

- `sensitive_strings` defaults to `[]` (`config.py` `DEFAULT_CONFIG`). With the
  default, no outbound path removes anything.
- The on-disk report and the JSONL logs keep raw values, by design. They stay on
  this Mac.
- A case variant (`Internal-DB` for `internal-db`) and any other spelling of a
  value (a reverse-DNS name for an IP address) pass through.
- The notification carries the full report path. The path contains the
  account's home directory name unless that name is in `sensitive_strings`.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Information disclosure | Hostnames, internal IPs and log lines leave the machine. | `redact` on every outbound path; the notification omits raw evidence. | Empty default list; case-sensitive matching. |
| Information disclosure | Truncation splits a sensitive string so that it no longer matches. | Truncation runs after redaction. | None known. |

### 8. LLM prompt and output (`anthropic_escalator.py`)

The escalation runs only when the ladder completed and the recheck is not
healthy (`escalation.should_escalate`).

Mitigations in the code:

- **Instructions apart from evidence.** `SYSTEM_PROMPT` goes in the `system`
  parameter. It says the evidence is untrusted machine output and that any
  instruction inside it is data.
- **Tagged, escaped evidence.** `build_prompt` puts each field in its own tag
  (`<classification>`, `<probe_results>`, `<ladder_results>`, `<log_excerpts>`).
  `_neutralise` escapes `&`, `<` and `>`, so evidence cannot close its tag.
- **Bounded call.** `max_tokens=512` and a 30 s timeout. `default_client` sets
  `max_retries=0`.
- **Errors carry no body.** `make_escalator` returns the exception class name and
  the HTTP status only.
- **Labelled output.** `format_notification` prefixes the analysis with
  `Claude analysis (unverified, derived from local logs):`.

The router AI check (`router_window.ai_config_check`) sends one user message
with the router form values, the routing table and the forwarding setting. It
has no system prompt and no evidence tags. The router window shows the reply.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Tampering | A local process writes a unified-log line that instructs the model. `log_watcher` collects every line whose message contains `DNS` or `network`. | System prompt; tags; escaping. | Tags reduce prompt injection. They do not prevent it. |
| Spoofing | The analysis reads as a verified diagnosis. | "unverified" label in notifications. | A human can still act on a wrong or injected analysis. |
| Information disclosure | An SDK error message copies request details into the report. | Class name and HTTP status only. | None known. |
| Denial of service | A slow API call blocks the app. | 30 s timeout; no retries. | The call runs on the rumps run loop, so the menu bar waits while it is in flight. |

### 9. Notifications (`notifications.py`)

Mitigations in the code:

- **Certificate verification.** `make_email_notifier` calls
  `starttls(context=ssl.create_default_context())`.
- **No login without TLS.** If a username and password are set and
  `smtp_starttls` is false, it returns `refusing SMTP login without TLS` before it
  connects.
- **Slack escaping.** `make_slack_notifier` escapes `&`, `<` and `>`, so the text
  cannot trigger `<!channel>`, `<@user>` or a link label.
- **Errors without secrets.** Slack errors carry the HTTP code or a fixed string,
  never `str(exc)`, which can contain the webhook URL. SMTP errors carry a fixed
  string or the exception class name. An authentication failure returns
  `SMTP authentication rejected`.
- **Delivery is checked.** Slack counts as delivered only on status 200 with body
  `ok`. Email reports refused recipients.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Information disclosure | A network-path attacker reads the SMTP login. | Verified STARTTLS; refusal without TLS. | With `smtp_starttls: false` and no login, the message goes in clear text. Implicit TLS on port 465 is not supported, because the transport is `smtplib.SMTP`. |
| Information disclosure | The webhook URL appears in an error string. | Fixed error strings. | None known. |
| Tampering | Injected text pings a Slack channel. | Slack escaping. | None known. |

### 10. Credentials (`credentials.py`)

- `config.yaml` carries no credential. `DEFAULT_CONFIG` has no key for any of the
  three.
- `CredentialStore.get` reads the environment first, then the Keychain. Keychain
  items are generic passwords under service `com.net-dns-monitor.credentials`,
  with the credential name as the account. `make_keychain_backend` sets no
  access-control or accessibility attribute, so the Keychain defaults apply.
- `CredentialStore.set` and `delete` return `ok:` or `failed:` with the OSStatus
  number only. `describe` reports where a value was found, never the value.
- `app.py` reads every credential through one `CredentialStore`.
  `build_escalator` reads `ANTHROPIC_API_KEY` from it, and `build_notifier`
  receives `credentials.as_env()`.
- The **Credentials** menu (both builds) has one item per credential and
  **Remove saved credentials**. `NetDnsMonitorApp.set_credential` passes the
  dialog's value to `CredentialStore.set` only. The notification shows the
  store's outcome text, which names the credential and never holds the value.
  After a change, `_apply_credentials` rebuilds the notifier and the escalator in
  place.
- `RouterWindowController.on_ai_check` reads `ANTHROPIC_API_KEY` from its
  `environ` mapping, which defaults to `os.environ`. A key saved only in the
  Keychain does not reach the router AI check.
- `.gitignore` lists `.env`. `.env.example` holds placeholders only.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Information disclosure | A shared or synced config file leaks a secret. | No secret keys in the config. | None known. |
| Information disclosure | A status pane or error shows a secret. | `describe`; OSStatus-only errors. | None known. |
| Tampering | A stale Keychain value overrides a freshly exported variable. | Environment first. | A leftover environment variable overrides a new Keychain value. |

### 11. Mac App Store sandbox (`distribution.py`)

- `distribution.detect` selects the store build when `APP_SANDBOX_CONTAINER_ID`
  is set, or when `NETDNS_DISTRIBUTION=appstore`. It ignores an unrecognised
  override value. The override cannot turn a sandboxed process into the direct
  build.
- In the store build, `detect` switches off the shell console, privileged
  repairs, the network-order write, the unified log, the router and the
  LaunchAgent login item, and sets `requires_ai_consent`.
- `distribution.unavailable` produces outcome text that starts with
  `UNAVAILABLE_IN_APP_STORE_BUILD` and ends with `Nothing was changed.`
- `ai_consent.ConsentStore` records a versioned permission in its own file,
  outside `config.yaml`. An unreadable or corrupt file counts as not granted.
  `gate_escalator` checks the grant on every call.
- `packaging/appstore/entitlements.plist` grants `com.apple.security.app-sandbox`,
  `network.client` and `network.server`, with no temporary exception.
  `entitlements-helper.plist` grants `app-sandbox` and `inherit` only.
- `NetDnsMonitorApp.__init__` calls `detect` once and stores the result in
  `self.capabilities`. In the store build, `app.py` does the following:
  - `_menu_layout` omits "Open console", the Router submenu, "Start at Login",
    "Switch to backup now" and "Switch back to preferred now". It adds
    "Allow Claude diagnosis…", "Withdraw Claude permission" and "Privacy Policy".
  - `GATED_DASHBOARD_ACTIONS` turns the console, router console, grant, revoke
    and log buttons into `unavailable(...)` text.
  - `build_state_machine` gives the repair executor an `unavailable_fn` for the
    privileged repairs and replaces the failover step and the log reader with
    `unavailable(...)` outcomes.
  - `_manual_switch` returns `unavailable(...)` text before it touches failover.
  - The `Router` is never constructed.
- `build_escalator` wraps the escalator with `ai_consent.gate_escalator` when
  `requires_ai_consent` is true. **Allow Claude diagnosis…** shows
  `ai_consent.DISCLOSURE` before it records a grant. "Don't Allow" withdraws an
  earlier grant.
- [APP_STORE_SUBMISSION.md §1](APP_STORE_SUBMISSION.md#1-read-this-first-what-the-store-build-can-and-cannot-do)
  is the feature contract. **UNVERIFIED:** the sandboxed GUI app has not been
  launched, so no one has seen these gates in a real sandbox.

| STRIDE | Threat | Mitigation now | Residual |
|---|---|---|---|
| Elevation of privilege | The store build asks for root or rewrites network settings. | Capabilities off in `detect`; gated menu items and actions in `app.py`; no temporary-exception entitlement. | The sandbox refuses these calls even if a gate were missed. |
| Information disclosure | Incident data goes to a third-party AI without permission. | `gate_escalator` checks the consent file on every call. | None known. |
| Information disclosure | LAN hosts reach the peer socket. | None specific to the store build. | `network.server` keeps peer discovery listening. |

## Residual risks

1. **The installed NAT LaunchDaemon on the owner's Mac still runs a user-writable
   script as root.** On 2026-09-14,
   `/Library/LaunchDaemons/com.custom.router.nat.plist` pointed `ProgramArguments`
   at `/Users/mitch/dev/net-dns-monitor/router/scripts/enable_nat.sh`, a file
   owned by the user. `/Library/PrivilegedHelperTools/net-dns-monitor/` did not
   exist. Any process running as that user can edit the script and have it run as
   root within 60 s. The fix is to reinstall with the fixed installer; see
   [runbooks/router-nat-recovery.md](runbooks/router-nat-recovery.md).
2. **Peers are unauthenticated.** A host on an attached subnet can forge a peer,
   change the fault-localization verdict and evict real peers.
3. **The shell console runs any command as the user.** That is the feature. It
   adds no privilege beyond Terminal.app, but it can use the sudoers grant.
4. **Redaction is case-sensitive and removes nothing by default.** With
   `sensitive_strings: []`, hostnames, internal IPs and log lines go to Anthropic,
   and the report path goes to Slack and email.
5. **LLM output shown to humans is unverified.** Log excerpts that any local
   process can write feed the prompt. The analysis reaches the report, Slack and
   email. Nothing checks it against the evidence.
6. **The sudoers grant lets every process running as the user run the granted
   commands as root.** On 2026-09-14 a file existed at
   `/etc/sudoers.d/net-dns-monitor` on the owner's Mac, dated 2026-08-19. Its
   content was not read. See [runbooks/sudoers-grant.md](runbooks/sudoers-grant.md).
7. **Two router stacks exist.** Which one is canonical is an owner decision. The
   app's router refuses to run while the `router/` daemon is installed. Once that
   daemon is removed, stopping the app's router turns off IP forwarding for the
   whole machine.
8. **Escalation runs on the run loop.** A slow Anthropic call holds the menu bar
   during an incident, bounded by the 30 s timeout.

## Not verified live

- The `networksetup -ordernetworkservices` write.
- The sudoers grant, including `renew_dhcp_lease` through `sudo -n`.
- Slack and SMTP delivery.
- The sandboxed GUI app. Only `sandbox_probe` has run sandboxed.
- The rewritten `router.py` start and stop scripts against a real machine.
