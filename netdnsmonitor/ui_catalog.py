"""What the windows say about their own controls, apart from drawing them.

Pure data and pure functions, so the offline suite can prove two things an AppKit
window cannot be asked about: that every setting, button and menu entry has a
tooltip, and that every dashboard action is reachable from exactly one place.
`ui_style.py` is the AppKit half; this file decides nothing about pixels.

Three tables:

* `SETTING_TIPS` -- one sentence per config key, shown on the label and on the
  field in the Settings window. `settings_window.FIELDS` is the list of keys; a
  test fails if a key has no entry here.
* `ACTION_GROUPS` / `ACTION_TIPS` -- the dashboard's actions, grouped into the
  dropdown menus that replaced the button grid, and what each one does.
* `CONTROL_TIPS` -- the fixed controls of the other windows, by identifier.
"""

# --- settings --------------------------------------------------------------

SETTING_TIPS = {
    # Ping heartbeat
    "ping_host_v6": "First host pinged, over IPv6. Leave blank to skip the IPv6 ping.",
    "ping_host": "Host pinged every interval to prove the internet is reachable.",
    "ping_fallback_host": "Pinged when the main host does not answer, to tell a dead host from a dead link. Blank = off.",
    "ping_host_name": "A host NAME pinged last over IPv6, so a DNS failure shows up apart from a routing failure. Blank = off.",
    "ping_interval_seconds": "How often the heartbeat pings. Needs a restart.",
    "ping_timeout_seconds": "How long one ping waits for a reply before it counts as lost.",
    "ping_failure_threshold": "Consecutive lost pings before the app alerts. Needs a restart.",
    "ping_alert_repeat_seconds": "Repeat the ping alert this often while it stays down. 0 = alert once. Needs a restart.",
    "ping_loss_window": "How many recent pings the loss percentage is averaged over. 12 at a 5-second cadence is the last minute. Needs a restart.",
    # Incident detection
    "external_targets": "Internet addresses probed each check, as IP:port pairs. Must be literal IPs, not names. Needs a restart.",
    "internal_targets": "LAN addresses probed each check (your router, for example), as IP:port pairs. Needs a restart.",
    "poll_interval_seconds": "Seconds between full incident checks. Needs a restart.",
    "failure_threshold": "Consecutive failed checks before an incident is declared. Needs a restart.",
    "success_threshold": "Consecutive healthy checks before an incident is cleared. Needs a restart.",
    "domains": "Names resolved on every check to detect DNS faults. Empty = none; the app does not read your browser history. Needs a restart.",
    "log_lookback": "How far back the unified log is read when an incident opens, e.g. 5m. Longer values can exceed the read timeout. Needs a restart.",
    "sensitive_strings": "Text removed from anything sent to Claude: internal host names, VPN ranges. Needs a restart.",
    # Resolution monitor
    "resolution_interval_seconds": "How often every previously stalled name is looked up again. Needs a restart.",
    "resolution_stall_seconds": "A lookup this slow or slower counts as a stall. An instant NXDOMAIN is not a stall.",
    "resolution_batch_deadline_seconds": "Hard ceiling on one batch of lookups. Keep it below the batch interval.",
    "resolution_timeout_seconds": "Advisory per-lookup timeout. The batch deadline is the real cap.",
    "resolution_max_workers": "How many names are looked up in parallel.",
    # Windows and graphs
    "open_dashboard_at_launch": "Open the dashboard window when the app starts.",
    "auto_open_console": "Open the shell console when the app starts. Not available in the App Store edition.",
    "ui_refresh_seconds": "How often open windows repaint. Needs a restart.",
    "dock_refresh_seconds": "Minimum seconds between Dock tile repaints when only the round-trip time changed.",
    "history_max_samples": "How many samples the graphs keep. Needs a restart.",
    # LAN peer discovery
    "peer_discovery_enabled": "Broadcast this Mac's host name and health to the local network and listen for other copies. Needs a restart.",
    "peer_port": "UDP port used for peer discovery. Needs a restart.",
    "peer_announce_seconds": "How often this Mac announces itself to peers. Needs a restart.",
    "peer_current_seconds": "A peer heard from this recently is shown as current. Needs a restart.",
    "peer_recent_seconds": "A peer heard from this recently is shown as recent. Needs a restart.",
    "peer_probe_wait_seconds": "How long to wait for peers to answer a probe.",
    # System log viewer
    "log_view_enabled": "Show the system-log column in the dashboard. Not available in the App Store edition. Needs a restart.",
    "log_view_errors_only": "Start the log column filtered to errors. Needs a restart.",
    "log_view_backfill_window": "How much history the log column loads at launch, e.g. 15m. Needs a restart.",
    "log_view_poll_window": "How much of the log each poll reads, e.g. 1m.",
    "log_view_poll_seconds": "Seconds between log polls. Needs a restart.",
    "log_view_timeout_seconds": "How long one `log show` read may take. Needs a restart.",
    "log_view_max_entries": "Log entries kept in memory. Needs a restart.",
    "log_view_row_limit": "Most rows drawn in the log pane at once.",
    "log_view_announce_limit": "Most new errors announced per poll, so a burst is one note.",
    "log_view_noise_patterns": "Log entries containing any of these texts are dropped as noise.",
    # Network failover
    "failover_enabled": "Switch to the backup network automatically on a network incident. Off = manual switching only. Needs a restart.",
    "failover_preferred_service": "Exact macOS network service name to prefer (see `networksetup -listallnetworkservices`). Needs a restart.",
    "failover_backup_service": "Exact name of the service to switch to. Needs a restart.",
    "failover_backup_services": "More backup services, tried in order after the first. Needs a restart.",
    "failover_trigger_classifications": "Which kinds of incident may trigger a switch: network, dns. Network only by default, since moving the link rarely fixes DNS. Needs a restart.",
    "failover_failback_threshold": "Healthy ticks on the backup before switching back. Needs a restart.",
    "failover_cooldown_seconds": "Minimum seconds between switches, to stop flapping. Needs a restart.",
    "failover_max_switches_per_hour": "Hard cap on switches in an hour. Needs a restart.",
    "failover_probe_targets": "IP:port pairs used to test a candidate link before switching to it. Needs a restart.",
    "failover_probe_timeout_seconds": "Budget for the whole reachability probe. Allow about 2s per target. 0 = use the probe timeout. Needs a restart.",
    "failover_speedtest_host": "Host used to measure throughput of each link. Needs a restart.",
    "failover_speedtest_path": "URL path fetched for the throughput measurement. Needs a restart.",
    "failover_speedtest_port": "Port of the throughput host. Needs a restart.",
    "failover_speedtest_timeout_seconds": "Timeout for the throughput measurement. Needs a restart.",
    "failover_speedtest_max_bytes": "Most bytes downloaded per throughput measurement. Needs a restart.",
    # Domain learning
    "probe_timeout_seconds": "Per-connection timeout for incident probes. 0 would fail every probe, so it is refused. Needs a restart.",
    "control_domain": "A name that should always resolve; if it fails, the problem is the resolver, not the site. Needs a restart.",
    "learn_domains_from_logs": "Add names that failed in the unified log to the domains checked. Finds nothing on a stock macOS install, where the log masks host names. Needs a restart.",
    "max_learned_domains": "Most learned names kept. Needs a restart.",
    "domain_learn_interval_seconds": "How often the log is mined for names. Needs a restart.",
    # Notifications
    "slack_enabled": "Send incident alerts to Slack. The webhook URL comes from the SLACK_WEBHOOK_URL environment variable or the Keychain, never this file. Needs a restart.",
    "email_enabled": "Send incident alerts by email. Needs a restart.",
    "email_recipients": "Who receives the email, comma separated. Needs a restart.",
    "email_from": "The From address on alert email. Needs a restart.",
    "smtp_host": "SMTP server for alert email. Needs a restart.",
    "smtp_port": "SMTP server port. Needs a restart.",
    "smtp_username": "SMTP login name. The password comes from SMTP_PASSWORD or the Keychain, never this file. Needs a restart.",
    "smtp_starttls": "Upgrade the SMTP connection with STARTTLS. Needs a restart.",
    "notify_timeout_seconds": "How long a Slack or email send may take. Kept short because it runs when the network is already broken. Needs a restart.",
    # Remediation scripts
    "custom_remediation_scripts_enabled": "Off = run only the shipped scripts and ignore every file in the scripts folder, to rule your edits out. Needs a restart.",
    "remediation_scripts_dir": "Folder holding your edits to the shipped scripts and your own scripts. Needs a restart.",
    "remediation_script_timeout_seconds": "A script still running after this is reported as unknown and abandoned. Needs a restart.",
    # Fleet reporting
    "fleet_reporting_enabled": "Send incidents, the steps tried and the recovery to the central server. Used by headless mode. Needs a restart.",
    "fleet_server_address": "IP address of the central server. Blank broadcasts to this subnet. An IP is more reliable than a name during an outage. Needs a restart.",
    "fleet_port": "UDP port the fleet reports use, on both the machines and the server. Needs a restart.",
    "fleet_heartbeat_seconds": "How often this machine tells the server it is alive. Needs a restart.",
    "fleet_machine_name": "Name shown in the server's log for this Mac. Blank uses the host name. Needs a restart.",
    "fleet_allow_unsigned": "Server only. Accept reports with no signature. A trial setting: any host on the network can then claim any machine name, and the machine keys protect nothing. Needs a restart.",
    "fleet_server_enabled": "Run the central server inside the headless process. Needs a restart.",
    "fleet_server_log_path": "Server only. Append-only log of every incident, resolution and silence. Needs a restart.",
    "fleet_server_state_path": "Server only. The current picture of every machine. Needs a restart.",
    "fleet_keys_path": "Server only. The enrolled machines and each one's key. Holds every key, so it is written readable by this account alone. Needs a restart.",
    "fleet_stale_seconds": "Server only. A machine not heard from for this long is logged as silent. Needs a restart.",
    # Files and folders
    "reports_dir": "Where incident reports are written. Needs a restart.",
    "learned_domains_path": "File holding the learned domain names. Needs a restart.",
    "failover_state_path": "File remembering the network service order from before a switch. Needs a restart.",
    "resolution_log_path": "Log of every slow or failed lookup, one JSON line each. Needs a restart.",
    "forensic_log_path": "Append-only journal of every down and up event. Needs a restart.",
    "forensic_episodes_dir": "One document per outage, written when the network returns. Needs a restart.",
    "peer_record_path": "File remembering the peers seen. Needs a restart.",
    "history_path": "File the graph samples are saved to. Needs a restart.",
    # Router
    "router_enabled": "Allow the Router menu to start bootpd DHCP and NAT on this Mac. Never starts at launch. Do not run with the router/ stack. Needs a restart.",
    "wan_interface": "The upstream interface, e.g. en3. Needs a restart.",
    "lan_interface": "The interface that serves the LAN, e.g. en0. Needs a restart.",
    "lan_ip": "This Mac's address on the LAN. Needs a restart.",
    "lan_netmask": "LAN netmask. Needs a restart.",
    "dhcp_start": "First address handed out by DHCP. Needs a restart.",
    "dhcp_end": "Last address handed out by DHCP. Needs a restart.",
}

GROUP_TIPS = {
    "Ping heartbeat": "The fast, cheap check that runs every few seconds.",
    "Incident detection": "The slower check that decides whether an incident has started.",
    "Resolution monitor": "Re-resolves names that have stalled before, to see whether they recover.",
    "Windows and graphs": "What opens at launch and how often windows repaint.",
    "LAN peer discovery": "Finding other copies of this app on the local network.",
    "System log viewer": "The unified-log column in the dashboard.",
    "Network failover": "Moving to a backup network service when the preferred one fails.",
    "Domain learning": "Names the app adds to its own checks.",
    "Notifications": "Slack and email alerts. Secrets are not stored here.",
    "Remediation scripts": "Where the editable troubleshooting scripts live and how long they may run.",
    "Fleet reporting": "Headless mode and the central server: where reports go and how the server logs them. This Mac's fleet key is a credential, not a setting.",
    "Files and folders": "Where the app writes its records.",
    "Router (not with the router/ stack)": "The in-app router. Conflicts with the standalone router/ stack.",
}

# --- the dashboard ---------------------------------------------------------

# (menu title, tooltip, [action ids]). The primary actions stay as buttons; these
# are the dropdowns. An action in ALL_ACTIONS that no group names lands in "More",
# so adding one never makes it unreachable (a test also fails until it is placed).
ACTION_GROUPS = [
    (
        "Checks",
        "Read-only diagnostics. None of these changes anything.",
        [
            "check_interface_state",
            "check_default_route",
            "check_configured_dns_servers",
            "check_resolver_overrides",
            "resolve_against_public_resolver",
            "prewarm_dns",
        ],
    ),
    (
        "Repairs",
        "Steps that change system state.",
        ["flush_dns_cache"],
    ),
    (
        "Tools",
        "Windows and editors.",
        [
            "open_remediation_editor",
            "open_console",
            "open_router_window",
            "open_settings",
            "toggle_mini",
        ],
    ),
    (
        "Reports",
        "Records of what happened, and a way to test the alert path.",
        ["open_last_report", "open_forensic_dir", "test_alert"],
    ),
    (
        "Permissions",
        "The sudoers grant that lets repairs run without a password prompt.",
        ["grant_privileges", "revoke_privileges"],
    ),
]

# Actions that stay as buttons: what you reach for during an outage.
PRIMARY_ACTIONS = ("ping_now", "full_diagnosis")

MORE_GROUP = ("More", "Other actions.")

ACTION_TIPS = {
    "ping_now": "Ping the heartbeat host right now and show the result below.",
    "full_diagnosis": "Probe, classify the fault, and run every step of the matching ladder. Repairs in it change system state.",
    "check_interface_state": "Runs scutil --nwi: is the link up, and which interface is primary. Changes nothing.",
    "check_default_route": "Prints the IPv4 and IPv6 routing tables. Changes nothing.",
    "check_configured_dns_servers": "Runs scutil --dns: which resolvers the system is using. Changes nothing.",
    "check_resolver_overrides": "Lists /etc/resolver files, which silently redirect single domains. Changes nothing.",
    "resolve_against_public_resolver": "Asks a public DNS server for a known name, to tell a broken local resolver from a broken name. Changes nothing.",
    "prewarm_dns": "Resolves the 50 most-queried names from the system log so their answers are cached. Needs the system log.",
    "flush_dns_cache": "Clears the DNS cache and signals mDNSResponder. Changes system state; the signal needs the elevated-permissions grant.",
    "open_remediation_editor": "Open the Python editor for the troubleshooting scripts: edit the shipped ones or add your own.",
    "open_console": "Open the shell console. It runs whatever you type.",
    "open_router_window": "Open the in-app router window (DHCP and NAT).",
    "open_settings": "Edit every option in the configuration file.",
    "toggle_mini": "Collapse to a small floating status window.",
    "open_last_report": "Open the most recent incident report.",
    "open_forensic_dir": "Open the folder of outage records in Finder.",
    "test_alert": "Send a test alert through every enabled channel to check the path works.",
    "grant_privileges": "Install a sudoers rule that lets two exact commands run without a password. Asks for an administrator password; changes system state.",
    "revoke_privileges": "Remove that sudoers rule. Asks for an administrator password.",
    "open_dashboard": "Open the dashboard.",
}

LOG_ACTION_TIPS = {
    "log_refresh": "Read the system log again now.",
    "log_toggle_level": "Switch between errors only and every entry.",
    "log_clear_search": "Empty the search box.",
    "log_clear_buffer": "Forget the log entries held in memory and start over.",
    "log_search": "Filter the log. Terms are ANDed; put - before a term to exclude it, e.g. dns -crowdstrike.",
}

# Fixed controls in the other windows, by identifier.
CONTROL_TIPS = {
    # Settings
    "save": "Write these values to the config file. A backup of the old file is made first, and comments in it are not kept.",
    "reload": "Throw away unsaved edits and read the file again.",
    # Remediation editor
    "pick": "Choose a script to read or edit. Labels show built-in, modified or custom.",
    "editor_save": "Check the script, then save it. It applies from the next incident.",
    "editor_check": "Compile the script and validate its settings without running it.",
    "editor_run": "Run the script now, for real, and show its outcome. Repairs ask first.",
    "editor_remove": "Reset a modified built-in to the shipped version, or delete a custom script.",
    "editor_new": "Start a new custom script from a documented template.",
    "editor_text": "The script's Python source. Smart quotes and autocorrect are off.",
    "editor_output": "The script's description, or the result of the last run.",
    "editor_status": "The result of the last Save, Check or Run.",
    # Console
    "console_input": "Type a shell command and press Return. :help lists the built-ins; q closes the window.",
    "console_transcript": "Everything typed and printed in this console.",
    # Dashboard panes
    "stats": "Current network statistics and the settings in force.",
    "output": "Results of anything run from the dashboard.",
    "log_pane": "Recent system-log entries, filtered by the controls above.",
    "log_status": "How many log entries were read and how many are errors.",
    "graph_rtt_ms": "Round-trip time of recent pings.",
    "graph_down_bps": "Download throughput measured on the active link.",
    "graph_up_bps": "Upload throughput measured on the active link.",
    "mini_label": "Current network status. Click to expand the dashboard.",
}


def group_actions(actions: list) -> tuple[list, list]:
    """Split the dashboard's available actions into buttons and dropdown menus.

    `actions` is `(label, action_id, kind)` triples, already filtered for this
    build. Returns `(primary, groups)`: `primary` is the actions kept as buttons,
    in `PRIMARY_ACTIONS` order; `groups` is `(title, tooltip, [triples])` with
    empty groups dropped, so the store build shows no empty menu. Every action
    appears exactly once: one no group names goes to "More".
    """
    by_id = {action[1]: action for action in actions}
    primary = [by_id[i] for i in PRIMARY_ACTIONS if i in by_id]
    placed = {a[1] for a in primary}
    groups = []
    for title, tip, ids in ACTION_GROUPS:
        members = [by_id[i] for i in ids if i in by_id and i not in placed]
        placed.update(a[1] for a in members)
        if members:
            groups.append((title, tip, members))
    leftover = [a for a in actions if a[1] not in placed]
    if leftover:
        groups.append((MORE_GROUP[0], MORE_GROUP[1], leftover))
    return primary, groups


def action_tip(action_id: str, kind: str = "check") -> str:
    """Tooltip for an action. A repair always says it changes system state."""
    tip = ACTION_TIPS.get(action_id) or "Run this troubleshooting step."
    if kind == "repair" and "changes system state" not in tip.lower():
        tip += " Changes system state."
    return tip


# --- options that are not config keys --------------------------------------

CREDENTIAL_ENTRIES = [
    (
        "Set Anthropic API key…",
        "cred_ANTHROPIC_API_KEY",
        "Store the Anthropic API key in the Keychain. Used for Claude diagnosis when the ladder cannot fix an incident.",
    ),
    (
        "Set Slack webhook URL…",
        "cred_SLACK_WEBHOOK_URL",
        "Store the Slack incoming-webhook URL in the Keychain. The URL is itself a credential.",
    ),
    (
        "Set SMTP password…",
        "cred_SMTP_PASSWORD",
        "Store the password for the SMTP login in the Keychain.",
    ),
    (
        "Set fleet machine key…",
        "cred_FLEET_MACHINE_KEY",
        "Store this Mac's own fleet key in the Keychain. Create it on the server with: netdns fleet enroll <name>.",
    ),
    (
        "Remove saved credentials",
        "cred_remove",
        "Delete every credential this app stored in the Keychain.",
    ),
]


def app_options(caps) -> list:
    """Settings that live outside config.yaml, as control specs for the Settings window.

    `caps` is `distribution.Capabilities`. Each spec is one of
    `("check", id, title, tip)`, `("menu", title, tip, [(label, id, tip), ...])` or
    `("button", id, title, tip)`. The build decides which exist: the store edition
    has no login item, no root grant and no script editor, and a control it
    cannot honour is not offered.
    """
    specs: list = []
    if caps.launch_agent_login_item:
        specs.append(
            (
                "check",
                "app_toggle_login",
                "Start at login",
                "Install or remove a login item so the app starts when you log in.",
            )
        )
    specs.append(
        (
            "check",
            "app_toggle_claude",
            "Allow Claude diagnosis",
            "Allow incident details to be sent to Anthropic for diagnosis. Shows exactly what is sent first. Untick to withdraw.",
        )
    )
    specs.append(
        (
            "menu",
            "Credentials",
            "API key, Slack webhook and SMTP password. They are kept in the Keychain, never in the config file.",
            list(CREDENTIAL_ENTRIES),
        )
    )
    if caps.privileged_repairs:
        specs.append(
            (
                "menu",
                "Permissions",
                "The sudoers grant that lets repairs run without a password prompt.",
                [
                    (
                        "Grant elevated permissions",
                        "grant_privileges",
                        ACTION_TIPS["grant_privileges"],
                    ),
                    (
                        "Revoke elevated permissions",
                        "revoke_privileges",
                        ACTION_TIPS["revoke_privileges"],
                    ),
                ],
            )
        )
    if caps.remediation_editor:
        specs.append(
            (
                "button",
                "open_remediation_editor",
                "Edit scripts…",
                ACTION_TIPS["open_remediation_editor"],
            )
        )
    return specs
