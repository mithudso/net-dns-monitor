"""Load user-configurable monitoring settings. Domains defaults to an empty
list rather than auto-detecting "most visited sites" from browser history --
that would need reading another app's data, which is an explicit opt-in the
user should choose, not a silent default (see the plan's probing-strategy
section).
"""

import copy
import difflib
import ipaddress
import math
import os
import re
import warnings
from collections.abc import Mapping
from typing import Optional

import yaml

from netdnsmonitor.classifier import Classification
from netdnsmonitor.system_log import DEFAULT_NOISE_PATTERNS

DEFAULT_CONFIG = {
    "external_targets": [["1.1.1.1", 443], ["8.8.8.8", 443]],
    "internal_targets": [],
    "domains": [],
    "poll_interval_seconds": 30,
    # Per-probe deadline, shared across all domain lookups in one tick.
    "probe_timeout_seconds": 2.0,
    "failure_threshold": 2,
    "success_threshold": 2,
    "log_lookback": "5m",
    "sensitive_strings": [],
    "reports_dir": "~/Library/Application Support/net-dns-monitor/reports",
    # Stalled-domain resolution monitor: re-resolve every domain that has ever
    # stalled (per the resolution log itself) on a fixed cadence, independent
    # of the `domains` list above (which drives incident detection). This
    # replaced an earlier "top-N busiest domains from the query log" selection;
    # `resolution_lookback` / `resolution_top_n` are therefore retired.
    "resolution_log_path": "~/Library/Application Support/net-dns-monitor/resolution-log.jsonl",
    "resolution_interval_seconds": 300,
    # A lookup counts as a stall at or above this many seconds. Keys on elapsed
    # time, not on failure: an instant NXDOMAIN is a fast definitive answer,
    # not a stall.
    "resolution_stall_seconds": 1.0,
    # Wall-clock ceiling for one batch. Must stay under
    # resolution_interval_seconds -- the stall list only grows and getaddrinfo
    # cannot be bounded per lookup, so this is what actually caps a cycle.
    "resolution_batch_deadline_seconds": 240,
    # Not enforceable per lookup: socket.setdefaulttimeout() does not bound
    # getaddrinfo. Kept because it documents the intended per-lookup ceiling
    # and ResolveFn requires the parameter; resolution_batch_deadline_seconds
    # is what actually caps a cycle. (Note the injected resolvers in the tests
    # accept the argument and ignore it too -- nothing honours this value.)
    "resolution_timeout_seconds": 2.0,
    "resolution_max_workers": 10,
    # Fast liveness heartbeat, separate from the incident poll above. One ICMP
    # echo requests to ordered targets every few seconds; it drives the menu bar
    # stats, the Dock tile, and the network-failed alert, and never the repair
    # ladder or escalation. See ping.py for why this uses ICMP while prober.py
    # deliberately does not.
    # Pinged before ping_host; blank or null turns it off. A native IPv6 reply
    # supports IPv6-only links, but NAT64-only test networks may not route a
    # native IPv6 literal. ICMP failure is not proof of a network outage.
    "ping_host_v6": "2001:4860:4860::8888",
    "ping_host": "8.8.8.8",
    "ping_fallback_host": "1.1.1.1",
    "ping_interval_seconds": 5,
    # Bounds the entire heartbeat across all targets, so keep it
    # comfortably under ping_interval_seconds.
    "ping_timeout_seconds": 2.0,
    # Consecutive failed pings before the alert fires.
    #
    # 1 is the literal reading of "if it fails a ping, alert" and was the original
    # default. It was changed to 2 on evidence from this machine: three episodes
    # in ~22 minutes, of which one was a real 2m35s outage (corroborated by the
    # anti-flap gate reporting external_reachable: False) and the rest cleared
    # within a single 5-second tick -- i.e. lone dropped Wi-Fi packets, each one
    # opening a forensic episode and bouncing the Dock.
    #
    # At 2, a single lost echo request is ignored and a real outage still alerts
    # within 10 seconds. Set it back to 1 if you would rather see every dropped
    # packet.
    "ping_failure_threshold": 2,
    # 0 means one alert per outage: the alert fires on the failure edge and then
    # stays quiet until pings succeed again. Set it to e.g. 300 to be re-alerted
    # every 5 minutes while the network stays down. The Dock bounce is a
    # critical-priority request that keeps bouncing until the app is activated,
    # so a long outage stays visible without any repeat.
    "ping_alert_repeat_seconds": 0,
    # How many recent pings the loss percentage in the menu bar averages over.
    # 12 at a 5-second cadence is the last minute.
    "ping_loss_window": 12,
    # Forensic record of every down/up episode. The journal is appended to as
    # each event happens, so an app killed mid-outage still leaves evidence; the
    # per-episode documents are written when the network comes back. See
    # forensic_log.py for what counts as one episode across the two detectors.
    "forensic_log_path": "~/Library/Application Support/net-dns-monitor/forensic-log.jsonl",
    "forensic_episodes_dir": "~/Library/Application Support/net-dns-monitor/episodes",
    # How often the dashboard window repaints and picks up the results of any
    # troubleshooting step run from it. Only costs a queue poll and a string
    # comparison while the window is closed.
    "ui_refresh_seconds": 1,
    # How often the Dock tile may be repainted when only the round-trip number has
    # changed. A status change (healthy/flaky/incident) always repaints
    # immediately. This exists because setApplicationIconImage_ is synchronous and
    # measured at ~2 seconds per call on the main thread -- at the 5-second
    # heartbeat it would block the run loop for most of every cycle.
    "dock_refresh_seconds": 30,
    # Open the dashboard window shortly after launch, so there is a visible
    # window without having to find a menu first. It is ordered front WITHOUT
    # stealing focus -- this starts from a launchd agent at login, and yanking
    # focus every login would be its own annoyance. Set false to keep it closed
    # until you ask for it.
    "open_dashboard_at_launch": True,
    # --- LAN peer discovery ------------------------------------------------
    # Announce this instance on the local network and look for other copies of
    # the monitor. Off means no socket is opened and nothing is broadcast.
    #
    # This DISCLOSES this machine's hostname and whether its network is healthy
    # to anything on the same LAN. That is the point of the feature, but it is a
    # disclosure, so it has its own switch. Nothing received over this socket is
    # ever used as a path, a command, or an argument; see peer_net.py.
    "peer_discovery_enabled": True,
    "peer_port": 45737,
    # Re-announce and heartbeat every known peer on this cadence.
    "peer_announce_seconds": 300,
    # A peer heard from within this window counts as "current". Two announce
    # intervals by default, so one dropped broadcast is not a demotion.
    "peer_current_seconds": 600,
    # Heard from within this window but not the one above: "recent". Older than
    # this: "other", kept as history.
    "peer_recent_seconds": 86400,
    "peer_record_path": "~/Library/Application Support/net-dns-monitor/peers.json",
    # When an outage starts, peers are probed immediately rather than at the next
    # 5-minute sweep, and the fault-localization verdict is computed this many
    # seconds later -- long enough for pongs to come back over a LAN, short enough
    # that the answer is still about the outage in progress.
    "peer_probe_wait_seconds": 3,
    # --- graph history -----------------------------------------------------
    # Rolling window of heartbeat samples behind the graphs. 720 at the default
    # 5s cadence is the last hour. Appended one line per sample and compacted
    # when the file outgrows the window.
    "history_path": "~/Library/Application Support/net-dns-monitor/history.jsonl",
    "history_max_samples": 720,
    # --- system log viewer -------------------------------------------------
    # The window's right-hand column reads the network-related parts of macOS's
    # unified log. Every number here came out of measuring `log show` on this
    # machine; see system_log.py for the measurements themselves.
    "log_view_enabled": True,
    # Read once at launch so the pane is not empty for the first poll interval.
    # 15 minutes measured 4.2s; 60 minutes measured 16.9s, which is why the
    # backfill is bounded and the steady-state poll below is not.
    "log_view_backfill_window": "15m",
    # Deliberately longer than log_view_poll_seconds: the windows overlap so
    # nothing falls between two polls, and LogBuffer de-duplicates the overlap.
    "log_view_poll_window": "1m",
    "log_view_poll_seconds": 30,
    # Not the 10s used for the incident-report log excerpt. A 1-minute window
    # measured 1.4s, but `log show` is scanning an archive and the machine is not
    # always idle -- and a timeout here shows as text in the pane, not as an
    # empty log.
    "log_view_timeout_seconds": 45,
    "log_view_max_entries": 3000,
    # Error and fault only. All levels over the same subsystems measured 192,901
    # lines in 30 minutes, which is not a thing anyone can read; the same window
    # filtered to errors was 919. The button above the pane switches this at
    # runtime.
    "log_view_errors_only": True,
    # Rows drawn into the pane. Identical messages are already collapsed into one
    # counted row before this applies.
    "log_view_row_limit": 400,
    # How many new error lines per poll are announced into the results pane on the
    # left. A cap, not a filter: everything still lands in the log pane. Without
    # it, one repeating message would push every manual result out of the pane.
    "log_view_announce_limit": 3,
    # Substrings that drop an entry entirely. These four are high-frequency
    # framework complaints from unrelated software on this machine, and they were
    # burying the one line that mattered. Commas separate entries in the settings
    # window, so a pattern containing a comma has to be edited in this file.
    "log_view_noise_patterns": list(DEFAULT_NOISE_PATTERNS),
    # A name expected to always resolve, probed alongside `domains`. It is the
    # control that lets a dead learned name be told apart from a broken
    # resolver (see app.anchor_domains); set to null to drop it. Defaults to the
    # Anthropic API host because this app already depends on resolving it -- if
    # the control fails, LLM escalation was going to fail too, so the control
    # result carries real operational meaning rather than being an arbitrary
    # canary.
    "control_domain": "api.anthropic.com",
    # Auto-learn monitored domains from failed DNS resolutions in the log.
    "learn_domains_from_logs": True,
    "learned_domains_path": ("~/Library/Application Support/net-dns-monitor/learned_domains.json"),
    "max_learned_domains": 20,
    "domain_learn_interval_seconds": 300,
    # Automatically open console window below log viewer on right-hand side on startup.
    "auto_open_console": True,
    # Notifications. Secrets are NOT here: the Slack webhook URL comes from
    # SLACK_WEBHOOK_URL and the SMTP password from SMTP_PASSWORD, so a config
    # file that gets shared or synced carries no credential.
    "slack_enabled": True,
    "email_enabled": True,
    "email_recipients": [],
    "email_from": "net-dns-monitor@localhost",
    "smtp_host": "localhost",
    "smtp_port": 587,
    "smtp_username": None,
    "smtp_starttls": True,
    "notify_timeout_seconds": 5,
    # --- automatic network failover -------------------------------------
    # Off by default, and deliberately so: this is the only feature that
    # rewrites system network configuration, and it cannot guess which of the
    # machine's services is the wired link the user actually prefers. Both
    # service names must be given verbatim as they appear in
    # `networksetup -listnetworkserviceorder`; a name that does not match is
    # reported as a failure with the available list, never fuzzy-matched.
    "failover_enabled": False,
    "failover_preferred_service": None,
    # One backup, or an ordered list of them. With several, every one that is
    # independently confirmed reachable gets benchmarked and the fastest wins
    # outright -- the list order only breaks ties.
    "failover_backup_service": None,
    "failover_backup_services": [],
    # What the interface prober aims at, when that must differ from
    # `external_targets`. Empty means "use external_targets". See
    # failover.failover_probe_targets for why the two are separable.
    "failover_probe_targets": [],
    # One deadline is spent across ALL failover probe targets, so the budget is
    # a function of how many are listed. 0 means "use probe_timeout_seconds".
    "failover_probe_timeout_seconds": 0,
    # Throughput measurement. Set the host to "" to turn it off, in which case
    # ranking falls back to reachability and configured order rather than
    # inventing numbers. The default endpoint serves an exact byte count over
    # plain HTTPS with no account or redirect, which is what makes it usable
    # from an interface-bound socket.
    "failover_speedtest_host": "speed.cloudflare.com",
    "failover_speedtest_path": "/__down?bytes=2000000",
    "failover_speedtest_port": 443,
    "failover_speedtest_timeout_seconds": 5.0,
    "failover_speedtest_max_bytes": 2000000,
    # Which incident classifications may move the link. Network-only: a DNS
    # fault is usually local, and changing the physical path will not fix it.
    "failover_trigger_classifications": ["network"],
    # Asymmetric on purpose. Failover happens on the first qualifying incident
    # (already debounced by failure_threshold); failback waits for the
    # preferred link to prove itself over several consecutive checks, so a
    # flapping link cannot drag the machine back and forth.
    "failover_failback_threshold": 3,
    "failover_cooldown_seconds": 300,
    # A hard ceiling on churn. Once spent, the machine stays wherever it is
    # until the rolling hour frees a slot -- including, if the budget ran out
    # mid-outage, on a preferred link that is still down. That is the cost of
    # bounding oscillation; raise the ceiling if you would rather have the
    # switching. 0 disables AUTOMATIC switching; the menu bar buttons and
    # `netdns failover backup` still work, because a person clicking a button
    # has supplied the judgement the brakes stand in for.
    "failover_max_switches_per_hour": 4,
    "failover_state_path": ("~/Library/Application Support/net-dns-monitor/failover.json"),
    # --- in-app router (NAT + DHCP) ----------------------------------------
    # Off by default. When on, App.__init__ builds netdnsmonitor/router.py's
    # Router from these but never starts it; Router > Start (or the router
    # window) starts it with administrator rights. That router
    # and the standalone router/ stack both rewrite pf NAT rules and serve DHCP
    # on the LAN interface, so they conflict: run one or the other, never both.
    # The values match the fallbacks app.py used before these keys existed.
    "router_enabled": False,
    "wan_interface": "en3",
    "lan_interface": "en0",
    "lan_ip": "192.168.10.1",
    "lan_netmask": "255.255.255.0",
    "dhcp_start": "192.168.10.100",
    "dhcp_end": "192.168.10.200",
}

# Every key load_config runs through expanduser. One list, so a new path-valued
# key is added in one place -- the settings window collapses the same keys back
# to "~" when it saves.
PATH_KEYS = (
    "reports_dir",
    "resolution_log_path",
    "forensic_log_path",
    "forensic_episodes_dir",
    "peer_record_path",
    "history_path",
    "learned_domains_path",
    "failover_state_path",
)

# Keys whose consumers iterate them. A str is iterable too, so a bare string is
# refused rather than iterated a character at a time.
LIST_KEYS = (
    "domains",
    "sensitive_strings",
    "log_view_noise_patterns",
    "email_recipients",
    "failover_backup_services",
    "failover_trigger_classifications",
)

# `key:` with every item beneath it commented out loads as None, not []. For
# these keys an empty list is the only reading, and None reaches code that
# iterates it: redact(text, None) raises TypeError on the incident edge, and the
# notification and forensic record for that incident are lost.
# failover_trigger_classifications is deliberately absent -- null there means
# "use the default"; see normalize_config.
EMPTY_WHEN_NULL = (
    "domains",
    "sensitive_strings",
    "log_view_noise_patterns",
    "email_recipients",
    "failover_backup_services",
    "internal_targets",
    "failover_probe_targets",
)

TARGET_KEYS = ("external_targets", "internal_targets", "failover_probe_targets")

# A timeout or interval of 0 is not "fast". A socket timeout of 0 makes connect
# non-blocking, so it fails at once with BlockingIOError; every tick then reads
# as a network incident on a healthy link, and the app runs repairs, fails over
# and escalates. A negative timeout raises ValueError instead of OSError.
POSITIVE_KEYS = (
    "poll_interval_seconds",
    "probe_timeout_seconds",
    "ping_interval_seconds",
    "ping_timeout_seconds",
    "resolution_interval_seconds",
    "domain_learn_interval_seconds",
    "resolution_batch_deadline_seconds",
    "resolution_timeout_seconds",
    "ui_refresh_seconds",
    "dock_refresh_seconds",
    "peer_announce_seconds",
    "log_view_poll_seconds",
    "log_view_timeout_seconds",
    "notify_timeout_seconds",
    "failover_speedtest_timeout_seconds",
    # A cap of 0 or less would make every throughput sample empty.
    "failover_speedtest_max_bytes",
    # ThreadPoolExecutor(max_workers=0) raises ValueError, so every resolution
    # batch failed.
    "resolution_max_workers",
)

PORT_KEYS = ("peer_port", "smtp_port", "failover_speedtest_port")

# Every other numeric key. 0 is meaningful for some of these (no re-alert, no
# automatic switching), so only the type is checked. A null loads as None, and
# None reached float() inside load_config itself, or a comparison on every tick.
NUMBER_KEYS = (
    "failure_threshold",
    "success_threshold",
    "resolution_stall_seconds",
    "ping_failure_threshold",
    "ping_alert_repeat_seconds",
    "ping_loss_window",
    "peer_current_seconds",
    "peer_recent_seconds",
    "peer_probe_wait_seconds",
    "history_max_samples",
    "log_view_max_entries",
    "log_view_row_limit",
    "log_view_announce_limit",
    "max_learned_domains",
    "domain_learn_interval_seconds",
    "failover_probe_timeout_seconds",
    "failover_speedtest_max_bytes",
    "failover_failback_threshold",
    "failover_cooldown_seconds",
    "failover_max_switches_per_hour",
)

# Counts that reach a deque maxlen, a slice or a list index. A float there
# raises TypeError (deque(maxlen=12.5), rows[:400.5]) and, for log_view_max_entries,
# 0 raises IndexError in LogBuffer.add -- so each needs a whole number, with the
# minimum below. 0 is meaningful for the "limit" keys (show/announce nothing, no
# learning), so only the keys that size a buffer must be at least 1.
INT_KEYS = {
    "log_view_max_entries": 1,
    "ping_loss_window": 1,
    "log_view_row_limit": 0,
    "log_view_announce_limit": 0,
    "history_max_samples": 0,
    "max_learned_domains": 0,
}

# Keys that were once configurable and are retired. A user file that still
# carries one is stale, not mistaken, so it is not reported as unknown.
RETIRED_KEYS = frozenset({"resolution_lookback", "resolution_top_n"})

# router.py interpolates these into a shell script that runs with administrator
# rights, so anything but an address or an interface name is refused before it
# can get there. Checked only while router_enabled is on: nothing reads them
# otherwise, and a stale value must not stop the monitor from starting.
ROUTER_ADDRESS_KEYS = ("lan_ip", "lan_netmask", "dhcp_start", "dhcp_end")
ROUTER_INTERFACE_KEYS = ("wan_interface", "lan_interface")
# BSD interface names: a letter, then letters or digits (en0, bridge100, utun3),
# at most 15 characters because IFNAMSIZ is 16 including the terminator.
_INTERFACE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9]{0,14}")


class ConfigError(ValueError):
    """A value load_config refuses. `key` names the offending config key, so the
    settings window can put the field's label in front of the message.
    """

    def __init__(self, key: str, message: str):
        super().__init__(message)
        self.key = key


def _is_port(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _is_number(value) -> bool:
    # bool is an int subclass, and `true` for a threshold is a typo, not 1.
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _is_text(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def host_problem(host) -> Optional[str]:
    """Why `host` cannot be handed to ping as an argument, or None if it can.

    The one predicate ping_once and the config share, so a value the config
    accepts is never one the heartbeat then refuses on every tick. `--` is not
    relied on to protect the argv; refusing a leading "-" is the guard.
    """
    if not isinstance(host, str) or not host:
        return f"expected a host name or address, got {host!r}"
    if host[0] == "-":
        return f"a host name cannot start with '-', got {host!r}"
    if " " in host or not host.isprintable():
        return f"a host name cannot contain whitespace or unprintable characters, got {host!r}"
    return None


def domain_problem(name) -> Optional[str]:
    """Why `name` cannot be resolved as a DNS name, or None if it can.

    getaddrinfo raises UnicodeError for a name the IDNA codec cannot encode
    (an empty label, a label over 63 characters), and TypeError for a
    non-string. Either would surface on every tick, and a probe error is not
    evidence of a DNS outage. A URL or user@host can never resolve, which reads
    as a permanent DNS failure on a healthy network.
    """
    if not isinstance(name, str):
        return f"expected a domain name, got {name!r}"
    if not name.strip() or name != name.strip():
        return f"a domain name cannot be blank or padded with whitespace, got {name!r}"
    if any(ch in name for ch in "/:@"):
        return f"expected a bare domain name, not a URL or address, got {name!r}"
    if len(name) > 253:
        return "a domain name is at most 253 characters"
    try:
        name.encode("idna")
    except UnicodeError:
        return f"not a valid domain name (empty or over-long label), got {name!r}"
    return None


def min_learn_interval(poll_seconds: float) -> float:
    """Shortest sensible domain_learn_interval_seconds for a poll interval.

    At or below the poll interval a dead domain is re-added on every tick, so
    the flap gate's success counter never resets and one dead name latches a
    permanent false incident. Pruning needs clean ticks in between, hence 2x.
    """
    return float(poll_seconds) * 2


def target_problem(entry) -> Optional[str]:
    """Why `entry` is not an [IP address, port] pair, or None if it is one.

    IP literals only. A hostname is resolved inside create_connection, where the
    probe timeout does not bound the lookup, and a resolver failure there reads
    as "internet unreachable" -- a DNS fault reported as a network one. A scoped
    IPv6 address such as fe80::1%en0 is an IP literal and is accepted.
    """
    if isinstance(entry, str) or not isinstance(entry, (list, tuple)) or len(entry) != 2:
        return f"expected an [IP, port] pair, got {entry!r}"
    host, port = entry
    try:
        if not isinstance(host, str):
            raise ValueError(host)
        ipaddress.ip_address(host)
    except ValueError:
        return f"expected an IP address (hostnames are not accepted), got {host!r}"
    if not _is_port(port):
        return f"expected a port from 1 to 65535, got {port!r}"
    return None


# `log show --last` windows. YAML reads `300` as an int, and an int in a
# subprocess argv raises TypeError inside the log reader -- which the incident
# pipeline turns into an empty excerpt list that reads as "nothing matched".
# A bare number is valid `--last` syntax (seconds), so the int has one safe
# reading: its text.
LOG_WINDOW_KEYS = ("log_lookback", "log_view_poll_window", "log_view_backfill_window")


def normalize_config(config: dict) -> None:
    """Replace a null that has exactly one safe reading with that reading, in place."""
    for key in LOG_WINDOW_KEYS:
        value = config.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            config[key] = str(value)
    for key in EMPTY_WHEN_NULL:
        if key in config and config[key] is None:
            config[key] = []
    if config.get("failover_trigger_classifications", []) is None:
        # Null means the default. It is written out rather than left null so the
        # settings window shows the list in force: shown blank, a save would
        # write [] and silently disable automatic failover.
        config["failover_trigger_classifications"] = list(
            DEFAULT_CONFIG["failover_trigger_classifications"]
        )


def validate_config(config: dict) -> None:
    """Raise ConfigError, naming the key, for a value the app would misread.

    Checks only the keys present, so the settings window can check just the
    fields it was sent.
    """
    # Catch the wrong type that fails silently instead of loudly. `domains:
    # example.com` -- the natural way to write a single entry -- becomes 11
    # single-character lookups. Every one fails, dns_ok goes False on a healthy
    # network, the flap gate latches an incident, and the app runs real repairs
    # and escalates, forever. `sensitive_strings` as a bare string redacts every
    # occurrence of each letter from the report. `log_view_noise_patterns` makes
    # every character a suppression pattern, so the log pane shows nothing.
    # `failover_trigger_classifications: network` becomes a set of letters that
    # no classification matches, so failover never triggers, and a bare
    # `email_recipients` address is mailed one character at a time.
    for key in LIST_KEYS:
        if key in config and isinstance(config[key], str):
            raise ConfigError(
                key,
                f"config key '{key}' must be a list of strings, not the "
                f"single string {config[key]!r} -- wrap it in a list, e.g. "
                f"[{config[key]!r}]. A bare string is iterated "
                f"character-by-character by the code that consumes it.",
            )

    # A mapping iterates its keys and an int does not iterate at all; neither is
    # "a list of strings". None is left to normalize_config.
    for key in LIST_KEYS:
        value = config.get(key)
        if value is not None and not isinstance(value, (str, list, tuple)):
            raise ConfigError(
                key,
                f"config key '{key}' must be a list of strings, got {type(value).__name__}",
            )

    # Items must be strings too. YAML reads an unquoted `-1009` as an int, and
    # an int in log_view_noise_patterns raises TypeError on `in` inside the log
    # filter, so the dashboard never opens and log announcements are lost.
    # sensitive_strings is exempt: redact() already reads each item with str().
    for key in LIST_KEYS:
        if key == "sensitive_strings" or not isinstance(config.get(key), (list, tuple)):
            continue
        for item in config[key]:
            if not isinstance(item, str):
                raise ConfigError(
                    key,
                    f"config key '{key}' must be a list of strings; {item!r} is not a "
                    f"string -- quote it",
                )

    for key in LOG_WINDOW_KEYS:
        if key in config and not (isinstance(config[key], str) and config[key].strip()):
            raise ConfigError(
                key,
                f"config key '{key}' must be a `log show --last` window such as "
                f"'5m' or '300', got {config[key]!r}",
            )

    for key in TARGET_KEYS:
        if key not in config:
            continue
        targets = config[key]
        if not isinstance(targets, (list, tuple)):
            raise ConfigError(
                key, f"config key '{key}' must be a list of [IP, port] pairs, got {targets!r}"
            )
        for entry in targets:
            problem = target_problem(entry)
            if problem is not None:
                raise ConfigError(key, f"config key '{key}': {problem}")

    for key in POSITIVE_KEYS:
        if key in config and not (_is_number(config[key]) and config[key] > 0):
            raise ConfigError(
                key, f"config key '{key}' must be a number greater than 0, got {config[key]!r}"
            )

    for key in NUMBER_KEYS:
        if key in config and not _is_number(config[key]):
            raise ConfigError(key, f"config key '{key}' must be a number, got {config[key]!r}")

    for key in INT_KEYS:
        if key not in config:
            continue
        value = config[key]
        minimum = INT_KEYS[key]
        if not (_is_number(value) and float(value).is_integer() and value >= minimum):
            raise ConfigError(
                key,
                f"config key '{key}' must be a whole number of at least {minimum}, got {value!r}",
            )

    # `failover_enabled: "false"` is a non-empty string and so truthy: it arms
    # automatic failover. None is not False either, so a null is refused too.
    for key, default in DEFAULT_CONFIG.items():
        if isinstance(default, bool) and key in config and not isinstance(config[key], bool):
            raise ConfigError(key, f"config key '{key}' must be true or false, got {config[key]!r}")

    # Blank is not "don't ping": `ping ""` cannot resolve the host and exits 68,
    # so every heartbeat is a lost ping and the alert fires on a healthy network.
    # A value ping_once would refuse makes every heartbeat raise, so the
    # heartbeat dies silently. v6 and the fallback may be blank (off).
    for key in ("ping_host", "ping_host_v6", "ping_fallback_host"):
        if key not in config:
            continue
        value = config[key]
        if key != "ping_host" and (value is None or value == ""):
            continue
        problem = host_problem(value)
        if problem is not None:
            raise ConfigError(key, f"config key '{key}': {problem}")

    # `reports_dir:` with nothing after it loads as None, and expanduser(None)
    # raises TypeError, which names no key. A blank path is refused too: it
    # expands to "", and every write to it fails.
    for key in PATH_KEYS:
        if key in config and not _is_text(config[key]):
            raise ConfigError(key, f"config key '{key}' must be a path, got {config[key]!r}")

    for key in PORT_KEYS:
        if key in config and not _is_port(config[key]):
            raise ConfigError(
                key, f"config key '{key}' must be a port from 1 to 65535, got {config[key]!r}"
            )

    if "domains" in config and isinstance(config["domains"], (list, tuple)):
        for item in config["domains"]:
            problem = domain_problem(item)
            if problem is not None:
                raise ConfigError("domains", f"config key 'domains': {problem}")
    if config.get("control_domain") is not None:
        problem = domain_problem(config["control_domain"])
        if problem is not None and config["control_domain"] != "":
            raise ConfigError("control_domain", f"config key 'control_domain': {problem}")

    # With no configured domain and no control domain, the DNS probe has no name
    # to resolve until one is learned. dns_ok is then None, classify() returns
    # UNCLASSIFIED, and the state machine counts that as a failing tick -- a
    # permanent incident, with its alert and escalation, on a healthy network.
    has_both = "domains" in config and "control_domain" in config
    if has_both and not config["domains"] and not config["control_domain"]:
        raise ConfigError(
            "control_domain",
            "config key 'control_domain' cannot be empty while 'domains' is "
            "empty: with no name to resolve, every check reads as unclassified "
            "and latches a permanent incident. Set control_domain or add a domain.",
        )

    triggers = config.get("failover_trigger_classifications")
    if isinstance(triggers, (list, tuple)):
        allowed = {c.value for c in Classification} - {Classification.HEALTHY.value}
        for item in triggers:
            if item not in allowed:
                raise ConfigError(
                    "failover_trigger_classifications",
                    f"config key 'failover_trigger_classifications': {item!r} is not "
                    f"one of {sorted(allowed)}",
                )

    if config.get("router_enabled"):
        for key in ROUTER_ADDRESS_KEYS:
            if key not in config:
                continue
            try:
                if not isinstance(config[key], str):
                    raise ValueError(config[key])
                ipaddress.IPv4Address(config[key])
            except ValueError:
                raise ConfigError(
                    key, f"config key '{key}' must be an IPv4 address, got {config[key]!r}"
                ) from None
        for key in ROUTER_INTERFACE_KEYS:
            value = config.get(key)
            if key in config and not (isinstance(value, str) and _INTERFACE_NAME.fullmatch(value)):
                raise ConfigError(
                    key,
                    f"config key '{key}' must be an interface name such as en0, got {value!r}",
                )


def load_config(path: str, default_overrides: Optional[Mapping[str, object]] = None) -> dict:
    # deepcopy, not dict(): the list defaults would otherwise be the same
    # objects in every load, and an append to one config's `domains` would
    # show up in the next.
    config = copy.deepcopy(DEFAULT_CONFIG)
    # Applied under the user's file, so a build-specific default never
    # overrides what someone actually set.
    config.update(default_overrides or {})
    user_keys: list = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
        if not isinstance(user_config, dict):
            # `or {}` above only rescues a falsy root (None from an empty or
            # fully commented-out file). A truthy non-dict root -- a top-level
            # YAML list, or a bare scalar -- reaches dict.update and raises an
            # opaque message that never names the file. Relaunching the built
            # .app from the Dock bypasses start.sh's guard, so that surfaces as
            # "the menu bar app simply never appeared".
            raise ValueError(
                f"config file {path} must contain a YAML mapping of key: value "
                f"pairs, got a top-level {type(user_config).__name__}"
            )
        config.update(user_config)
        user_keys = [k for k in user_config if isinstance(k, str)]

    normalize_config(config)
    try:
        validate_config(config)
    except ConfigError as exc:
        # Name the file as well as the key: the app can be launched from the
        # Dock, where nothing else says which config was read.
        raise ConfigError(exc.key, f"{exc} (in {path})") from None

    for path_key in PATH_KEYS:
        config[path_key] = os.path.expanduser(config[path_key])
        # A relative path lands wherever the app was launched from -- the Dock
        # launches with "/" as the working directory -- and `$HOME` is not
        # expanded, so it would create a literal "$HOME" directory.
        if not os.path.isabs(config[path_key]):
            raise ConfigError(
                path_key,
                f"config key '{path_key}' must be an absolute path or start with ~, "
                f"got {config[path_key]!r} (in {path})",
            )

    # Names only, never values: sensitive_strings is a likely typo target and
    # its value is the secret.
    unknown = sorted(set(user_keys) - set(DEFAULT_CONFIG) - RETIRED_KEYS)
    if unknown:
        hints = []
        for key in unknown:
            close = difflib.get_close_matches(key, list(DEFAULT_CONFIG), n=1)
            hints.append(f"{key} (did you mean {close[0]}?)" if close else key)
        warnings.warn(
            f"config file {path} has unknown keys, ignored: " + ", ".join(hints),
            UserWarning,
            stacklevel=2,
        )

    # A learn interval at or below the poll interval re-adds a dead domain on
    # every tick, so the flap gate's success counter can never reset and one
    # dead name latches a permanent false incident. Pruning needs clean ticks
    # in between, so the interval is clamped to give it some.
    min_interval = min_learn_interval(config["poll_interval_seconds"])
    if float(config["domain_learn_interval_seconds"]) < min_interval:
        config["domain_learn_interval_seconds"] = min_interval
    return config
