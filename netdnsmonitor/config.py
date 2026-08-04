"""Load user-configurable monitoring settings. Domains defaults to an empty
list rather than auto-detecting "most visited sites" from browser history --
that would need reading another app's data, which is an explicit opt-in the
user should choose, not a silent default (see the plan's probing-strategy
section).
"""

import os

import yaml

DEFAULT_CONFIG = {
    "external_targets": [["1.1.1.1", 443], ["8.8.8.8", 443]],
    "internal_targets": [],
    "domains": [],
    "poll_interval_seconds": 30,
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
    # echo request to a single host every few seconds; it drives the menu bar
    # stats, the Dock tile, and the network-failed alert, and never the repair
    # ladder or escalation. See ping.py for why this uses ICMP while prober.py
    # deliberately does not.
    "ping_host": "8.8.8.8",
    "ping_interval_seconds": 5,
    # Bounds the per-tick ping. A failed ping takes about this long, so keep it
    # comfortably under ping_interval_seconds.
    "ping_timeout_seconds": 2.0,
    # Consecutive failed pings before the alert fires. 1 is the literal reading
    # of "if it fails a ping, alert" and is the default. On Wi-Fi a lone lost
    # echo request will occasionally trip it; raise to 2 to ignore single
    # dropped packets and still alert within 10 seconds of a real outage.
    "ping_failure_threshold": 1,
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
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
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

    # Catch the one wrong type that fails silently instead of loudly. These two
    # keys are iterated, and a str is iterable, so `domains: example.com` --
    # the natural way to write a single entry -- becomes 11 single-character
    # lookups. Every one fails, dns_ok goes False on a healthy network, the
    # flap gate latches an incident, and the app runs real repairs and
    # escalates, forever. `sensitive_strings` as a bare string redacts every
    # occurrence of each letter from the report. Neither raises on its own.
    # (external_targets/internal_targets need no check: app.py unpacks them and
    # raises loudly on a string.)
    for list_key in ("domains", "sensitive_strings"):
        if isinstance(config[list_key], str):
            raise ValueError(
                f"config key '{list_key}' must be a list of strings, not the "
                f"single string {config[list_key]!r} -- wrap it in a list, e.g. "
                f"[{config[list_key]!r}]. A bare string is iterated "
                f"character-by-character by the code that consumes it."
            )

    for path_key in (
        "reports_dir",
        "resolution_log_path",
        "forensic_log_path",
        "forensic_episodes_dir",
        "peer_record_path",
    ):
        config[path_key] = os.path.expanduser(config[path_key])
    return config
