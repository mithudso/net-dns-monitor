"""Load user-configurable monitoring settings. Domains defaults to an empty
list rather than auto-detecting "most visited sites" from browser history --
that would need reading another app's data, which is an explicit opt-in the
user should choose, not a silent default (see the plan's probing-strategy
section).
"""

import os

import yaml

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
    # echo request to a single host every few seconds; it drives the menu bar
    # stats, the Dock tile, and the network-failed alert, and never the repair
    # ladder or escalation. See ping.py for why this uses ICMP while prober.py
    # deliberately does not.
    "ping_host": "8.8.8.8",
    "ping_interval_seconds": 5,
    # Bounds the per-tick ping. A failed ping takes about this long, so keep it
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
    "learned_domains_path": (
        "~/Library/Application Support/net-dns-monitor/learned_domains.json"
    ),
    "max_learned_domains": 20,
    "domain_learn_interval_seconds": 300,
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
    # log_view_noise_patterns joins the same club for the same reason: as a bare
    # string it is iterated character by character, every character becomes a
    # suppression pattern, and the log pane silently shows nothing at all.
    for list_key in ("domains", "sensitive_strings", "log_view_noise_patterns"):
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
        "history_path",
        # Folded into this loop during the reconcile rather than kept as the
        # separate expanduser call the console-window line had: one list is the
        # place a new path-valued key gets added, and two would guarantee the
        # next one is added to only one of them.
        "learned_domains_path",
    ):
        config[path_key] = os.path.expanduser(config[path_key])

    # A learn interval at or below the poll interval re-adds a dead domain on
    # every tick, so the flap gate's success counter can never reset and one
    # dead name latches a permanent false incident. Pruning needs clean ticks
    # in between, so the interval is clamped to give it some.
    min_interval = float(config["poll_interval_seconds"]) * 2
    if float(config["domain_learn_interval_seconds"]) < min_interval:
        config["domain_learn_interval_seconds"] = min_interval
    return config
