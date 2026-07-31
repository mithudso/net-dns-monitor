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
    # getaddrinfo. Kept because it is honoured by injected resolvers in tests
    # and documents intent; resolution_batch_deadline_seconds is the real
    # ceiling.
    "resolution_timeout_seconds": 2.0,
    "resolution_max_workers": 10,
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    if os.path.isfile(path):
        with open(path) as f:
            user_config = yaml.safe_load(f) or {}
        config.update(user_config)
    config["reports_dir"] = os.path.expanduser(config["reports_dir"])
    config["resolution_log_path"] = os.path.expanduser(config["resolution_log_path"])
    return config
