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

    config["reports_dir"] = os.path.expanduser(config["reports_dir"])
    config["resolution_log_path"] = os.path.expanduser(config["resolution_log_path"])
    return config
