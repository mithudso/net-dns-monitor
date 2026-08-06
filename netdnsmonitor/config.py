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
    # Per-probe deadline, shared across all domain lookups in one tick.
    "probe_timeout_seconds": 2.0,
    "failure_threshold": 2,
    "success_threshold": 2,
    "log_lookback": "5m",
    "sensitive_strings": [],
    "reports_dir": "~/Library/Application Support/net-dns-monitor/reports",
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
    "failover_state_path": (
        "~/Library/Application Support/net-dns-monitor/failover.json"
    ),
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    if os.path.isfile(path):
        with open(path) as f:
            user_config = yaml.safe_load(f) or {}
        config.update(user_config)
    config["reports_dir"] = os.path.expanduser(config["reports_dir"])
    config["learned_domains_path"] = os.path.expanduser(config["learned_domains_path"])
    config["failover_state_path"] = os.path.expanduser(config["failover_state_path"])

    # A learn interval at or below the poll interval re-adds a dead domain on
    # every tick, so the flap gate's success counter can never reset and one
    # dead name latches a permanent false incident. Pruning needs clean ticks
    # in between, so the interval is clamped to give it some.
    min_interval = float(config["poll_interval_seconds"]) * 2
    if float(config["domain_learn_interval_seconds"]) < min_interval:
        config["domain_learn_interval_seconds"] = min_interval
    return config
