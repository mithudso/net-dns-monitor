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
}


def load_config(path: str) -> dict:
    config = dict(DEFAULT_CONFIG)
    if os.path.isfile(path):
        with open(path) as f:
            user_config = yaml.safe_load(f) or {}
        config.update(user_config)
    config["reports_dir"] = os.path.expanduser(config["reports_dir"])
    config["learned_domains_path"] = os.path.expanduser(config["learned_domains_path"])

    # A learn interval at or below the poll interval re-adds a dead domain on
    # every tick, so the flap gate's success counter can never reset and one
    # dead name latches a permanent false incident. Pruning needs clean ticks
    # in between, so the interval is clamped to give it some.
    min_interval = float(config["poll_interval_seconds"]) * 2
    if float(config["domain_learn_interval_seconds"]) < min_interval:
        config["domain_learn_interval_seconds"] = min_interval
    return config
