import os

from netdnsmonitor.config import DEFAULT_CONFIG, load_config


EXPANDED_PATH_KEYS = ("reports_dir", "learned_domains_path", "failover_state_path")


def test_missing_file_returns_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    non_path_keys = {k: v for k, v in cfg.items() if k not in EXPANDED_PATH_KEYS}
    expected = {k: v for k, v in DEFAULT_CONFIG.items() if k not in EXPANDED_PATH_KEYS}
    assert non_path_keys == expected
    for key in EXPANDED_PATH_KEYS:
        assert cfg[key] == os.path.expanduser(DEFAULT_CONFIG[key])


def test_partial_yaml_overrides_only_given_keys(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("poll_interval_seconds: 10\ndomains:\n  - example.com\n")
    cfg = load_config(str(config_path))
    assert cfg["poll_interval_seconds"] == 10
    assert cfg["domains"] == ["example.com"]
    assert cfg["failure_threshold"] == DEFAULT_CONFIG["failure_threshold"]


def test_reports_dir_is_tilde_expanded(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("reports_dir: '~/somewhere/reports'\n")
    cfg = load_config(str(config_path))
    assert not cfg["reports_dir"].startswith("~")


def test_learn_interval_is_clamped_above_the_poll_interval(tmp_path):
    """At or below the poll interval, a dead domain is re-added every tick, the
    flap gate's success counter never resets, and one dead name latches a
    permanent false incident.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "poll_interval_seconds: 30\ndomain_learn_interval_seconds: 30\n"
    )
    cfg = load_config(str(config_path))
    assert cfg["domain_learn_interval_seconds"] >= 60


def test_a_generous_learn_interval_is_left_alone(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "poll_interval_seconds: 30\ndomain_learn_interval_seconds: 900\n"
    )
    assert load_config(str(config_path))["domain_learn_interval_seconds"] == 900
