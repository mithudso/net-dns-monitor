import os

import pytest

from netdnsmonitor.config import DEFAULT_CONFIG, load_config


def test_missing_file_returns_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    path_keys = {"reports_dir", "resolution_log_path"}
    non_path_keys = {k: v for k, v in cfg.items() if k not in path_keys}
    expected = {k: v for k, v in DEFAULT_CONFIG.items() if k not in path_keys}
    assert non_path_keys == expected
    assert cfg["reports_dir"] == os.path.expanduser(DEFAULT_CONFIG["reports_dir"])
    assert cfg["resolution_log_path"] == os.path.expanduser(
        DEFAULT_CONFIG["resolution_log_path"]
    )


def test_resolution_monitor_defaults_present(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["resolution_interval_seconds"] == 300
    assert cfg["resolution_stall_seconds"] == 1.0
    assert cfg["resolution_batch_deadline_seconds"] == 240
    assert cfg["resolution_timeout_seconds"] == 2.0
    assert cfg["resolution_max_workers"] == 10


def test_batch_deadline_fits_inside_the_poll_cadence(tmp_path):
    """A batch that outlasts its own interval would queue cycles back to back;
    the deadline is the only thing preventing that, so assert the relationship
    rather than just the literal value.
    """
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["resolution_batch_deadline_seconds"] < cfg["resolution_interval_seconds"]


def test_resolution_log_path_is_tilde_expanded(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("resolution_log_path: '~/somewhere/resolution-log.jsonl'\n")
    cfg = load_config(str(config_path))
    assert not cfg["resolution_log_path"].startswith("~")


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


def test_incident_thresholds_default_to_the_documented_values(tmp_path):
    """test_missing_file_returns_defaults builds `expected` out of
    DEFAULT_CONFIG itself, so it holds for whatever value each key takes --
    changing failure_threshold to 7 keeps it green. These two gate incident
    declaration and config.example.yaml documents both as 2, so pin the
    literals the way the resolution defaults above already are.
    """
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["failure_threshold"] == 2
    assert cfg["success_threshold"] == 2
    assert cfg["poll_interval_seconds"] == 30
    assert cfg["domains"] == []  # the deliberate privacy default
    assert cfg["external_targets"] == [["1.1.1.1", 443], ["8.8.8.8", 443]]


def test_empty_config_file_falls_back_to_defaults(tmp_path):
    """yaml.safe_load returns None for an empty or fully commented-out file --
    realistic, since config.example.yaml is mostly comments. Without the
    `or {}` that None reaches dict.update and raises TypeError during startup.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("# every line commented out\n")
    cfg = load_config(str(config_path))
    assert cfg["failure_threshold"] == 2
    assert cfg["domains"] == []


def test_load_config_does_not_mutate_the_module_level_defaults(tmp_path):
    """`dict(DEFAULT_CONFIG)` is a copy on purpose: without it, expanduser and
    every user override get written back into the module global and leak into
    the next load. test_missing_file_returns_defaults cannot catch that,
    because it compares the result against the very object the bug corrupts.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("poll_interval_seconds: 999\nreports_dir: '~/elsewhere'\n")
    load_config(str(config_path))
    assert DEFAULT_CONFIG["poll_interval_seconds"] == 30
    assert DEFAULT_CONFIG["reports_dir"] == (
        "~/Library/Application Support/net-dns-monitor/reports"
    )


def test_a_bare_string_for_a_list_key_is_rejected_at_load(tmp_path):
    """`domains: example.com` is the natural way to write one entry, and a str
    is iterable -- so without this it becomes 11 single-character lookups, all
    failing, which drives dns_ok False on a healthy network, latches the flap
    gate, and runs real repairs and LLM escalations forever. Failing at the
    boundary is the only place this is diagnosable.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("domains: example.com\n")
    with pytest.raises(ValueError, match="must be a list of strings"):
        load_config(str(config_path))


def test_a_bare_string_for_sensitive_strings_is_rejected_at_load(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("sensitive_strings: corp.local\n")
    with pytest.raises(ValueError, match="sensitive_strings"):
        load_config(str(config_path))


def test_a_list_of_strings_is_still_accepted(tmp_path):
    """Guard against the check being too eager: the correct form must pass."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("domains:\n  - example.com\nsensitive_strings:\n  - corp.local\n")
    cfg = load_config(str(config_path))
    assert cfg["domains"] == ["example.com"]
    assert cfg["sensitive_strings"] == ["corp.local"]


def test_a_non_mapping_yaml_root_is_rejected_with_the_filename(tmp_path):
    """A top-level list or scalar reaches dict.update and raises a message that
    never names the config file. Relaunching the built .app from the Dock
    bypasses start.sh's guard, so the user just sees no menu bar app at all.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("- 1.1.1.1\n- 8.8.8.8\n")
    with pytest.raises(ValueError, match="must contain a YAML mapping"):
        load_config(str(config_path))

    config_path.write_text("5\n")
    with pytest.raises(ValueError, match="must contain a YAML mapping"):
        load_config(str(config_path))
