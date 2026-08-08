import os
import pathlib

import pytest
import yaml

from netdnsmonitor.config import DEFAULT_CONFIG, load_config

# The repo's own tracked config.yaml -- the shipped default config, not a sample
# of one. The three tests at the bottom of this file are what make that claim
# true rather than aspirational.
SHIPPED_CONFIG = pathlib.Path(__file__).resolve().parents[1] / "config.yaml"

# Every key load_config runs through expanduser. Kept as one list so adding a
# path default without expanding it fails the test below rather than shipping a
# literal "~" that the app then tries to create a directory called.
PATH_KEYS = {
    "reports_dir",
    "resolution_log_path",
    "forensic_log_path",
    "forensic_episodes_dir",
    "peer_record_path",
    "history_path",
    # Added by the reconcile: load_config expands this one too, so leaving it
    # out would make test_missing_file_returns_defaults compare an expanded
    # path against the unexpanded default and fail.
    "learned_domains_path",
    "failover_state_path",
}


def test_missing_file_returns_defaults(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    non_path_keys = {k: v for k, v in cfg.items() if k not in PATH_KEYS}
    expected = {k: v for k, v in DEFAULT_CONFIG.items() if k not in PATH_KEYS}
    assert non_path_keys == expected
    for key in PATH_KEYS:
        assert cfg[key] == os.path.expanduser(DEFAULT_CONFIG[key])


def test_every_path_default_is_expanded(tmp_path):
    """A `~` that survives load_config becomes a literal directory named "~" in
    the working directory the moment something calls makedirs on it.
    """
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    for key, value in cfg.items():
        if isinstance(value, str) and ("/" in value or key.endswith(("_dir", "_path"))):
            assert not value.startswith("~"), key


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
    declaration and config.yaml documents both as 2, so pin the
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
    realistic, since config.yaml is mostly comments. Without the
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


def test_the_shipped_alert_threshold_ignores_a_single_dropped_packet(tmp_path):
    """Pinned deliberately, because it is a behaviour decision rather than an
    arbitrary number.

    It was 1 -- the literal reading of "if it fails a ping, alert". Measured on a
    real machine, that meant three forensic episodes and three Dock bounces in
    ~22 minutes, of which exactly one was a real outage (2m35s, corroborated by
    the gate reporting external_reachable: False); the rest cleared inside one
    5-second tick, i.e. lone dropped Wi-Fi packets.

    A change back to 1 should be a deliberate edit that fails this test, not a
    silent drift.
    """
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["ping_failure_threshold"] == 2
    # And a real outage still alerts fast: two ticks of the heartbeat.
    assert cfg["ping_failure_threshold"] * cfg["ping_interval_seconds"] <= 10


# --- the shipped config.yaml IS the default config --------------------------
#
# It used to be config.example.yaml: a template to copy, free to drift from the
# code because nothing compared them. Renaming it to config.yaml is a claim that
# it states what the app actually does, and a comment cannot keep that claim
# honest -- these three tests can. Together they force any new key to be declared
# in both netdnsmonitor/config.py and config.yaml, at the same value.


def test_the_shipped_config_parses_as_a_yaml_mapping():
    """Ship a broken config and every install.sh run copies it into place, where
    load_config raises during startup and the app just never appears.
    """
    loaded = yaml.safe_load(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)


def test_the_shipped_config_declares_every_default_at_its_real_value():
    """Compared against DEFAULT_CONFIG rather than against load_config's output,
    so the `~` paths line up: both sides are pre-expanduser here.
    """
    shipped = yaml.safe_load(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    missing = sorted(set(DEFAULT_CONFIG) - set(shipped))
    assert not missing, (
        f"config.yaml does not declare {missing}. It is the shipped default "
        "config, so a key the app reads has to appear in it -- add the key with "
        "its default and a comment saying what it does."
    )
    mismatched = {
        key: {"config.py": DEFAULT_CONFIG[key], "config.yaml": shipped[key]}
        for key in DEFAULT_CONFIG
        if shipped[key] != DEFAULT_CONFIG[key]
    }
    assert not mismatched, f"config.yaml disagrees with DEFAULT_CONFIG: {mismatched}"


def test_the_shipped_config_declares_nothing_the_app_ignores():
    """The other direction. A key only in the file is documentation for
    behaviour that does not exist -- which is how `resolution_top_n` outlived the
    code that read it.
    """
    shipped = yaml.safe_load(SHIPPED_CONFIG.read_text(encoding="utf-8"))
    unread = sorted(set(shipped) - set(DEFAULT_CONFIG))
    assert not unread, (
        f"config.yaml declares {unread}, which load_config never reads. Either "
        "add them to DEFAULT_CONFIG or delete them from the file."
    )


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
