import os
import pathlib

import pytest
import yaml

from netdnsmonitor import config as config_module
from netdnsmonitor.config import DEFAULT_CONFIG, ConfigError, load_config

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


@pytest.mark.parametrize(
    "key",
    [
        "poll_interval_seconds",
        "ping_interval_seconds",
        "ui_refresh_seconds",
        "peer_announce_seconds",
        "log_view_poll_seconds",
        "resolution_interval_seconds",
        "domain_learn_interval_seconds",
    ],
)
@pytest.mark.parametrize("value", ["0", "-5", "'30'", "true"])
def test_a_zero_negative_or_non_numeric_interval_is_rejected_at_load(tmp_path, key, value):
    """`poll_interval_seconds: 0` reaches rumps.Timer as an interval and spins
    the run loop; it also collapses the learn-interval clamp to 0.0.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"{key}: {value}\n")
    with pytest.raises(ValueError, match=f"{key}.*greater than 0"):
        load_config(str(config_path))


@pytest.mark.parametrize("key", ["ping_timeout_seconds", "log_view_timeout_seconds"])
@pytest.mark.parametrize("value", ["0", "-1", "'2'", "true"])
def test_a_zero_negative_or_non_numeric_timeout_is_rejected_at_load(tmp_path, key, value):
    """ping.py raises on every heartbeat for a bad ping_timeout_seconds, and
    make_log_reader coerces log_view_timeout_seconds at start-up -- neither
    names the key or the file. Zero is not "default" for these two.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"{key}: {value}\n")
    with pytest.raises(ValueError, match=f"{key}.*greater than 0"):
        load_config(str(config_path))


def test_zero_still_means_default_for_the_probe_budget(tmp_path):
    """0 is documented as "use probe_timeout_seconds" here; it must not be caught
    by the timeout check.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("failover_probe_timeout_seconds: 0\n")
    assert load_config(str(config_path))["failover_probe_timeout_seconds"] == 0


def test_two_loads_do_not_share_the_same_list_objects(tmp_path):
    """`dict(DEFAULT_CONFIG)` copies the mapping but not the lists inside it, so
    an append to one load's `domains` shows up in every later load.
    """
    a = load_config(str(tmp_path / "does-not-exist.yaml"))
    b = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert a["domains"] is not b["domains"]
    assert a["domains"] is not DEFAULT_CONFIG["domains"]


def test_a_mapping_for_a_list_key_is_rejected_at_load(tmp_path):
    """A mapping iterates its keys and an int does not iterate at all; neither
    is "a list of strings", which is what the error already claimed to require.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("domains:\n  example.com: true\n")
    with pytest.raises(ValueError, match="must be a list of strings"):
        load_config(str(config_path))


def test_a_non_string_path_is_rejected_naming_the_key_and_file(tmp_path):
    """`reports_dir: null` used to raise a bare TypeError from expanduser that
    named neither the key nor the file.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("reports_dir: null\n")
    with pytest.raises(ValueError, match="reports_dir") as excinfo:
        load_config(str(config_path))
    assert str(config_path) in str(excinfo.value)


def test_the_router_keys_have_declared_defaults(tmp_path):
    """app.py and router_window.py each carried their own inline fallback for
    these, and the two disagreed about which interface was WAN and which LAN.
    """
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["router_enabled"] is False
    assert cfg["wan_interface"] == "en3"
    assert cfg["lan_interface"] == "en0"
    assert cfg["lan_ip"] == "192.168.10.1"
    assert cfg["lan_netmask"] == "255.255.255.0"
    assert cfg["dhcp_start"] == "192.168.10.100"
    assert cfg["dhcp_end"] == "192.168.10.200"


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


def test_the_shipped_config_does_not_say_the_router_starts_at_launch():
    """The comment still said so after app.py stopped starting the router at
    launch, because the admin dialog appeared unasked on every login. app.py
    builds the router at launch, but only the Router menu and the router window
    start it.
    """
    text = SHIPPED_CONFIG.read_text(encoding="utf-8")
    assert "at launch it addresses" not in text
    assert "Nothing starts at launch." in text


def test_learn_interval_is_clamped_above_the_poll_interval(tmp_path):
    """At or below the poll interval, a dead domain is re-added every tick, the
    flap gate's success counter never resets, and one dead name latches a
    permanent false incident.
    """
    config_path = tmp_path / "config.yaml"
    config_path.write_text("poll_interval_seconds: 30\ndomain_learn_interval_seconds: 30\n")
    cfg = load_config(str(config_path))
    assert cfg["domain_learn_interval_seconds"] >= 60


def test_a_generous_learn_interval_is_left_alone(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("poll_interval_seconds: 30\ndomain_learn_interval_seconds: 900\n")
    assert load_config(str(config_path))["domain_learn_interval_seconds"] == 900


def test_the_module_expands_exactly_the_path_keys_this_file_pins():
    """The settings window collapses config.PATH_KEYS back to `~` on save, so the
    module's list and the one pinned above must be the same list.
    """
    assert set(config_module.PATH_KEYS) == PATH_KEYS


# --- validation at the boundary ---------------------------------------------


def _write(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize(
    "key,value",
    [
        ("email_recipients", "ops@example.com"),
        ("failover_backup_services", "Wi-Fi"),
        ("failover_trigger_classifications", "network"),
    ],
)
def test_a_bare_string_for_any_iterated_list_key_is_rejected(tmp_path, key, value):
    """frozenset("network") is a set of letters no classification matches, so
    failover never triggers; list("ops@example.com") mails one-character
    addresses. Neither raises on its own.
    """
    with pytest.raises(ValueError, match=key):
        load_config(_write(tmp_path, f"{key}: {value}\n"))


@pytest.mark.parametrize(
    "key",
    [
        "domains",
        "sensitive_strings",
        "log_view_noise_patterns",
        "email_recipients",
        "failover_backup_services",
        "internal_targets",
        "failover_probe_targets",
    ],
)
def test_a_list_key_with_every_item_commented_out_loads_as_empty(tmp_path, key):
    """`key:` above commented items loads as None. redact(text, None) raised
    TypeError on the incident edge, and that incident's alert was lost.
    """
    extra = "control_domain: example.com\n" if key == "domains" else ""
    cfg = load_config(_write(tmp_path, f"{key}:\n  # - something\n{extra}"))
    assert cfg[key] == []


def test_a_null_trigger_list_means_the_default_not_nothing(tmp_path):
    cfg = load_config(_write(tmp_path, "failover_trigger_classifications:\n"))
    assert cfg["failover_trigger_classifications"] == ["network"]
    # An explicit empty list is a deliberate "never trigger" and is kept.
    cfg = load_config(_write(tmp_path, "failover_trigger_classifications: []\n"))
    assert cfg["failover_trigger_classifications"] == []


@pytest.mark.parametrize("key", ["external_targets", "internal_targets", "failover_probe_targets"])
def test_a_hostname_target_is_rejected_naming_the_key(tmp_path, key):
    """A hostname is resolved inside create_connection, outside the probe
    timeout, and a resolver failure reads as NETWORK instead of DNS.
    """
    with pytest.raises(ValueError, match=f"{key}.*IP address"):
        load_config(_write(tmp_path, f'{key}:\n  - ["google.com", 443]\n'))


@pytest.mark.parametrize(
    "entry",
    ['["1.1.1.1", 99999]', '["1.1.1.1", 0]', '["1.1.1.1", "443"]', '"1.1.1.1:443"', '["1.1.1.1"]'],
)
def test_a_malformed_target_is_rejected_naming_the_key(tmp_path, entry):
    with pytest.raises(ValueError, match="internal_targets"):
        load_config(_write(tmp_path, f"internal_targets:\n  - {entry}\n"))


def test_ip_literal_targets_are_accepted_including_scoped_ipv6(tmp_path):
    cfg = load_config(
        _write(
            tmp_path,
            'internal_targets:\n  - ["192.168.1.1", 53]\n  - ["fe80::1%en0", 53]\n'
            'failover_probe_targets:\n  - ["::1", 443]\n',
        )
    )
    assert cfg["internal_targets"] == [["192.168.1.1", 53], ["fe80::1%en0", 53]]
    assert cfg["failover_probe_targets"] == [["::1", 443]]


@pytest.mark.parametrize("value", ["0", "-1", "0.0", '"2"', "true", ".nan"])
def test_a_probe_timeout_that_is_not_a_positive_number_is_rejected(tmp_path, value):
    """Timeout 0 makes connect non-blocking: every connect fails at once, every
    tick is a NETWORK incident, and the app runs repairs and fails over.
    """
    with pytest.raises(ValueError, match="probe_timeout_seconds"):
        load_config(_write(tmp_path, f"probe_timeout_seconds: {value}\n"))


def test_a_fractional_probe_timeout_is_accepted(tmp_path):
    assert (
        load_config(_write(tmp_path, "probe_timeout_seconds: 0.5\n"))["probe_timeout_seconds"]
        == 0.5
    )


@pytest.mark.parametrize("key", config_module.POSITIVE_KEYS)
def test_every_timeout_and_interval_refuses_zero(tmp_path, key):
    with pytest.raises(ValueError, match=key):
        load_config(_write(tmp_path, f"{key}: 0\n"))


@pytest.mark.parametrize("key", ["peer_port", "smtp_port", "failover_speedtest_port"])
@pytest.mark.parametrize("value", ["0", "65536", '"587"'])
def test_a_port_outside_1_to_65535_is_rejected(tmp_path, key, value):
    with pytest.raises(ValueError, match=key):
        load_config(_write(tmp_path, f"{key}: {value}\n"))


def test_zero_keeps_its_documented_meaning_where_it_has_one(tmp_path):
    """0 is a real setting for these: "use probe_timeout_seconds", "never
    re-alert", "no automatic switching". The positive check must not touch them.
    """
    cfg = load_config(
        _write(
            tmp_path,
            "failover_probe_timeout_seconds: 0\nping_alert_repeat_seconds: 0\n"
            "failover_max_switches_per_hour: 0\n",
        )
    )
    assert cfg["failover_probe_timeout_seconds"] == 0
    assert cfg["ping_alert_repeat_seconds"] == 0


def test_no_domains_and_no_control_domain_is_rejected(tmp_path):
    """dns_ok is None with no name to resolve, classify() returns UNCLASSIFIED,
    and the state machine counts that as a failure: a permanent incident.
    """
    with pytest.raises(ValueError, match="control_domain"):
        load_config(_write(tmp_path, "domains: []\ncontrol_domain: null\n"))
    with pytest.raises(ValueError, match="control_domain"):
        load_config(_write(tmp_path, "control_domain: ''\n"))


def test_either_domains_or_a_control_domain_is_enough(tmp_path):
    cfg = load_config(_write(tmp_path, "domains: [example.com]\ncontrol_domain: null\n"))
    assert cfg["domains"] == ["example.com"]
    assert load_config(_write(tmp_path, "domains: []\n"))["control_domain"]


def test_a_refused_value_is_a_value_error_that_names_its_key(tmp_path):
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, "smtp_port: 0\n"))
    assert isinstance(caught.value, ValueError)
    assert caught.value.key == "smtp_port"


@pytest.mark.parametrize("key", config_module.PATH_KEYS)
@pytest.mark.parametrize("value", ["null", "''", "5"])
def test_a_path_key_that_is_not_a_path_is_refused_naming_the_key(tmp_path, key, value):
    """`reports_dir:` with nothing after it loads as None, and expanduser(None)
    raised TypeError. main() did not catch that, so the app never appeared and
    nothing said which key was at fault.
    """
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, f"{key}: {value}\n"))
    assert caught.value.key == key
    assert key in str(caught.value)


@pytest.mark.parametrize("key", config_module.NUMBER_KEYS)
@pytest.mark.parametrize("value", ["null", '"300"', "true", ".nan"])
def test_a_numeric_key_that_is_not_a_number_is_refused_naming_the_key(tmp_path, key, value):
    """`domain_learn_interval_seconds: null` raised TypeError from float(None)
    inside load_config; a quoted threshold compares an int with a str on every
    tick instead.
    """
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, f"{key}: {value}\n"))
    assert caught.value.key == key


def test_every_numeric_default_is_type_checked_at_load():
    numeric = {
        key
        for key, value in DEFAULT_CONFIG.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    checked = (
        set(config_module.POSITIVE_KEYS)
        | set(config_module.PORT_KEYS)
        | set(config_module.NUMBER_KEYS)
    )
    assert numeric == checked


@pytest.mark.parametrize("value", ["''", "'   '", "null", "8"])
def test_a_blank_ping_host_is_refused(tmp_path, value):
    """`ping ""` cannot resolve the host and exits 68, so every heartbeat reads
    as a lost ping and the network-failed alert fires on a healthy network.
    """
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, f"ping_host: {value}\n"))
    assert caught.value.key == "ping_host"


@pytest.mark.parametrize("value", ["0", "-2"])
def test_zero_parallel_lookups_is_refused(tmp_path, value):
    """ThreadPoolExecutor(max_workers=0) raises ValueError, so every resolution
    batch would fail.
    """
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, f"resolution_max_workers: {value}\n"))
    assert caught.value.key == "resolution_max_workers"


# --- the in-app router --------------------------------------------------------


def test_router_defaults_match_the_fallbacks_app_py_used(tmp_path):
    cfg = load_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg["router_enabled"] is False
    assert (cfg["wan_interface"], cfg["lan_interface"]) == ("en3", "en0")
    assert (cfg["lan_ip"], cfg["lan_netmask"]) == ("192.168.10.1", "255.255.255.0")
    assert (cfg["dhcp_start"], cfg["dhcp_end"]) == ("192.168.10.100", "192.168.10.200")


def test_the_shipped_config_warns_that_the_router_conflicts_with_the_router_stack():
    text = SHIPPED_CONFIG.read_text(encoding="utf-8")
    router_section = text[text.index("router_enabled") - 900 : text.index("router_enabled")]
    assert "router/" in router_section
    assert "CONFLICT" in router_section


@pytest.mark.parametrize(
    "line,key",
    [
        ('lan_ip: "10.0.0.1; reboot"', "lan_ip"),
        ('dhcp_start: "10.0.0"', "dhcp_start"),
        ('lan_netmask: "::1"', "lan_netmask"),
        ('wan_interface: "Thunderbolt Bridge"', "wan_interface"),
        ('lan_interface: "en0 && reboot"', "lan_interface"),
    ],
)
def test_an_enabled_router_refuses_values_that_are_not_addresses(tmp_path, line, key):
    """router.py writes these into a shell script run with administrator rights."""
    with pytest.raises(ValueError, match=key):
        load_config(_write(tmp_path, f"router_enabled: true\n{line}\n"))


def test_a_disabled_router_does_not_block_startup_on_a_stale_value(tmp_path):
    cfg = load_config(
        _write(tmp_path, 'router_enabled: false\nwan_interface: "Thunderbolt Bridge"\n')
    )
    assert cfg["wan_interface"] == "Thunderbolt Bridge"


def test_a_non_string_list_item_is_refused_naming_the_key(tmp_path):
    """An unquoted `-1009` loads as an int, and an int noise pattern raises inside
    the log filter, so the dashboard never opens."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("log_view_noise_patterns:\n  - -1009\n")
    with pytest.raises(ConfigError) as caught:
        load_config(str(config_path))
    assert caught.value.key == "log_view_noise_patterns"


def test_a_numeric_sensitive_string_is_still_accepted(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("sensitive_strings:\n  - 8443\n")
    assert load_config(str(config_path))["sensitive_strings"] == [8443]


def test_a_numeric_log_window_is_read_as_seconds_text(tmp_path):
    """`log show --last 300` means 300 seconds; an int in the argv would raise."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text("log_lookback: 300\nlog_view_poll_window: 60\n")
    cfg = load_config(str(config_path))
    assert cfg["log_lookback"] == "300"
    assert cfg["log_view_poll_window"] == "60"


def test_a_blank_log_window_is_refused_naming_the_key(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("log_view_backfill_window: ''\n")
    with pytest.raises(ConfigError) as caught:
        load_config(str(config_path))
    assert caught.value.key == "log_view_backfill_window"


def test_a_blank_ipv6_ping_host_is_allowed_and_turns_it_off(tmp_path):
    assert load_config(_write(tmp_path, 'ping_host_v6: ""\n'))["ping_host_v6"] == ""


def test_a_non_text_ipv6_ping_host_is_refused(tmp_path):
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, "ping_host_v6: [1, 2]\n"))
    assert caught.value.key == "ping_host_v6"


# --- audit fixes: values the app would misread -----------------------------


def _write_cfg(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return str(path)


BOOL_KEYS = sorted(k for k, v in DEFAULT_CONFIG.items() if isinstance(v, bool))


def test_every_boolean_default_is_covered_by_the_bool_check():
    # Parity: a new bool default must be refused when written as a string.
    assert "failover_enabled" in BOOL_KEYS
    for key in BOOL_KEYS:
        with pytest.raises(ConfigError) as caught:
            config_module.validate_config({key: "false"})
        assert caught.value.key == key


@pytest.mark.parametrize("value", ['"false"', '"no"', "n", "disabled", "1", "null"])
def test_a_non_boolean_for_a_switch_is_refused(tmp_path, value):
    # "false" is a non-empty string, so it is truthy: it would arm failover.
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, f"failover_enabled: {value}\n"))
    assert caught.value.key == "failover_enabled"


def test_real_booleans_still_load(tmp_path):
    cfg = load_config(_write_cfg(tmp_path, "failover_enabled: true\nslack_enabled: false\n"))
    assert cfg["failover_enabled"] is True
    assert cfg["slack_enabled"] is False


@pytest.mark.parametrize(
    "line",
    [
        'domains: ["example..com"]',
        'domains: [".corp.example"]',
        'domains: ["https://example.com"]',
        'domains: ["user@example.com"]',
        'domains: ["host:80"]',
        'domains: [" "]',
        'domains: [" example.com"]',
        "domains: [12]",
        "control_domain: 123",
        'control_domain: "  "',
    ],
)
def test_a_domain_that_cannot_be_looked_up_is_refused(tmp_path, line):
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, line + "\n"))
    assert caught.value.key in ("domains", "control_domain")


def test_domain_problem_rejects_the_overlong_and_the_bad_label():
    assert config_module.domain_problem("example.com") is None
    assert config_module.domain_problem("bücher.example") is None
    assert config_module.domain_problem("a" * 64 + ".com") is not None
    assert config_module.domain_problem(".".join(["abcdefghi"] * 30)) is not None
    assert config_module.domain_problem(None) is not None


def test_null_control_domain_is_still_allowed_when_domains_exist(tmp_path):
    cfg = load_config(_write_cfg(tmp_path, "domains: [example.com]\ncontrol_domain: null\n"))
    assert cfg["control_domain"] is None


def test_host_problem_matches_what_ping_once_refuses():
    assert config_module.host_problem("8.8.8.8") is None
    assert config_module.host_problem("2001:4860:4860::8888") is None
    for bad in ("-c5", "bad host", "", "a\x00b", None, 5):
        assert config_module.host_problem(bad) is not None, bad


@pytest.mark.parametrize(
    "key,value",
    [
        ("ping_host", "8.8.8.8, 1.1.1.1"),
        ("ping_host", "-c5"),
        ("ping_host_v6", "bad host"),
        ("ping_host_v6", "-6"),
        ("ping_fallback_host", "1.1.1.1 "),
    ],
)
def test_a_ping_host_that_ping_once_refuses_is_refused_at_load(tmp_path, key, value):
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, yaml.safe_dump({key: value})))
    assert caught.value.key == key


def test_blank_v6_and_fallback_ping_hosts_still_turn_those_targets_off(tmp_path):
    cfg = load_config(_write_cfg(tmp_path, 'ping_host_v6: ""\nping_fallback_host: null\n'))
    assert cfg["ping_host_v6"] == ""
    assert cfg["ping_fallback_host"] is None


@pytest.mark.parametrize(
    "line,key",
    [
        ("log_view_max_entries: 0", "log_view_max_entries"),
        ("ping_loss_window: 0", "ping_loss_window"),
        ("ping_loss_window: 12.5", "ping_loss_window"),
        ("log_view_row_limit: 400.5", "log_view_row_limit"),
        ("log_view_row_limit: -1", "log_view_row_limit"),
        ("log_view_announce_limit: 1.5", "log_view_announce_limit"),
        ("history_max_samples: 7.5", "history_max_samples"),
        ("max_learned_domains: -1", "max_learned_domains"),
        ("max_learned_domains: 2.5", "max_learned_domains"),
    ],
)
def test_a_count_the_consumer_cannot_use_is_refused(tmp_path, line, key):
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, line + "\n"))
    assert caught.value.key == key


def test_whole_number_floats_and_zero_where_zero_means_off_still_load(tmp_path):
    cfg = load_config(
        _write_cfg(
            tmp_path, "max_learned_domains: 0\nlog_view_announce_limit: 0\nping_loss_window: 12\n"
        )
    )
    assert cfg["max_learned_domains"] == 0
    assert cfg["log_view_announce_limit"] == 0


def test_a_misspelt_key_is_reported_by_name_not_value(tmp_path):
    with pytest.warns(UserWarning, match="sensitive_string") as record:
        load_config(_write_cfg(tmp_path, "sensitive_string: [hunter2]\n"))
    text = " ".join(str(w.message) for w in record)
    assert "hunter2" not in text
    assert "sensitive_strings" in text  # close-match hint


def test_retired_and_known_keys_do_not_warn(tmp_path):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_config(_write_cfg(tmp_path, "resolution_lookback: 5m\nresolution_top_n: 50\n"))


@pytest.mark.parametrize("line", ["reports_dir: reports", "history_path: $HOME/h.jsonl"])
def test_a_path_that_is_not_absolute_after_expansion_is_refused(tmp_path, line):
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, line + "\n"))
    assert caught.value.key == line.split(":")[0]


@pytest.mark.parametrize("value", ["[Network]", "[networks]", "[net]", "[healthy]"])
def test_an_unknown_trigger_classification_is_refused(tmp_path, value):
    with pytest.raises(ConfigError) as caught:
        load_config(_write_cfg(tmp_path, f"failover_trigger_classifications: {value}\n"))
    assert caught.value.key == "failover_trigger_classifications"


def test_known_trigger_classifications_load(tmp_path):
    cfg = load_config(
        _write_cfg(tmp_path, "failover_trigger_classifications: [network, dns, unclassified]\n")
    )
    assert cfg["failover_trigger_classifications"] == ["network", "dns", "unclassified"]


@pytest.mark.parametrize("value", [0, -5])
def test_a_speedtest_byte_cap_of_zero_or_less_is_refused(value):
    with pytest.raises(ConfigError) as caught:
        config_module.validate_config({"failover_speedtest_max_bytes": value})
    assert caught.value.key == "failover_speedtest_max_bytes"


def test_min_learn_interval_is_twice_the_poll_and_load_config_uses_it(tmp_path):
    assert config_module.min_learn_interval(30) == 60.0
    cfg = load_config(
        _write_cfg(tmp_path, "poll_interval_seconds: 100\ndomain_learn_interval_seconds: 50\n")
    )
    assert cfg["domain_learn_interval_seconds"] == config_module.min_learn_interval(100)


def test_the_shipped_example_config_loads():
    example = pathlib.Path(__file__).resolve().parents[1] / "config.example.yaml"
    assert load_config(str(example))["failover_enabled"] is False
