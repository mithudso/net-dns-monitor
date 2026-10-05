"""The settings window.

The pure half gets the attention, because this is the only code in the project
that writes to the user's own config file. The round-trip test is the important
one: it is not enough that a value is written, it has to come back out of
`load_config` as the same typed value, or the app quietly runs on a string where
it expected a number.
"""

import os
from pathlib import Path

import pytest
import yaml

from netdnsmonitor.config import DEFAULT_CONFIG, load_config
from netdnsmonitor.settings_window import (
    DEFAULT_CONFIG_PATH_DISPLAY,
    FIELDS,
    NEEDS_RESTART,
    SERVICE_RESTART_HINT,
    STORE_RESTART_HINT,
    SettingsWindow,
    backup_path,
    collect,
    format_field,
    parse_field,
    restart_note,
    save_config,
    settings_notice,
)

# --- coverage --------------------------------------------------------------


def test_every_config_key_has_a_field():
    """The window is advertised as covering every configurable option. A default
    added without a field would silently not be editable, and nothing else would
    catch it.
    """
    assert {key for key, _label, _kind in FIELDS} == set(DEFAULT_CONFIG)


def test_no_field_refers_to_a_key_that_does_not_exist():
    """A renamed config key would leave a field writing something load_config
    ignores -- the setting would appear to save and do nothing.
    """
    for key, _label, _kind in FIELDS:
        assert key in DEFAULT_CONFIG


def test_every_field_has_a_label_and_a_known_kind():
    for key, label, kind in FIELDS:
        assert label, key
        assert kind in ("str", "int", "float", "bool", "list", "targets"), key


def test_every_field_kind_matches_its_default_type():
    """An "int" field over a float default truncates it on the first save:
    parse_field("int", "0.5") is 0, and a 0.5s probe timeout becomes no timeout.
    """
    accepted = {
        "int": (int,),
        "float": (int, float),
        "bool": (bool,),
        "str": (str,),
        "list": (list,),
        "targets": (list,),
    }
    for key, _label, kind in FIELDS:
        default = DEFAULT_CONFIG[key]
        if default is None:
            continue
        if kind != "bool":
            assert not isinstance(default, bool), key
        assert isinstance(default, accepted[kind]), (key, kind, type(default).__name__)


def test_no_field_can_carry_a_credential():
    """The window writes every field straight into config.yaml, which gets shared
    and synced. Secrets stay in the environment.
    """
    banned = ("webhook", "password", "passwd", "api_key", "apikey", "token", "secret")
    for key, _label, _kind in FIELDS:
        assert not any(word in key.lower() for word in banned), key


# --- parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text,expected", [("yes", True), ("no", False), ("TRUE", True), ("0", False)]
)
def test_booleans_accept_the_obvious_spellings(text, expected):
    assert parse_field("bool", text) is expected


def test_a_nonsense_boolean_is_rejected_by_name():
    with pytest.raises(ValueError, match="Enabled"):
        parse_field("bool", "maybe", "Enabled")


def test_integers_are_integers_not_strings():
    """`peer_port` as the string "45737" reaches bind() and raises TypeError deep
    in a worker; `ping_interval_seconds` as a string makes a timer that never
    fires. Both were real failure modes before the types were pinned.
    """
    value = parse_field("int", "45737")
    assert value == 45737
    assert isinstance(value, int)


def test_a_nonsense_number_is_rejected_by_name():
    with pytest.raises(ValueError, match="Ping every"):
        parse_field("int", "soon", "Ping every (seconds)")


def test_a_float_field_keeps_its_fraction():
    assert parse_field("float", "1.5") == 1.5


def test_lists_split_on_commas_and_drop_blanks():
    assert parse_field("list", " a.com , , b.com ") == ["a.com", "b.com"]


def test_an_empty_list_is_empty_not_a_list_containing_nothing():
    assert parse_field("list", "  ") == []


def test_targets_round_trip_as_host_port_pairs():
    """app.py does `tuple(t)` on each entry and the prober unpacks host, port."""
    parsed = parse_field("targets", "1.1.1.1:443, 8.8.8.8:53")
    assert parsed == [["1.1.1.1", 443], ["8.8.8.8", 53]]
    assert format_field("targets", parsed) == "1.1.1.1:443, 8.8.8.8:53"


def test_a_target_without_a_port_is_rejected_here_not_inside_a_probe():
    with pytest.raises(ValueError, match="LAN targets"):
        parse_field("targets", "192.168.1.1", "LAN targets")


def test_a_target_with_a_nonnumeric_port_is_rejected():
    with pytest.raises(ValueError, match="IP:port"):
        parse_field("targets", "192.168.1.1:https", "LAN targets")


@pytest.mark.parametrize("text", ["1.1.1.1:99999", "1.1.1.1:0"])
def test_a_target_port_outside_the_valid_range_is_rejected(text):
    with pytest.raises(ValueError, match="LAN targets.*port from 1 to 65535"):
        parse_field("targets", text, "LAN targets")


def test_a_hostname_target_is_rejected_by_name():
    """A hostname is resolved inside create_connection, outside the probe
    timeout, and a resolver failure there reads as the internet being down.
    """
    with pytest.raises(ValueError, match="Internet targets.*IP address"):
        parse_field("targets", "google.com:443", "Internet targets")


def test_a_scoped_ipv6_target_is_accepted_and_round_trips():
    parsed = parse_field("targets", "fe80::1%en0:53, [::1]:443")
    assert parsed == [["fe80::1%en0", 53], ["::1", 443]]
    assert parse_field("targets", format_field("targets", parsed)) == parsed


def test_the_target_fields_ask_for_an_ip_not_a_host():
    for key in ("external_targets", "internal_targets", "failover_probe_targets"):
        label = next(label for k, label, _kind in FIELDS if k == key)
        assert "IP:port" in label
        assert "host:port" not in label


def test_a_target_saved_as_a_plain_string_still_formats():
    """An older window saved ["192.168.68.1:53"]. Unpacking that raised inside
    open_settings, and the Settings window never opened at all.
    """
    assert format_field("targets", ["192.168.68.1:53"]) == "192.168.68.1:53"
    assert format_field("targets", [["1.1.1.1", 443], "odd"]) == "1.1.1.1:443, odd"


@pytest.mark.parametrize("key", ["probe_timeout_seconds", "failover_speedtest_timeout_seconds"])
def test_a_fractional_timeout_keeps_its_fraction(key):
    """int(float("0.5")) is 0, and a socket timeout of 0 fails every connect at
    once -- a false network incident on every tick.
    """
    assert collect({key: "0.5"}) == {key: 0.5}


@pytest.mark.parametrize(
    "key,text",
    [
        ("probe_timeout_seconds", "0"),
        ("probe_timeout_seconds", "-1"),
        ("poll_interval_seconds", "0"),
        ("ping_interval_seconds", "0"),
        ("notify_timeout_seconds", "0"),
    ],
)
def test_a_zero_or_negative_timeout_or_interval_is_refused(key, text):
    label = next(label for k, label, _kind in FIELDS if k == key)
    with pytest.raises(ValueError) as caught:
        collect({key: text})
    assert label in str(caught.value)
    # A negative is caught earlier, in parse_field, which knows only the label.
    assert key in str(caught.value) or "0 or more" in str(caught.value)


@pytest.mark.parametrize("key", ["peer_port", "smtp_port", "failover_speedtest_port"])
def test_a_port_outside_the_valid_range_is_refused(key):
    with pytest.raises(ValueError, match=key):
        collect({key: "70000"})
    with pytest.raises(ValueError, match=key):
        collect({key: "0"})


def test_no_domain_and_no_control_domain_is_refused():
    """With neither, the DNS check has no name, every tick is UNCLASSIFIED, and
    that latches a permanent incident on a healthy network.
    """
    with pytest.raises(ValueError, match="Control domain"):
        collect({"domains": "", "control_domain": ""})
    assert collect({"domains": "a.example", "control_domain": ""})["domains"] == ["a.example"]
    assert collect({"domains": "", "control_domain": "b.example"})["domains"] == []


def test_a_blank_ping_host_is_refused():
    """`ping ""` exits 68, so a cleared field would make every heartbeat a lost
    ping and fire the network-failed alert on a healthy network.
    """
    with pytest.raises(ValueError, match="Host to ping"):
        collect({"ping_host": ""})
    with pytest.raises(ValueError, match="Host to ping"):
        collect({"ping_host": "   "})


@pytest.mark.parametrize("text", ["0", "-1"])
def test_zero_parallel_lookups_is_refused(text):
    """ThreadPoolExecutor(max_workers=0) raises, so every resolution batch fails."""
    with pytest.raises(ValueError, match="Parallel lookups"):
        collect({"resolution_max_workers": text})


def test_a_cleared_path_field_is_refused():
    """A blank path expands to "", and every write to it fails."""
    with pytest.raises(ValueError, match="Incident reports"):
        collect({"reports_dir": ""})


def test_a_router_address_is_refused_when_it_is_not_an_address():
    """router.py writes these into a shell script run with administrator rights."""
    with pytest.raises(ValueError, match="LAN address"):
        collect({"router_enabled": "yes", "lan_ip": "10.0.0.1; reboot"})
    with pytest.raises(ValueError, match="Upstream interface"):
        collect({"router_enabled": "yes", "wan_interface": "Thunderbolt Bridge"})
    # Nothing reads them while the router is off.
    assert collect({"router_enabled": "no", "lan_ip": "later"})["lan_ip"] == "later"


@pytest.mark.parametrize("text", ["::1", "1.1.1.1:0", "1.1.1.1:99999"])
def test_a_target_with_an_unusable_port_or_bare_ipv6_host_is_rejected(text):
    """ "::1" splits into host ":" and port 1, and port 99999 raises OverflowError
    inside a probe on a background timer.
    """
    with pytest.raises(ValueError, match="LAN targets"):
        parse_field("targets", text, "LAN targets")


def test_a_bracketed_ipv6_target_loses_its_brackets():
    assert parse_field("targets", "[::1]:53") == [["::1", 53]]


def test_a_negative_integer_is_rejected_by_name():
    """`-30` reaches rumps.Timer as an interval."""
    with pytest.raises(ValueError, match="Ping every"):
        parse_field("int", "-30", "Ping every (seconds)")


def test_a_negative_float_is_rejected_by_name():
    with pytest.raises(ValueError, match="Ping timeout"):
        parse_field("float", "-0.5", "Ping timeout")


def test_zero_is_still_a_valid_number():
    """0 carries meaning for several keys ("never re-alert", "use the default")."""
    assert parse_field("int", "0") == 0
    assert parse_field("float", "0") == 0.0


def test_a_zero_interval_is_refused_before_anything_is_written(tmp_path):
    """load_config rejects a zero interval, so letting it through collect would
    write a file the app then refuses to start on. The refusal has to happen in
    the parse step, where the window already reports "Not saved" and writes
    nothing.
    """
    path = tmp_path / "config.yaml"
    with pytest.raises(ValueError, match="Probe every"):
        save_config(str(path), collect({"poll_interval_seconds": "0"}))
    assert not path.exists()


def test_a_zero_timeout_is_refused_before_anything_is_written(tmp_path):
    path = tmp_path / "config.yaml"
    with pytest.raises(ValueError, match="Ping timeout"):
        save_config(str(path), collect({"ping_timeout_seconds": "0"}))
    assert not path.exists()


def test_collect_stops_on_the_first_bad_field_so_nothing_is_half_saved():
    with pytest.raises(ValueError):
        collect({"ping_interval_seconds": "soon", "ping_host": "8.8.8.8"})


def test_collect_ignores_keys_it_does_not_own():
    parsed = collect({"ping_host": "1.1.1.1", "not_a_setting": "x"})
    assert parsed == {"ping_host": "1.1.1.1"}


# --- saving ----------------------------------------------------------------


def test_a_save_round_trips_through_load_config(tmp_path):
    """The assertion that matters: written, then read back by the real loader, as
    the same typed values.
    """
    path = str(tmp_path / "config.yaml")
    save_config(path, collect({"ping_host": "1.1.1.1", "ping_interval_seconds": "9"}))
    reloaded = load_config(path)
    assert reloaded["ping_host"] == "1.1.1.1"
    assert reloaded["ping_interval_seconds"] == 9
    assert isinstance(reloaded["ping_interval_seconds"], int)


def test_a_saved_config_still_loads_with_every_key_intact(tmp_path):
    """A save must not produce a file that load_config then rejects -- that would
    leave the app unable to start, with the only good copy in a backup.

    Presence is not enough: a numeric default that comes back as a different
    numeric type has been silently truncated by the field's kind.
    """
    path = str(tmp_path / "config.yaml")
    save_config(
        path, collect({key: format_field(kind, DEFAULT_CONFIG[key]) for key, _l, kind in FIELDS})
    )
    reloaded = load_config(path)
    expected_type = {"int": int, "float": float, "bool": bool}
    for key, _l, kind in FIELDS:
        assert key in reloaded
        if kind in expected_type:
            assert isinstance(reloaded[key], expected_type[kind]), key
        if isinstance(DEFAULT_CONFIG[key], float):
            assert reloaded[key] == DEFAULT_CONFIG[key], key


def test_the_previous_file_is_backed_up_with_a_timestamp(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("ping_host: 9.9.9.9  # a comment worth keeping\n", encoding="utf-8")
    result = save_config(str(path), {"ping_host": "1.1.1.1"}, clock=lambda: 1000)
    assert result["backup"].endswith(".bak-1000")
    assert "a comment worth keeping" in Path(result["backup"]).read_text(encoding="utf-8")


def test_a_second_save_does_not_overwrite_the_first_backup(tmp_path):
    """The whole reason the backup name is timestamped. A fixed `.bak` would be
    replaced on the second save by the already-stripped version, and the only
    commented copy would be gone -- exactly when someone is clicking Save
    repeatedly.
    """
    path = tmp_path / "config.yaml"
    path.write_text("# original comments\nping_host: 9.9.9.9\n", encoding="utf-8")

    first = save_config(str(path), {"ping_host": "1.1.1.1"}, clock=lambda: 1000)
    second = save_config(str(path), {"ping_host": "2.2.2.2"}, clock=lambda: 2000)

    assert first["backup"] != second["backup"]
    assert "# original comments" in Path(first["backup"]).read_text(encoding="utf-8")


def test_two_saves_in_the_same_second_keep_the_commented_backup(tmp_path):
    """The backup name has one-second resolution. Without a suffix the second
    save's already-stripped copy replaced the only commented one.
    """
    path = tmp_path / "config.yaml"
    path.write_text("# original comments\nping_host: 9.9.9.9\n", encoding="utf-8")

    first = save_config(str(path), {"ping_host": "1.1.1.1"}, clock=lambda: 1000)
    second = save_config(str(path), {"ping_host": "2.2.2.2"}, clock=lambda: 1000)

    assert first["backup"] != second["backup"]
    assert second["backup"].endswith(".bak-1000-1")
    assert "# original comments" in Path(first["backup"]).read_text(encoding="utf-8")


def test_the_first_save_does_not_claim_a_backup_that_was_never_made(tmp_path):
    """The header used to promise a `.bak-<timestamp>` unconditionally; on a first
    save, or after a failed backup, that sends someone looking for a file that
    does not exist.
    """
    path = tmp_path / "new" / "config.yaml"
    result = save_config(str(path), {"ping_host": "1.1.1.1"})
    assert result["backup"] is None
    assert "bak-" not in path.read_text(encoding="utf-8")


def test_a_successful_backup_is_named_in_the_written_header(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("ping_host: 9.9.9.9\n", encoding="utf-8")
    result = save_config(str(path), {"ping_host": "1.1.1.1"}, clock=lambda: 1000)
    assert os.path.basename(result["backup"]) in path.read_text(encoding="utf-8")


def test_a_refused_value_writes_nothing(tmp_path):
    """A file load_config rejects leaves the app unable to start, so the check
    runs before the backup and before the write.
    """
    path = tmp_path / "config.yaml"
    original = "# keep\nprobe_timeout_seconds: 2.0\n"
    path.write_text(original, encoding="utf-8")
    with pytest.raises(ValueError, match="probe_timeout_seconds"):
        save_config(str(path), {"probe_timeout_seconds": 0})
    assert path.read_text(encoding="utf-8") == original
    assert list(tmp_path.glob("config.yaml.bak-*")) == []


def test_saving_writes_home_paths_in_portable_form(tmp_path):
    """load_config expands `~` on every read. An absolute /Users/<name>/ path
    pins the file to one account and, sandboxed, points outside the container.
    """
    path = tmp_path / "config.yaml"
    save_config(str(path), {"reports_dir": os.path.expanduser("~/x"), "ping_host": "1.1.1.1"})
    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert written["reports_dir"] == "~/x"
    assert written["ping_host"] == "1.1.1.1"
    assert load_config(str(path))["reports_dir"] == os.path.expanduser("~/x")


def test_saving_through_a_symlink_keeps_the_link(tmp_path):
    target = tmp_path / "dotfiles" / "config.yaml"
    target.parent.mkdir()
    target.write_text("ping_host: 9.9.9.9\n", encoding="utf-8")
    link = tmp_path / "config.yaml"
    link.symlink_to(target)

    save_config(str(link), {"ping_host": "1.1.1.1"})

    assert link.is_symlink()
    assert yaml.safe_load(target.read_text(encoding="utf-8"))["ping_host"] == "1.1.1.1"


def test_a_null_trigger_list_survives_a_round_trip_through_the_window(tmp_path):
    """Null means the default ["network"]. Shown as a blank field, a save wrote []
    and silently turned automatic failover off.
    """
    path = tmp_path / "config.yaml"
    path.write_text("failover_trigger_classifications:\n", encoding="utf-8")
    loaded = load_config(str(path))
    fields = {key: format_field(kind, loaded[key]) for key, _label, kind in FIELDS}
    save_config(str(path), collect(fields))
    assert load_config(str(path))["failover_trigger_classifications"] == ["network"]


def test_saving_preserves_keys_the_window_does_not_send(tmp_path):
    """The merge is onto the file's own contents. Merging onto only the submitted
    fields would reset anything not in the form to its default.
    """
    path = tmp_path / "config.yaml"
    path.write_text("some_future_key: keep me\nping_host: 9.9.9.9\n", encoding="utf-8")
    save_config(str(path), {"ping_host": "1.1.1.1"})
    written = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert written["some_future_key"] == "keep me"
    assert written["ping_host"] == "1.1.1.1"


def test_the_written_file_points_at_the_documentation_it_replaced(tmp_path):
    """Comments are lost, so the file has to say where the explanations went.

    The pointer used to name `config.example.yaml`. That file is now just
    `config.yaml` -- the same basename as the file this header is written into --
    so the header has to distinguish them, and this asserts it still points
    somewhere rather than at itself.
    """
    path = tmp_path / "config.yaml"
    save_config(str(path), {"ping_host": "1.1.1.1"})
    body = path.read_text(encoding="utf-8")
    assert "tracked default config.yaml" in body
    assert "NOT preserved" in body
    # It named a warning about an empty `domains` that config.yaml never had.
    assert "leaving `domains` empty" not in body
    # Nothing was there to back up, so the header must not claim a backup.
    assert "saved alongside" not in body


def test_the_header_names_the_backup_it_actually_took(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("ping_host: 9.9.9.9\n", encoding="utf-8")
    result = save_config(str(path), {"ping_host": "1.1.1.1"}, clock=lambda: 1234)
    body = path.read_text(encoding="utf-8")
    assert os.path.basename(result["backup"]) in body
    assert "config.yaml.bak-1234" in body


def test_saving_over_a_malformed_file_still_works(tmp_path):
    """That is the situation someone opens this window to get out of."""
    path = tmp_path / "config.yaml"
    path.write_text("{ not: valid: yaml: at all", encoding="utf-8")
    save_config(str(path), {"ping_host": "1.1.1.1"})
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["ping_host"] == "1.1.1.1"


def test_saving_when_no_config_exists_yet_reports_no_backup(tmp_path):
    result = save_config(str(tmp_path / "new" / "config.yaml"), {"ping_host": "1.1.1.1"})
    assert result["backup"] is None
    assert os.path.isfile(result["path"])


def test_backup_path_is_derived_from_the_config_path():
    assert backup_path("/x/config.yaml", clock=lambda: 5).endswith("config.yaml.bak-5")


# --- restart guidance ------------------------------------------------------


def test_changes_that_need_a_restart_are_named(tmp_path):
    """Otherwise someone changes a threshold, sees nothing happen, and reasonably
    concludes the setting is broken.
    """
    note = restart_note({"ping_failure_threshold": 2})
    assert "restart" in note.lower()
    assert "ping_failure_threshold" in note


def test_the_restart_note_names_the_service_script_by_default():
    note = restart_note({"failure_threshold": 3})
    assert note.endswith("\n" + SERVICE_RESTART_HINT)
    assert "net-dns-monitor-service restart" in note


def test_the_restart_note_can_name_another_way_to_restart():
    """The store build ships no service script, so naming it sends someone
    looking for a command that does not exist.
    """
    note = restart_note({"failure_threshold": 3}, restart_hint=STORE_RESTART_HINT)
    assert "failure_threshold" in note
    assert note.endswith("\n" + STORE_RESTART_HINT)
    assert "net-dns-monitor-service" not in note


def test_an_immediate_change_names_no_way_to_restart():
    note = restart_note({"ping_host": "1.1.1.1"}, restart_hint=STORE_RESTART_HINT)
    assert STORE_RESTART_HINT not in note


def test_changes_that_take_effect_immediately_say_so():
    note = restart_note({"ping_host": "1.1.1.1"})
    assert "immediately" in note


def test_the_restart_set_only_names_real_config_keys():
    for key in NEEDS_RESTART:
        assert key in DEFAULT_CONFIG


def test_turning_peer_discovery_off_is_marked_as_needing_a_restart():
    """Off at runtime only makes peer_tick return early; the socket keeps answering
    PROBE with this machine's hostname and health until a restart.
    """
    assert "peer_discovery_enabled" in NEEDS_RESTART


def test_the_router_settings_are_marked_as_needing_a_restart():
    """The Router is built and started once, in App.__init__."""
    for key in ("router_enabled", "wan_interface", "lan_interface", "lan_ip"):
        assert key in NEEDS_RESTART


def test_only_changed_keys_are_named_when_the_previous_config_is_given():
    """The window sends every field. Naming every restart-only key on each save
    hides the one that actually changed.
    """
    previous = dict(DEFAULT_CONFIG)
    updates = dict(DEFAULT_CONFIG, ping_host="1.1.1.1", failure_threshold=5)
    note = restart_note(updates, previous=previous)
    assert "failure_threshold" in note
    assert "success_threshold" not in note
    assert "(1)" in note


def test_a_null_string_shown_blank_does_not_count_as_a_change():
    note = restart_note(
        {"failover_preferred_service": ""}, previous={"failover_preferred_service": None}
    )
    assert "immediately" in note


def test_the_restart_note_names_only_the_keys_that_changed():
    """The window submits every field on Save, so without the changed subset the
    note lists every restart key on every save and says nothing useful.
    """
    updates = {"ping_failure_threshold": 2, "poll_interval_seconds": 30, "ping_host": "1.1.1.1"}
    note = restart_note(updates, changed={"ping_failure_threshold", "ping_host"})
    assert "ping_failure_threshold" in note
    assert "poll_interval_seconds" not in note


def test_a_save_that_changed_nothing_needing_a_restart_says_immediately():
    updates = {"ping_failure_threshold": 2, "ping_host": "1.1.1.1"}
    assert "immediately" in restart_note(updates, changed={"ping_host"})


# --- the window ------------------------------------------------------------


def test_the_window_builds_a_field_per_option():
    window = SettingsWindow(on_save=lambda values: "Saved.")
    assert set(window.fields) == {key for key, _l, _k in FIELDS}


def test_the_window_is_not_released_when_closed():
    assert SettingsWindow(on_save=lambda values: "").window.isReleasedWhenClosed() is False


def test_loading_populates_every_field_from_the_config():
    window = SettingsWindow(on_save=lambda values: "")
    window.load(DEFAULT_CONFIG)
    assert window.fields["ping_host"].stringValue() == DEFAULT_CONFIG["ping_host"]
    assert window.fields["peer_discovery_enabled"].stringValue() == "yes"
    assert window.fields["external_targets"].stringValue() == "1.1.1.1:443, 8.8.8.8:443"


def test_loading_a_hand_written_target_string_does_not_kill_the_window():
    """A config written by hand as `external_targets: ["1.1.1.1:443"]` is a list
    of strings, not pairs. Unpacking it raised inside `load()`, which is called
    from the menu callback that opens the window.
    """
    window = SettingsWindow(on_save=lambda values: "")
    window.load({**DEFAULT_CONFIG, "external_targets": ["1.1.1.1:443"]})
    assert window.fields["external_targets"].stringValue() == "1.1.1.1:443"


def test_the_window_knows_which_fields_were_edited_since_loading():
    window = SettingsWindow(on_save=lambda values: "")
    window.load(DEFAULT_CONFIG)
    values = {key: f.stringValue() for key, f in window.fields.items()}
    values["ping_host"] = "1.1.1.1"
    assert window.changed_keys(values) == {"ping_host"}


def _button(window, action):
    return next(
        b
        for b in window.window.contentView().subviews()
        if str(getattr(b, "identifier", lambda: "")() or "") == action
    )


def test_a_failing_reload_is_reported_in_the_window_not_raised_into_appkit():
    """Reload re-reads the file through load_config, which raises on a malformed
    one -- and the status line had already said "Reloaded" before the attempt.
    """

    def explode(values):
        raise ValueError("config key 'domains' must be a list of strings")

    window = SettingsWindow(on_save=explode)
    window._target.invoke_(_button(window, "reload"))
    assert window.status.stringValue().startswith("Not reloaded")
    assert "ValueError" in window.status.stringValue()


def test_a_successful_reload_reports_what_the_app_said():
    window = SettingsWindow(on_save=lambda values: "Reloaded from disk.")
    window._target.invoke_(_button(window, "reload"))
    assert window.status.stringValue() == "Reloaded from disk."


def test_a_parse_error_is_shown_in_the_window_rather_than_raised():
    """Raised, it would escape into an AppKit callback where nobody sees it and
    the click would appear to do nothing.
    """

    def boom(values):
        raise ValueError("Ping every (seconds): expected a whole number, got 'soon'")

    window = SettingsWindow(on_save=boom)
    save = next(
        b
        for b in window.window.contentView().subviews()
        if str(getattr(b, "identifier", lambda: "")() or "") == "save"
    )
    window._target.invoke_(save)
    assert "Not saved" in window.status.stringValue()
    assert "whole number" in window.status.stringValue()


def test_a_successful_save_reports_the_message_it_was_given():
    window = SettingsWindow(on_save=lambda values: "Saved. Restart needed.")
    save = next(
        b
        for b in window.window.contentView().subviews()
        if str(getattr(b, "identifier", lambda: "")() or "") == "save"
    )
    window._target.invoke_(save)
    assert "Restart needed" in window.status.stringValue()


def _button(window, identifier):
    return next(
        b
        for b in window.window.contentView().subviews()
        if str(getattr(b, "identifier", lambda: "")() or "") == identifier
    )


def test_a_failed_reload_is_reported_and_not_claimed():
    """load_config raises on a malformed file. The status used to read "Reloaded
    from disk." before the reload ran, and the exception escaped into AppKit.
    """

    def refuse(values):
        assert values is None
        raise ValueError("config key 'probe_timeout_seconds' must be a number greater than 0")

    window = SettingsWindow(on_save=refuse)
    window._target.invoke_(_button(window, "reload"))
    status = window.status.stringValue()
    assert "Not reloaded" in status
    assert "probe_timeout_seconds" in status
    assert "Reloaded from disk" not in status


def test_a_successful_reload_reports_success():
    calls = []
    window = SettingsWindow(on_save=lambda values: calls.append(values) or "Reloaded from disk.")
    window._target.invoke_(_button(window, "reload"))
    assert calls == [None]
    assert window.status.stringValue() == "Reloaded from disk."


def test_the_window_warns_before_saving_not_after():
    """By the time a dialog could say it, the comments would already be gone."""
    window = SettingsWindow(on_save=lambda values: "")
    assert "comments" in window.notice.stringValue()
    assert "bak-" in window.notice.stringValue()
    assert DEFAULT_CONFIG_PATH_DISPLAY in window.notice.stringValue()
    assert SERVICE_RESTART_HINT in window.notice.stringValue()


CONTAINER_CONFIG = (
    "/Users/someone/Library/Containers/example.netdnsmonitor/Data/.config/"
    "net-dns-monitor/config.yaml"
)


def test_the_notice_names_the_file_and_the_restart_it_is_given():
    text = settings_notice(CONTAINER_CONFIG, STORE_RESTART_HINT)
    assert CONTAINER_CONFIG in text.splitlines()
    assert "config.yaml.bak-<timestamp>" in text
    assert "comments" in text
    assert STORE_RESTART_HINT in text
    assert "~/.config" not in text
    assert "net-dns-monitor-service" not in text


def test_the_window_shows_the_notice_for_the_path_and_restart_it_is_given():
    window = SettingsWindow(
        on_save=lambda values: "",
        config_path_display=CONTAINER_CONFIG,
        restart_hint=STORE_RESTART_HINT,
    )
    assert window.notice.stringValue() == settings_notice(CONTAINER_CONFIG, STORE_RESTART_HINT)


def test_a_container_path_notice_fits_its_label_without_clipping():
    """A container path wraps inside the label; the label must be tall enough
    for the wrapped text, or the restart line is the part cut off.
    """
    import AppKit

    long_path = "/Users/a-longer-user-name" + CONTAINER_CONFIG[len("/Users/someone") :]
    window = SettingsWindow(
        on_save=lambda values: "",
        config_path_display=long_path,
        restart_hint=STORE_RESTART_HINT,
    )
    frame = window.notice.frame()
    needed = window.notice.cell().cellSizeForBounds_(
        AppKit.NSMakeRect(0, 0, frame.size.width, 10_000)
    )
    assert needed.height <= frame.size.height


# --- deep-optimizer regressions --------------------------------------------


@pytest.mark.parametrize("text", ["inf", "-inf", "nan"])
def test_non_finite_numbers_are_rejected_as_values_not_raised_as_overflow(text):
    """`float("inf")` parses and `int()` then refuses it with OverflowError, which
    is NOT a ValueError -- so it escaped the window's handler into an AppKit
    callback and the click appeared to do nothing.
    """
    with pytest.raises(ValueError):
        parse_field("int", text, "Ping every (seconds)")


def test_a_non_finite_float_never_reaches_a_timer_interval():
    with pytest.raises(ValueError, match="finite"):
        parse_field("float", "inf", "Ping timeout")


def test_saving_over_a_config_that_is_not_valid_utf8(tmp_path):
    """A UnicodeDecodeError is not an OSError, so reading such a file to back it up
    escaped save_config entirely. The save must still succeed -- and the file it
    overwrites is backed up byte for byte, because skipping the backup destroyed
    the only copy of the original.
    """
    path = tmp_path / "config.yaml"
    original = b"\xff\xfe\x00 not utf-8 at all"
    path.write_bytes(original)
    result = save_config(str(path), {"ping_host": "1.1.1.1"})
    assert Path(result["backup"]).read_bytes() == original
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["ping_host"] == "1.1.1.1"


def test_a_failing_save_is_reported_in_the_window_not_raised_into_appkit():
    """The handler caught only ValueError, so a full disk or a read-only config
    directory escaped into the ObjC callback where nothing is visible.
    """

    def explode(values):
        raise OSError("No space left on device")

    window = SettingsWindow(on_save=explode)
    save = next(
        b
        for b in window.window.contentView().subviews()
        if str(getattr(b, "identifier", lambda: "")() or "") == "save"
    )
    window._target.invoke_(save)
    assert "Not saved" in window.status.stringValue()
    assert "No space left" in window.status.stringValue()


# --- cdo fixes: learn interval, whole numbers, minimums ---------------------


def test_collect_refuses_a_learn_interval_below_twice_the_poll():
    with pytest.raises(ValueError, match="Learn every"):
        collect({"poll_interval_seconds": "30", "domain_learn_interval_seconds": "40"})


def test_collect_checks_learn_interval_against_the_current_config_poll():
    with pytest.raises(ValueError, match="Learn every"):
        collect(
            {"domain_learn_interval_seconds": "40"}, current_config={"poll_interval_seconds": 30}
        )
    assert collect(
        {"domain_learn_interval_seconds": "60"}, current_config={"poll_interval_seconds": 30}
    )


def test_int_field_rejects_a_fraction_instead_of_truncating():
    with pytest.raises(ValueError, match="whole number"):
        parse_field("int", "5.9", "Ping every")
    assert parse_field("int", "5.0", "Ping every") == 5


@pytest.mark.parametrize(
    "key",
    [
        "failure_threshold",
        "success_threshold",
        "ping_failure_threshold",
        "ping_loss_window",
    ],
)
def test_counts_below_one_are_refused(key):
    with pytest.raises(ValueError):
        collect({key: "0"})
    assert collect({key: "1"}) == {key: 1}


def test_hidden_keys_get_no_field_and_are_never_collected():
    window = SettingsWindow(
        on_save=lambda values: "", hidden_keys=frozenset({"router_enabled", "failover_enabled"})
    )
    assert "router_enabled" not in window.fields
    assert "failover_enabled" not in window.fields
    assert "ping_host" in window.fields
    window.load({"ping_host": "1.1.1.1"})
    assert window.changed_keys({"ping_host": "1.1.1.1"}) == set()


def test_a_long_restart_note_names_a_few_keys_and_counts_the_rest():
    # The status label holds about three lines; a note listing 62 keys was cut
    # off after the second, so the restart instruction never showed.
    restart_keys = sorted(NEEDS_RESTART)[:10]
    note = restart_note({key: 1 for key in restart_keys})
    assert "(10)" in note
    assert "and 6 more" in note
    assert all(key in note for key in restart_keys[:4])
    assert restart_keys[4] not in note
    assert note.rstrip().endswith(SERVICE_RESTART_HINT)
