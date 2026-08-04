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
    FIELDS,
    NEEDS_RESTART,
    SettingsWindow,
    backup_path,
    collect,
    format_field,
    parse_field,
    restart_note,
    save_config,
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
    with pytest.raises(ValueError, match="host:port"):
        parse_field("targets", "192.168.1.1:https", "LAN targets")


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
    """
    path = str(tmp_path / "config.yaml")
    save_config(
        path, collect({key: format_field(kind, DEFAULT_CONFIG[key]) for key, _l, kind in FIELDS})
    )
    reloaded = load_config(path)
    for key in DEFAULT_CONFIG:
        assert key in reloaded


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
    """Comments are lost, so the file has to say where the explanations went."""
    path = tmp_path / "config.yaml"
    save_config(str(path), {"ping_host": "1.1.1.1"})
    body = path.read_text(encoding="utf-8")
    assert "config.example.yaml" in body
    assert "NOT preserved" in body


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


def test_changes_that_take_effect_immediately_say_so():
    note = restart_note({"ping_host": "1.1.1.1"})
    assert "immediately" in note


def test_the_restart_set_only_names_real_config_keys():
    for key in NEEDS_RESTART:
        assert key in DEFAULT_CONFIG


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


def test_the_window_warns_before_saving_not_after():
    """By the time a dialog could say it, the comments would already be gone."""
    window = SettingsWindow(on_save=lambda values: "")
    assert "comments" in window.notice.stringValue()
    assert "bak-" in window.notice.stringValue()
