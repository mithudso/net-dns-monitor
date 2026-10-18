"""The tooltip and menu catalogue: what the windows say about their controls.

Pure data, no AppKit. The window-level walk that proves the *controls* carry these
tips is tests/test_ui_windows.py.
"""

import pytest

from netdnsmonitor import distribution, ui_catalog
from netdnsmonitor.config import DEFAULT_CONFIG
from netdnsmonitor.dashboard import ALL_ACTIONS, LOG_ACTIONS
from netdnsmonitor.settings_window import FIELDS, GROUPS
from netdnsmonitor.ui_catalog import (
    ACTION_GROUPS,
    ACTION_TIPS,
    LOG_ACTION_TIPS,
    PRIMARY_ACTIONS,
    SETTING_TIPS,
    app_options,
    group_actions,
)

STORE = distribution.detect({"NETDNS_DISTRIBUTION": "appstore"})
DIRECT = distribution.detect({})


# --- settings ----------------------------------------------------------------


def test_every_config_option_is_in_the_settings_window():
    """The window is advertised as covering every configurable option."""
    assert {key for key, _label, _kind in FIELDS} == set(DEFAULT_CONFIG)


def test_every_setting_has_a_tooltip_and_none_is_orphaned():
    keys = {key for key, _label, _kind in FIELDS}
    assert set(SETTING_TIPS) == keys
    for key, text in SETTING_TIPS.items():
        assert len(text.strip()) > 20, f"{key}: a tooltip should say something"


def test_every_settings_group_has_a_tooltip():
    for group, _fields in GROUPS:
        assert group in ui_catalog.GROUP_TIPS, group


def test_a_setting_that_needs_a_restart_says_so_in_its_tooltip():
    from netdnsmonitor.settings_window import NEEDS_RESTART

    for key in NEEDS_RESTART:
        assert "restart" in SETTING_TIPS[key].lower(), key


# --- dashboard actions -------------------------------------------------------


def available(caps):
    from netdnsmonitor import app as app_module

    gated = {
        action_id
        for action_id, (feature, _what) in app_module.GATED_DASHBOARD_ACTIONS.items()
        if not getattr(caps, feature)
    }
    return [a for a in ALL_ACTIONS if a[1] not in gated]


@pytest.mark.parametrize("caps", [DIRECT, STORE], ids=["direct", "store"])
def test_every_available_action_is_reachable_exactly_once(caps):
    actions = available(caps)
    primary, groups = group_actions(actions)
    placed = [a[1] for a in primary] + [a[1] for g in groups for a in g[2]]
    assert sorted(placed) == sorted(a[1] for a in actions)


def test_the_store_build_shows_no_empty_menu():
    _primary, groups = group_actions(available(STORE))
    assert all(members for _title, _tip, members in groups)
    titles = [g[0] for g in groups]
    assert "Permissions" not in titles  # both its actions are root-only
    assert "Repairs" not in titles  # flush_dns_cache is gated in the store build


def test_the_buttons_that_stay_are_the_outage_ones():
    primary, _ = group_actions(ALL_ACTIONS)
    assert [a[1] for a in primary] == list(PRIMARY_ACTIONS)


def test_an_action_no_group_names_still_appears_under_more():
    extra = ALL_ACTIONS + [("Brand new", "brand_new", "check")]
    _primary, groups = group_actions(extra)
    assert groups[-1][0] == "More"
    assert [a[1] for a in groups[-1][2]] == ["brand_new"]


def test_groups_name_only_real_actions():
    ids = {a[1] for a in ALL_ACTIONS}
    for _title, _tip, members in ACTION_GROUPS:
        assert set(members) <= ids


def test_every_action_has_a_tooltip_and_a_repair_says_it_changes_state():
    for _label, action_id, kind in ALL_ACTIONS:
        assert action_id in ACTION_TIPS, action_id
        if kind == "repair":
            assert "changes system state" in ui_catalog.action_tip(action_id, kind).lower()


def test_every_log_control_has_a_tooltip():
    for _title, action_id in LOG_ACTIONS:
        assert LOG_ACTION_TIPS[action_id]
    assert LOG_ACTION_TIPS["log_search"]


# --- options that are not config keys -----------------------------------------


def test_the_direct_build_offers_every_app_level_option():
    specs = app_options(DIRECT)
    ids = set()
    for spec in specs:
        if spec[0] == "menu":
            ids |= {entry[1] for entry in spec[3]}
        else:
            ids.add(spec[1])
    assert {
        "app_toggle_login",
        "app_toggle_claude",
        "cred_ANTHROPIC_API_KEY",
        "cred_SLACK_WEBHOOK_URL",
        "cred_SMTP_PASSWORD",
        "cred_remove",
        "grant_privileges",
        "revoke_privileges",
        "open_remediation_editor",
    } <= ids


def test_the_store_build_offers_only_what_it_can_honour():
    ids = set()
    for spec in app_options(STORE):
        if spec[0] == "menu":
            ids |= {entry[1] for entry in spec[3]}
        else:
            ids.add(spec[1])
    assert "app_toggle_login" not in ids
    assert not {"grant_privileges", "revoke_privileges", "open_remediation_editor"} & ids
    assert "app_toggle_claude" in ids  # the consent prompt is the store build's


def test_every_app_option_has_a_tooltip():
    for caps in (DIRECT, STORE):
        for spec in app_options(caps):
            if spec[0] == "menu":
                assert spec[2].strip()
                assert all(entry[2].strip() for entry in spec[3])
            else:
                assert spec[3].strip()


def test_credential_entries_match_the_menu_bars():
    from netdnsmonitor.app import CREDENTIAL_ITEMS

    assert [e[1] for e in ui_catalog.CREDENTIAL_ENTRIES[:-1]] == [
        f"cred_{name}" for _title, name, _msg in CREDENTIAL_ITEMS
    ]
