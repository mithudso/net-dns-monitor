"""Build each AppKit window headlessly and walk its controls.

The offline suite cannot look at pixels, but it can construct a window (the other
window tests do) and ask every control the one thing the interface promises:
**every button, menu, field and toggle has a tooltip**. A control added later
without one fails here.

None of these windows is ordered front, so nothing appears on screen.
"""

import AppKit
import pytest

from netdnsmonitor import distribution, ui_style
from netdnsmonitor.dashboard import ALL_ACTIONS, DashboardWindow
from netdnsmonitor.mini_window import MiniWindow
from netdnsmonitor.settings_window import FIELDS, SettingsWindow
from netdnsmonitor.ui_catalog import SETTING_TIPS, app_options

DIRECT = distribution.detect({})
STORE = distribution.detect({"NETDNS_DISTRIBUTION": "appstore"})


def assert_all_tipped(window):
    missing = ui_style.controls_without_tip(AppKit, window.contentView())
    assert missing == []


def test_the_dashboard_has_a_tooltip_on_every_control():
    assert_all_tipped(DashboardWindow(on_action=lambda a: None).window)


def test_the_store_dashboard_has_a_tooltip_on_every_control():
    actions = [a for a in ALL_ACTIONS if a[1] not in ("open_console", "grant_privileges")]
    window = DashboardWindow(on_action=lambda a: None, actions=actions, log_column=False)
    assert_all_tipped(window.window)


def test_every_dashboard_menu_item_has_its_own_tooltip():
    window = DashboardWindow(on_action=lambda a: None)
    for action_id, control in window.action_controls.items():
        assert (control.toolTip() or "").strip(), action_id


def test_the_dashboard_groups_actions_into_few_top_level_controls():
    window = DashboardWindow(on_action=lambda a: None)
    assert len(window.buttons) <= 8
    pulldowns = [b for b in window.buttons if isinstance(b, AppKit.NSPopUpButton)]
    assert {str(b.itemArray()[0].title()) for b in pulldowns} >= {"Checks", "Tools", "Reports"}


@pytest.mark.parametrize("caps", [DIRECT, STORE], ids=["direct", "store"])
def test_settings_has_a_tooltip_on_every_field_label_and_control(caps):
    window = SettingsWindow(
        on_save=lambda values: "", app_options=app_options(caps), on_app_action=lambda a: None
    )
    assert_all_tipped(window.window)
    assert set(window.fields) == {key for key, _l, _k in FIELDS}
    for key, field in window.fields.items():
        assert str(field.toolTip()) == SETTING_TIPS[key]


def test_settings_app_options_row_dispatches_to_the_app():
    seen = []
    window = SettingsWindow(
        on_save=lambda values: "", app_options=app_options(DIRECT), on_app_action=seen.append
    )
    window._handle(window.app_controls["open_remediation_editor"])
    window._handle(window.app_controls["cred_SMTP_PASSWORD"])
    assert seen == ["open_remediation_editor", "cred_SMTP_PASSWORD"]


def test_settings_checkboxes_follow_the_state_it_is_given():
    window = SettingsWindow(
        on_save=lambda values: "", app_options=app_options(DIRECT), on_app_action=lambda a: None
    )
    window.set_app_state({"app_toggle_claude": True, "app_toggle_login": False})
    assert window.app_controls["app_toggle_claude"].state() == 1
    assert window.app_controls["app_toggle_login"].state() == 0


def test_the_mini_window_label_has_a_tooltip():
    window = MiniWindow()
    assert (window.label.toolTip() or "").strip()


def test_windows_take_the_glass_path_when_the_system_has_it():
    window = DashboardWindow(on_action=lambda a: None)
    expected = "glass" if ui_style.glass_available(AppKit) else "vibrancy"
    assert window.glass_kind == expected
    wanted = "GlassEffectView" if expected == "glass" else "VisualEffectView"
    assert wanted in type(window.window.contentView()).__name__


def test_a_system_without_glass_falls_back_to_vibrancy(monkeypatch):
    monkeypatch.setattr(ui_style, "glass_available", lambda AppKit: False)
    window = DashboardWindow(on_action=lambda a: None)
    assert window.glass_kind == "vibrancy"
    assert "VisualEffectView" in type(window.window.contentView()).__name__
    assert_all_tipped(window.window)


def test_the_remediation_editor_has_a_tooltip_on_every_control(tmp_path):
    from netdnsmonitor.remediation_editor import EditorSession
    from netdnsmonitor.remediation_scripts import ScriptStore
    from netdnsmonitor.remediation_window import RemediationWindowController

    controller = RemediationWindowController(EditorSession(ScriptStore(user_dir=tmp_path / "u")))
    controller.build()
    assert_all_tipped(controller.window)


def test_the_router_window_has_a_tooltip_on_every_control():
    from netdnsmonitor import router_window

    controller = router_window.RouterWindowController(config={})
    controller._target = (
        router_window._router_target_class().alloc().initWithController_(controller)
    )
    controller._build_window()
    assert_all_tipped(controller.window)


def test_an_empty_tooltip_is_refused():
    with pytest.raises(ValueError):
        ui_style.tip(AppKit.NSButton.alloc().init(), "  ")
