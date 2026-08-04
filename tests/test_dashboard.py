"""The dashboard window: its contents as pure data, and the real AppKit window.

The window is built for real rather than mocked, the same choice
test_dock_icon.py makes -- NSWindow construction works headlessly and the
properties that matter (retain policy, button wiring, layout) are exactly the
ones that fail silently in a bundle. `show()` is deliberately never called: that
would flash a window across the screen on every test run.
"""

from netdnsmonitor.dashboard import (
    ALL_ACTIONS,
    LEFT_WIDTH,
    LOG_ACTIONS,
    LOG_WIDTH,
    MARGIN,
    SECONDARY_ACTIONS,
    TROUBLESHOOTING_ACTIONS,
    WINDOW_HEIGHT,
    WINDOW_WIDTH,
    DashboardWindow,
    dashboard_sections,
    render_dashboard_text,
)

HEALTHY = {"rtt_ms": 61.4, "loss_pct": 0.0, "down_bps": 1_200_000, "up_bps": 300_000, "down": False}
DOWN = {"rtt_ms": None, "loss_pct": 100.0, "down_bps": None, "up_bps": None, "down": True}
NO_DATA = {"rtt_ms": None, "loss_pct": None, "down_bps": None, "up_bps": None, "down": False}

CONFIG = {
    "ping_host": "8.8.8.8",
    "ping_interval_seconds": 5,
    "ping_failure_threshold": 1,
    "ping_alert_repeat_seconds": 0,
    "poll_interval_seconds": 30,
    "failure_threshold": 2,
    "success_threshold": 2,
    "resolution_interval_seconds": 300,
    "domains": ["cloudflare.com"],
}


def flat(sections):
    return {label: value for _, rows in sections for label, value in rows}


# --- contents --------------------------------------------------------------


def test_shows_the_current_reading(tmp_path):
    rows = flat(dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG))
    assert rows["Ping target"] == "8.8.8.8"
    assert rows["Round trip"] == "61 ms"
    assert rows["Packet loss"] == "0%"
    assert "1.2M" in rows["Download"]
    assert "300K" in rows["Upload"]


def test_a_down_network_says_no_reply_rather_than_a_stale_number():
    rows = flat(
        dashboard_sections(ping_stats={**DOWN, "rtt_ms": 61.0}, flap_state="healthy", config=CONFIG)
    )
    assert rows["Round trip"] == "no reply"


def test_before_the_first_ping_nothing_is_presented_as_measured():
    rows = flat(dashboard_sections(ping_stats=NO_DATA, flap_state="healthy", config=CONFIG))
    assert rows["Round trip"] == "not measured yet"
    assert rows["Packet loss"] == "not measured yet"
    assert rows["Download"] == "not measured yet"


def test_status_reports_a_dead_ping_first():
    """Precedence matters: a down heartbeat is the most urgent and most specific
    thing the window can say, and it is known seconds before the gate agrees.
    """
    rows = flat(dashboard_sections(ping_stats=DOWN, flap_state="healthy", config=CONFIG))
    assert "DOWN" in rows["Status"]


def test_status_reports_a_declared_incident():
    rows = flat(dashboard_sections(ping_stats=HEALTHY, flap_state="incident", config=CONFIG))
    assert "incident" in rows["Status"]


def test_status_reports_flaky_below_the_incident_threshold():
    rows = flat(
        dashboard_sections(
            ping_stats=HEALTHY, flap_state="healthy", consecutive_failures=1, config=CONFIG
        )
    )
    assert "flaky" in rows["Status"]


def test_status_reports_healthy():
    rows = flat(dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG))
    assert rows["Status"] == "healthy"


def test_resolution_batch_summarised_when_one_has_run():
    rows = flat(
        dashboard_sections(
            ping_stats=HEALTHY,
            flap_state="healthy",
            config=CONFIG,
            resolution_findings=[{"resolved": True}, {"resolved": False}],
        )
    )
    assert rows["Resolution check"] == "1 of 2 domains failing"


def test_resolution_batch_distinguishes_never_run_from_all_passing():
    """`0 of 0` would read as a clean bill of health from a batch that never ran."""
    rows = flat(dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG))
    assert rows["Resolution check"] == "no batch has run yet"


def test_an_open_forensic_episode_is_visible_with_its_start_time():
    rows = flat(
        dashboard_sections(
            ping_stats=DOWN,
            flap_state="healthy",
            config=CONFIG,
            episode_open=True,
            episode_started_at="2026-08-04T12:00:00+00:00",
        )
    )
    assert "2026-08-04T12:00:00+00:00" in rows["Forensic episode"]


def test_settings_in_force_are_shown_so_behaviour_is_explicable():
    rows = flat(dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG))
    assert rows["Ping every"] == "5s"
    assert "1 failed ping" in rows["Alert after"]
    assert "one alert per outage" in rows["Re-alert while down"]
    assert rows["Domains checked for DNS"] == "cloudflare.com"


def test_an_empty_domains_list_is_called_out_not_left_blank():
    """An empty `domains` list is the documented foot-gun that latches a
    permanent false incident, so the window must not render it as whitespace.
    """
    rows = flat(
        dashboard_sections(
            ping_stats=HEALTHY, flap_state="healthy", config={**CONFIG, "domains": []}
        )
    )
    assert rows["Domains checked for DNS"] == "none configured"


def test_missing_config_keys_do_not_crash_the_window():
    """The window must render against a bare config rather than raising inside a
    click handler, where the traceback would be invisible.
    """
    rows = flat(dashboard_sections(ping_stats=NO_DATA, flap_state="healthy", config={}))
    assert rows["Ping target"] == "unknown"


def test_rendered_text_aligns_values_in_one_column_across_all_sections():
    """Padding per section instead of globally makes the values step in and out
    down the window, which is what the monospaced font is there to avoid.
    """
    import re

    text = render_dashboard_text(
        dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG)
    )
    # Label and value are separated by 3+ spaces; the value's start offset must
    # be identical on every row of every section.
    value_columns = set()
    for line in text.splitlines():
        match = re.match(r"^ {2}(\S.*?) {3,}(\S)", line)
        if match:
            value_columns.add(match.start(2))
    assert len(value_columns) == 1, value_columns


def test_rendered_text_labels_every_section():
    text = render_dashboard_text(
        dashboard_sections(ping_stats=HEALTHY, flap_state="healthy", config=CONFIG)
    )
    assert "NETWORK RIGHT NOW" in text
    assert "MONITOR" in text
    assert "SETTINGS IN FORCE" in text


# --- the window ------------------------------------------------------------


def test_window_is_titled_and_sized():
    window = DashboardWindow(on_action=lambda action: None)
    assert window.window.title() == "Net-DNS-Monitor"
    assert window.window.frame().size.width == WINDOW_WIDTH
    assert WINDOW_WIDTH == LEFT_WIDTH + LOG_WIDTH + MARGIN


def test_the_window_still_fits_on_a_1080_high_display():
    """Why the log pane went beside the existing content instead of below it.

    The window was already 950 tall and the display it opens on is 1080 logical
    pixels high; a pane stacked underneath would have run off the bottom of the
    screen, where a window cannot be dragged back from. Growing sideways is the
    only direction with room, so this pins the height against the constraint that
    forced the two-column layout -- otherwise the next feature quietly adds 200px
    and the window becomes unusable on the machine it was built for.
    """
    assert WINDOW_HEIGHT <= 1000


def test_window_is_not_released_when_closed():
    """The trap that makes the second open crash: with the default release
    policy, closing the window deallocates it and the next `show()` touches
    freed memory. Nothing else in the suite would catch that.
    """
    window = DashboardWindow(on_action=lambda action: None)
    assert window.window.isReleasedWhenClosed() is False


def test_every_declared_action_gets_a_button():
    window = DashboardWindow(on_action=lambda action: None)
    assert len(window.buttons) == len(ALL_ACTIONS)
    assert len(ALL_ACTIONS) == len(TROUBLESHOOTING_ACTIONS) + len(SECONDARY_ACTIONS)


# --- the log column --------------------------------------------------------


def test_the_log_controls_are_not_counted_as_troubleshooting_buttons():
    """`self.buttons` is the troubleshooting grid and the test above counts it
    against ALL_ACTIONS. Log controls live in their own dict so adding one cannot
    break that count, and so the layout code cannot lay them out twice.
    """
    window = DashboardWindow(on_action=lambda action: None)
    assert set(window.log_control_buttons) == {action_id for _, action_id in LOG_ACTIONS}
    assert len(window.buttons) == len(ALL_ACTIONS)


def test_every_log_control_carries_its_action_id_and_a_target():
    """Same failure mode as the troubleshooting buttons: a nil target is a button
    that looks normal and does nothing.
    """
    window = DashboardWindow(on_action=lambda action: None)
    for action_id, button in window.log_control_buttons.items():
        assert button.target() is not None
        assert str(button.identifier()) == action_id


def test_clicking_a_log_control_dispatches_its_action_id():
    seen = []
    window = DashboardWindow(on_action=seen.append)
    window._handle(window.log_control_buttons["log_refresh"])
    assert seen == ["log_refresh"]


def test_the_search_field_reports_what_was_typed():
    window = DashboardWindow(on_action=lambda action: None)
    window.set_search_query("dns -crowdstrike")
    assert window.search_query() == "dns -crowdstrike"


def test_the_search_field_shares_the_one_button_target():
    """Defining a second ObjC target class raises "_ButtonTarget is overriding
    existing Objective-C class" the second time a window is built, and the second
    window is the reopen path -- i.e. normal use. Return in the search field has
    to go through the same shared target the buttons use.
    """
    window = DashboardWindow(on_action=lambda action: None)
    assert window.log_search_field.target() is window._target
    assert str(window.log_search_field.identifier()) == "log_search"


def test_the_log_pane_does_not_overlap_its_controls():
    """Pure frame arithmetic again, and the same failure the left column had: a
    control added to the row above silently lands on top of the pane.
    """
    window = DashboardWindow(on_action=lambda action: None)
    pane = window.log_view.enclosingScrollView()
    pane_top = pane.frame().origin.y + pane.frame().size.height
    assert pane_top <= window.log_status_label.frame().origin.y
    lowest_control = min(b.frame().origin.y for b in window.log_control_buttons.values())
    assert lowest_control >= pane_top


def test_the_log_column_stays_beside_the_left_column_not_on_top_of_it():
    window = DashboardWindow(on_action=lambda action: None)
    left_edge = window.log_view.enclosingScrollView().frame().origin.x
    stats = window.stats_view.enclosingScrollView().frame()
    assert left_edge >= stats.origin.x + stats.size.width
    assert left_edge + LOG_WIDTH <= WINDOW_WIDTH


def test_the_log_pane_is_read_only_but_updatable():
    window = DashboardWindow(on_action=lambda action: None)
    window.set_log("12:00:00 ! configd: something\n")
    assert "configd" in str(window.log_view.string())
    assert window.log_view.isEditable() is False


def test_the_log_status_line_is_updatable():
    window = DashboardWindow(on_action=lambda action: None)
    window.set_log_status("40 entries  |  3 error/fault")
    assert "40 entries" in str(window.log_status_label.stringValue())


def test_the_level_button_title_states_the_current_filter():
    window = DashboardWindow(on_action=lambda action: None)
    window.set_log_level_title("All levels")
    assert str(window.log_control_buttons["log_toggle_level"].title()) == "All levels"


def test_every_button_is_wired_to_a_target_and_carries_its_action_id():
    """An NSButton with a nil target is silently inert -- it looks completely
    normal and does nothing when clicked.
    """
    window = DashboardWindow(on_action=lambda action: None)
    ids = {action_id for _, action_id, _ in ALL_ACTIONS}
    for button in window.buttons:
        assert button.target() is not None
        assert button.action() == "invoke:"
        assert str(button.identifier()) in ids


def test_clicking_a_button_dispatches_its_action_id():
    """Driven through the real ObjC target, so this covers the bridge rather
    than just the Python handler.
    """
    dispatched = []
    window = DashboardWindow(on_action=dispatched.append)
    by_id = {str(b.identifier()): b for b in window.buttons}
    window._target.invoke_(by_id["flush_dns_cache"])
    window._target.invoke_(by_id["ping_now"])
    assert dispatched == ["flush_dns_cache", "ping_now"]


def test_state_changing_buttons_say_so():
    """`flush_dns_cache` mutates system state. A button that does that should
    warn before it is clicked, not after.
    """
    repairs = {action_id for _, action_id, kind in ALL_ACTIONS if kind == "repair"}
    assert "flush_dns_cache" in repairs
    label = next(label for label, aid, _ in ALL_ACTIONS if aid == "flush_dns_cache")
    assert "changes system state" in label.lower()

    window = DashboardWindow(on_action=lambda action: None)
    for button in window.buttons:
        if str(button.identifier()) in repairs:
            assert "state" in (button.toolTip() or "").lower()


def test_buttons_do_not_overlap_the_output_pane():
    """Pure frame arithmetic with no layout constraints, so a longer action list
    silently pushes buttons down over the results pane.
    """
    window = DashboardWindow(on_action=lambda action: None)
    output_top = (
        window.output_view.enclosingScrollView().frame().origin.y
        + window.output_view.enclosingScrollView().frame().size.height
    )
    lowest_button = min(b.frame().origin.y for b in window.buttons)
    assert lowest_button >= output_top


def test_buttons_stay_inside_the_window():
    window = DashboardWindow(on_action=lambda action: None)
    for button in window.buttons:
        frame = button.frame()
        assert frame.origin.x >= 0
        assert frame.origin.x + frame.size.width <= 640


def test_stats_pane_is_updatable_and_read_only():
    window = DashboardWindow(on_action=lambda action: None)
    window.set_stats("NETWORK RIGHT NOW\n  Round trip   61 ms\n")
    assert "61 ms" in window.stats_view.string()
    assert window.stats_view.isEditable() is False


def test_output_pane_accumulates_rather_than_replacing():
    """Each troubleshooting step's result has to join the previous ones, or the
    only visible output is whatever finished last.
    """
    window = DashboardWindow(on_action=lambda action: None)
    window.append_output("first\n")
    window.append_output("second\n")
    body = window.output_view.string()
    assert "first" in body
    assert "second" in body
    assert body.index("first") < body.index("second")
