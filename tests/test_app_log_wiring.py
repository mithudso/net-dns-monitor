"""The system log viewer, as wired into the rumps shell.

`app.log_reader` is replaced in every test here. Nothing in this suite may run
`log show`: it is a multi-second archive scan whose output depends on whatever the
machine happened to be doing, so a test that used the real one would be both slow
and differently wrong on every run. `system_log.py` covers the reader itself with
an injected `run_fn`.

`show()` is monkeypatched for the same reason test_app_dashboard_wiring.py does
it -- it calls `activateIgnoringOtherApps_`, which would flash a window across the
screen on every test run.
"""

import pytest

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.forensic_log import ForensicRecorder
from netdnsmonitor.system_log import parse_lines

UNREACHABLE = (
    "2026-08-04 12:48:56.386 E  identityservicesd[762:ac80d] "
    "[com.apple.network:connection] nw_socket_handle_socket_event [C134.1.1:3] "
    "Socket SO_ERROR [51: Network is unreachable]"
)

SECOND_ERROR = (
    "2026-08-04 12:49:02.100 E  configd[123:abc] [com.apple.SystemConfiguration:] "
    "DHCP en0: INIT-REBOOT timed out"
)

CROWDSTRIKE_NOISE = (
    "2026-08-04 12:48:45.379 E  com.crowdstrike.falcon.Agent[580:a8fb7] "
    "[com.apple.network:] nw_endpoint_get_address called with null endpoint, "
    "backtrace limit exceeded"
)

MDNS_DEFAULT = (
    "2026-08-04 12:48:48.537 Df mDNSResponder[441:ac0cd] [com.apple.mdns:dnssd_server] "
    "[R20823] getaddrinfo start -- hostname: <mask.hash: 'bUgVj5G8ik0EQt8fUVm4Fg=='>"
)


@pytest.fixture(autouse=True)
def _no_real_window(monkeypatch):
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show",
        lambda self, activate=True: None,
    )
    # `show` is stubbed so no window flashes across the screen, which leaves the real
    # `is_visible()` answering False -- and the refresh paths now skip a hidden window.
    # A double that stubs the shower must also stub the observable it sets, or every
    # assertion about painted content tests the guard instead of the content.
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.is_visible",
        lambda self: True,
    )


def reader_returning(*lines, error=None):
    """A stand-in for make_log_reader's return value, recording its arguments."""
    calls = []

    def reader(window="1m", errors_only=True):
        calls.append({"window": window, "errors_only": errors_only})
        return {"entries": parse_lines(lines), "error": error}

    reader.calls = calls
    return reader


def backfill(app, window="15m"):
    """The launch-time read, run to completion on this thread."""
    app._start_log_read(window, announce=False)
    if app._log_thread is not None:
        app._log_thread.join(timeout=5)
    app._drain_log_results()


def build_app(tmp_path, reader=None):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-config.yaml"))
    app.log_reader = reader if reader is not None else reader_returning()
    return app


def read_now(app, window="1m"):
    """Run one read to completion on this thread, then fold it in.

    `_start_log_read` spawns a daemon thread; joining it keeps the test
    deterministic rather than sleeping and hoping.
    """
    app._start_log_read(window)
    if app._log_thread is not None:
        app._log_thread.join(timeout=5)
    app._drain_log_results()


# --- the poller ------------------------------------------------------------


def test_the_log_poll_runs_off_the_run_loop(tmp_path):
    """`log show` measured 1.4s for a 1-minute window. On the run loop that would
    stall the 5-second heartbeat and freeze the window for the length of every
    poll, which is the same reason the ping does not run there.
    """
    app = build_app(tmp_path)
    app.log_tick()
    assert app._log_thread is not None
    assert app._log_thread.daemon is True
    app._log_thread.join(timeout=5)


def test_a_read_still_running_is_not_stacked_with_another(tmp_path):
    """A read that outran its cadence means the machine is busy; starting a second
    one is the wrong response. Same choice ping_tick and resolution_tick make.
    """
    app = build_app(tmp_path)

    class FakeThread:
        daemon = True

        def is_alive(self):
            return True

    app._log_thread = FakeThread()
    app._start_log_read("1m")
    assert isinstance(app._log_thread, FakeThread)


def test_the_poll_uses_the_configured_window_and_level(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.config["log_view_poll_window"] = "2m"
    read_now(app, app.config["log_view_poll_window"])
    assert app.log_reader.calls[0] == {"window": "2m", "errors_only": True}


def test_entries_land_in_the_buffer(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE, MDNS_DEFAULT))
    read_now(app)
    assert len(app.log_buffer.entries()) == 2
    assert app.log_buffer.error_count() == 1


def test_an_overlapping_poll_does_not_double_count(tmp_path):
    """The window is longer than the interval on purpose, so every entry arrives
    about twice.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    read_now(app)
    read_now(app)
    assert len(app.log_buffer.entries()) == 1


def test_a_read_failure_is_kept_for_the_status_line(tmp_path):
    app = build_app(tmp_path, reader_returning(error="Reading the system log took too long"))
    read_now(app)
    assert app.log_error == "Reading the system log took too long"


def test_the_viewer_can_be_switched_off_entirely(tmp_path):
    """`log_view_enabled: false` has to mean no subprocess at all, not a hidden
    pane that still shells out every 30 seconds.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.config["log_view_enabled"] = False
    app._start_log_read("1m")
    assert app._log_thread is None
    assert app.log_reader.calls == []


def test_a_reader_that_raises_does_not_kill_the_poller(tmp_path):
    """The reader is meant to convert every failure into an error string, so this
    is the unforeseen case -- and it happens on a thread whose exception nobody
    sees.
    """

    def exploding_reader(window="1m", errors_only=True):
        raise RuntimeError("unforeseen")

    app = build_app(tmp_path, exploding_reader)
    read_now(app)
    assert app.log_buffer.entries() == []
    # And the next read still works.
    app.log_reader = reader_returning(UNREACHABLE)
    read_now(app)
    assert len(app.log_buffer.entries()) == 1


# --- automatic reporting ---------------------------------------------------


def test_new_errors_are_announced_without_being_asked_for(tmp_path):
    """The automatic half of the feature: a log pane only helps someone already
    looking at it, and the point of a monitor is that nobody is.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    announced = []
    app._append_output = announced.append
    read_now(app)
    assert announced
    assert "Network is unreachable" in "".join(announced)


def test_the_launch_backfill_is_history_not_news(tmp_path):
    """The backfill reads up to 15 minutes back, so announcing it would report
    quarter-hour-old entries as new -- measured at 618 of them on a real machine,
    which is a burst of "new errors" in the results pane at every single launch.

    It still lands in the buffer, because the pane is meant to open with history in
    it. Only the reporting is suppressed.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE, SECOND_ERROR))
    announced = []
    app._append_output = announced.append
    backfill(app)
    assert announced == []
    assert len(app.log_buffer.entries()) == 2
    assert app.log_buffer.error_count() == 2


def test_the_backfill_does_not_credit_itself_to_the_since_launch_count(tmp_path):
    """Otherwise the Monitor row reads "618 reported since launch" when nothing was
    reported -- and with open_dashboard_at_launch false it climbs while
    _append_output is a no-op into a window that does not exist yet.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app._append_output = lambda text: None
    backfill(app)
    assert app.new_log_errors == 0


def test_errors_arriving_after_the_backfill_are_still_announced(tmp_path):
    """Guard against the suppression leaking into the steady-state poll."""
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app._append_output = lambda text: None
    backfill(app)

    announced = []
    app._append_output = announced.append
    app.log_reader = reader_returning(SECOND_ERROR)
    read_now(app)
    assert "INIT-REBOOT" in "".join(announced)
    assert app.new_log_errors == 1


def test_only_new_errors_are_announced_not_the_whole_buffer_again(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    announced = []
    app._append_output = announced.append
    read_now(app)
    announced.clear()
    read_now(app)
    assert announced == []


def test_suppressed_noise_is_never_announced(tmp_path):
    """It is still captured for the pane -- it just is not worth interrupting the
    results pane for, which is the whole reason the noise list exists.
    """
    app = build_app(tmp_path, reader_returning(CROWDSTRIKE_NOISE))
    announced = []
    app._append_output = announced.append
    read_now(app)
    assert announced == []
    assert len(app.log_buffer.entries()) == 1


def test_non_error_entries_are_not_announced(tmp_path):
    app = build_app(tmp_path, reader_returning(MDNS_DEFAULT))
    announced = []
    app._append_output = announced.append
    read_now(app)
    assert announced == []


def test_the_announcement_is_capped_but_the_count_is_not(tmp_path):
    """Without a cap, one repeating message pushes every manual troubleshooting
    result out of the results pane.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE, SECOND_ERROR))
    app.config["log_view_announce_limit"] = 1
    announced = []
    app._append_output = announced.append
    read_now(app)
    text = "".join(announced)
    assert "2 new network error line(s)" in text
    assert "and 1 more" in text
    assert app.new_log_errors == 2


def test_announced_errors_are_counted_for_the_stats_pane(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE, SECOND_ERROR))
    read_now(app)
    assert app.new_log_errors == 2
    rows = dict(
        row
        for _title, section in _sections(app)
        for row in section  # noqa: B007 - flattening (label, value) pairs
    )
    assert "2 reported since launch" in rows["System log"]


def _sections(app):
    from netdnsmonitor.dashboard import dashboard_sections

    return dashboard_sections(
        ping_stats=app.ping_stats,
        flap_state="healthy",
        config=app.config,
        log_entries=len(app.log_buffer.entries()),
        log_errors=app.log_buffer.error_count(),
        new_log_errors=app.new_log_errors,
        log_error=app.log_error,
    )


def test_errors_during_an_open_episode_are_written_into_it(tmp_path):
    """So the forensic record of an outage says what the OS reported at the time,
    not only what this app measured.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.forensic = ForensicRecorder(
        journal_path=str(tmp_path / "journal.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
    )
    app.forensic.note("down", "ping", reason="no reply", result="episode open")
    read_now(app)
    journal = (tmp_path / "journal.jsonl").read_text(encoding="utf-8")
    assert "system_log" in journal
    assert "Network is unreachable" in journal


def test_nothing_is_recorded_when_no_episode_is_open(tmp_path):
    """A quiet network still logs the occasional error. Recording those would file
    evidence against an outage that is not happening.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.forensic = ForensicRecorder(
        journal_path=str(tmp_path / "journal.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
    )
    read_now(app)
    assert not (tmp_path / "journal.jsonl").exists()


# --- the pane ---------------------------------------------------------------


def test_the_pane_is_filtered_by_whatever_is_in_the_search_box(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE, SECOND_ERROR))
    read_now(app)
    app.open_dashboard()
    app._dashboard.set_search_query("dhcp")
    app._refresh_log_pane()
    pane = str(app._dashboard.log_view.string())
    assert "INIT-REBOOT" in pane
    assert "Network is unreachable" not in pane


def test_the_pane_is_not_rewritten_when_nothing_changed(tmp_path):
    """setString_ resets the scroll position, so at the 1-second refresh this would
    drag the pane back to the top every second while someone is reading it.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    read_now(app)
    app.open_dashboard()
    pushes = []
    app._dashboard.set_log = pushes.append
    app._refresh_log_pane()
    app._refresh_log_pane()
    assert pushes == []


def test_the_pane_is_rewritten_when_a_new_entry_arrives(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    read_now(app)
    app.open_dashboard()
    pushes = []
    app._dashboard.set_log = pushes.append
    app.log_reader = reader_returning(SECOND_ERROR)
    read_now(app)
    app._refresh_log_pane()
    assert len(pushes) == 1
    assert "INIT-REBOOT" in pushes[0]


def test_an_empty_pane_says_which_kind_of_empty_it_is(tmp_path):
    """Four different things produce a blank pane and only some of them say
    anything about the network.
    """
    app = build_app(tmp_path)
    app.open_dashboard()

    app._refresh_log_pane()
    quiet = str(app._dashboard.log_view.string())
    assert "No network errors or faults" in quiet

    app._dashboard.set_search_query("nothing matches this")
    app._refresh_log_pane()
    assert "matches" in str(app._dashboard.log_view.string())

    app._dashboard.set_search_query("")
    app.log_error = "`log show` failed: not permitted"
    app._refresh_log_pane()
    assert "not permitted" in str(app._dashboard.log_view.string())

    app.log_error = None
    app.config["log_view_enabled"] = False
    app._refresh_log_pane()
    assert "switched off" in str(app._dashboard.log_view.string())


def test_a_control_does_not_claim_a_re_read_that_never_happened(tmp_path):
    """`log_view_enabled: false` still builds the log control buttons, and
    `_start_log_read` returns immediately. The buttons used to print "re-reading the
    last 1m" anyway -- and with the viewer off, no read would ever happen.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.config["log_view_enabled"] = False
    app.open_dashboard()
    output = []
    app._append_output = output.append

    app.handle_dashboard_action("log_refresh")
    app.handle_dashboard_action("log_toggle_level")

    text = "".join(output)
    assert "switched off" in text
    assert "Re-reading the system log" not in text
    assert "re-reading the last" not in text
    assert app.log_reader.calls == []


def test_the_level_button_still_reports_the_new_filter_when_no_read_ran(tmp_path):
    """The filter did change even though nothing was re-read, so saying nothing at
    all would be its own lie.
    """
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.config["log_view_enabled"] = False
    app.open_dashboard()
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("log_toggle_level")
    assert app.log_errors_only is False
    assert "all levels" in "".join(output).lower()


def test_a_skipped_read_says_one_is_already_in_flight(tmp_path):
    class FakeThread:
        daemon = True

        def is_alive(self):
            return True

    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app._log_thread = FakeThread()
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("log_refresh")
    assert "already in flight" in "".join(output)


def test_an_all_filtered_pane_says_so_rather_than_looking_like_a_quiet_network(tmp_path):
    """Every captured entry matched a noise pattern. An empty pane reading "no
    network errors yet" would be indistinguishable from a healthy network.
    """
    app = build_app(tmp_path, reader_returning(CROWDSTRIKE_NOISE))
    app._append_output = lambda text: None
    read_now(app)
    app.open_dashboard()
    app._refresh_log_pane()

    pane = str(app._dashboard.log_view.string())
    assert "filtered out" in pane
    assert "1 entries captured" in pane
    assert "No network errors or faults" not in pane


def test_the_forensic_record_is_not_truncated_by_the_announce_cap(tmp_path):
    """`log_view_announce_limit` caps what is printed into the results pane. An
    episode write-up that silently kept 3 of 12 error lines would be evidence with a
    hole in it, and the "...and N more" note goes to the pane, not the episode.
    """
    lines = [
        f"2026-08-04 12:5{i}:00.000 E  configd[1:a] [com.apple.network:] distinct failure {i}"
        for i in range(6)
    ]
    app = build_app(tmp_path, reader_returning(*lines))
    app.config["log_view_announce_limit"] = 2
    app.forensic = ForensicRecorder(
        journal_path=str(tmp_path / "journal.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
    )
    app.forensic.note("down", "ping", reason="no reply", result="episode open")
    announced = []
    app._append_output = announced.append
    read_now(app)

    journal = (tmp_path / "journal.jsonl").read_text(encoding="utf-8")
    for index in range(6):
        assert f"distinct failure {index}" in journal, index
    # The pane, by contrast, is capped.
    assert "and 4 more" in "".join(announced)


def test_the_pane_refresh_is_harmless_with_no_window_open(tmp_path):
    """ui_tick calls this every second for the life of the process, and the window
    is created lazily on first open.
    """
    app = build_app(tmp_path)
    assert app._dashboard is None
    app._refresh_log_pane()


# --- the controls -----------------------------------------------------------


def test_the_level_button_switches_the_filter_and_re_reads(tmp_path):
    """The level is part of the predicate, so entries at other levels were never
    fetched and are not in the buffer to filter -- switching has to re-read.
    """
    app = build_app(tmp_path, reader_returning(MDNS_DEFAULT))
    app.open_dashboard()
    assert app.log_errors_only is True

    app.handle_dashboard_action("log_toggle_level")
    if app._log_thread is not None:
        app._log_thread.join(timeout=5)
    app._drain_log_results()

    assert app.log_errors_only is False
    assert app.log_reader.calls[-1]["errors_only"] is False
    assert len(app.log_buffer.entries()) == 1


def test_the_level_button_title_states_the_filter_in_force(tmp_path):
    """A label that names the action rather than the state gets read backwards, and
    then someone concludes the log is empty while looking at a filtered view.
    """
    app = build_app(tmp_path)
    app.open_dashboard()
    button = app._dashboard.log_control_buttons["log_toggle_level"]
    assert str(button.title()) == "Errors only"
    app.handle_dashboard_action("log_toggle_level")
    assert str(button.title()) == "All levels"


def test_clear_search_empties_the_box(tmp_path):
    app = build_app(tmp_path)
    app.open_dashboard()
    app._dashboard.set_search_query("dns")
    app.handle_dashboard_action("log_clear_search")
    assert app._dashboard.search_query() == ""


def test_refresh_now_triggers_a_read(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    app.handle_dashboard_action("log_refresh")
    if app._log_thread is not None:
        app._log_thread.join(timeout=5)
    assert app.log_reader.calls


def test_emptying_the_buffer_clears_the_counts_too(tmp_path):
    app = build_app(tmp_path, reader_returning(UNREACHABLE))
    read_now(app)
    app.handle_dashboard_action("log_clear_buffer")
    assert app.log_buffer.entries() == []
    assert app.new_log_errors == 0
    assert app.log_error is None


def test_no_log_control_falls_through_to_the_repair_ladder(tmp_path):
    """An id this method does not recognise reaches step_by_name and reports
    "Unknown step" -- a control that looks wired and does nothing useful. This is
    the second time that bug class has been caught here, so it gets a test.
    """
    from netdnsmonitor.dashboard import LOG_ACTIONS

    app = build_app(tmp_path)
    app.open_dashboard()
    output = []
    app._append_output = output.append
    for _title, action_id in LOG_ACTIONS:
        app.handle_dashboard_action(action_id)
    app.handle_dashboard_action("log_search")
    if app._log_thread is not None:
        app._log_thread.join(timeout=5)
    assert "Unknown step" not in "".join(output)
