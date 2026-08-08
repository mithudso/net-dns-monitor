"""The dashboard window and the forensic recorder, as wired into the rumps shell.

`show()` is monkeypatched throughout: it calls `activateIgnoringOtherApps_`,
which would steal focus and flash a window across the screen on every test run.
Everything up to and including the call is still exercised.

Each test repoints `app.forensic` at tmp_path. conftest.py already redirects HOME
so the defaults cannot reach real user data, but pointing it explicitly is what
lets these assert against the documents on disk.
"""

import threading
import time

import pytest

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.forensic_log import DOWN, STEP, ForensicRecorder
from netdnsmonitor.ladder import LadderStep
from netdnsmonitor.ping_monitor import PingMonitor

OK = {"ok": True, "rtt_ms": 61.4, "error": None}
FAIL = {"ok": False, "rtt_ms": None, "error": "no reply from 8.8.8.8"}


class FakeFlapGate:
    def __init__(self, state="healthy", consecutive_failures=0):
        self.state = state
        self.consecutive_failures = consecutive_failures


class FakeStateMachine:
    def __init__(self, flap_state="healthy", consecutive_failures=0, report=None):
        self.flap_gate = FakeFlapGate(flap_state, consecutive_failures)
        self._report = report
        self.prober = lambda: {"external_reachable": True, "dns_ok": False}
        self.repair_executor = lambda step: f"ran {step.name}"

    def tick(self):
        report, self._report = self._report, None
        return report


@pytest.fixture(autouse=True)
def _no_real_window(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show",
        # Signature must match: show() takes `activate`, and the launch path
        # passes activate=False so it does not steal focus at login.
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
    # The fake reports below carry only the fields the forensic recorder reads.
    # Persisting them is a separate concern with its own tests in
    # test_report_storage.py, and requiring the full report schema here would
    # couple every forensic assertion to that renderer.
    monkeypatch.setattr(
        "netdnsmonitor.app.save_report",
        lambda report, directory: {"markdown_path": str(tmp_path / "report.md")},
    )


def make_app(tmp_path, state_machine=None, result=OK):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = state_machine or FakeStateMachine()
    app.ping_job = lambda: (result, (0, 0))
    app.forensic = ForensicRecorder(
        journal_path=str(tmp_path / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
    )
    # Pin the alert threshold rather than inheriting the shipped default -- see
    # the same note in test_app_ping_wiring.make_app. How many failed pings the
    # policy requires is decided and tested in test_config.py, not here.
    app.ping_monitor = PingMonitor(
        failure_threshold=1,
        loss_window=app.config["ping_loss_window"],
        alert_repeat_seconds=app.config["ping_alert_repeat_seconds"],
    )
    return app


def heartbeat(app, cycles=1):
    for _ in range(cycles):
        app.ping_tick()
        app._ping_thread.join(timeout=5)
    app._drain_ping_results()


def kinds(app):
    return [e["kind"] for e in (app.forensic.episode or {}).get("events", [])]


# --- the window --------------------------------------------------------------


def test_constructing_the_app_creates_no_window(tmp_path):
    """Eleven other tests build this class. A window in __init__ pops one each."""
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app._dashboard is None


def test_the_menu_offers_the_dashboard_first(tmp_path):
    """First *actionable* entry, not first entry outright.

    The reconcile put the failover indicator rows at the top of the menu. They
    carry no callback -- that is what greys them out -- so they read as a status
    header rather than as choices, and the dashboard is still the first thing
    anyone can click. Asserting position 0 would now pin the indicator's
    placement instead of the property this test exists for: that the dashboard
    leads, because the status item itself is easy to miss.

    Filtered by name rather than by `callback`: rumps binds the `@rumps.clicked`
    handlers when the app runs, so every string-declared item still reports
    `callback is None` at construction time and a callback-based filter would
    silently match only the explicitly-constructed failover items.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    entries = [
        key
        for key in app.menu.keys()
        if not key.startswith("SeparatorMenuItem") and not key.startswith("failover-row-")
    ]
    assert entries[0] == "Open dashboard"


def test_opening_the_dashboard_creates_and_populates_it(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()
    assert app._dashboard is not None
    assert "NETWORK RIGHT NOW" in app._dashboard.stats_view.string()


def test_reopening_reuses_the_same_window(tmp_path):
    """A second DashboardWindow would leak the first and re-register the ObjC
    button-target class, which raises.
    """
    app = make_app(tmp_path)
    app.open_dashboard()
    first = app._dashboard
    app.open_dashboard()
    assert app._dashboard is first


def test_the_window_shows_the_live_reading(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()
    heartbeat(app)
    app.ui_tick()
    assert "61 ms" in app._dashboard.stats_view.string()


def test_ui_tick_is_a_no_op_while_the_window_is_closed(tmp_path):
    """It runs every second for the life of the process, so it must cost nothing
    and must never raise when there is nothing to paint.
    """
    app = make_app(tmp_path)
    app.ui_tick()
    assert app._dashboard is None


def test_the_window_reports_a_failing_ping(tmp_path):
    app = make_app(tmp_path, result=FAIL)
    app.open_dashboard()
    heartbeat(app)
    app.ui_tick()
    text = app._dashboard.stats_view.string()
    assert "DOWN" in text
    assert "no reply" in text


# --- troubleshooting buttons -------------------------------------------------


def test_a_step_button_runs_the_step_and_reports_why_and_what_happened(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()
    app.handle_dashboard_action("flush_dns_cache")
    app._action_thread.join(timeout=5)
    app.ui_tick()

    output = app._dashboard.output_view.string()
    assert "flush_dns_cache" in output
    assert "why:" in output
    assert "ran flush_dns_cache" in output


def test_a_step_button_does_not_run_on_the_run_loop(tmp_path):
    """repair_executor allows 5s per step and a full ladder is four of them.
    Inline, a click would freeze the window and all four timers.
    """
    app = make_app(tmp_path)
    app.open_dashboard()
    release = threading.Event()
    app.state_machine.repair_executor = lambda step: (release.wait(timeout=5), "done")[1]

    started = time.monotonic()
    app.handle_dashboard_action("flush_dns_cache")
    assert time.monotonic() - started < 1.0
    release.set()
    app._action_thread.join(timeout=5)


def test_a_second_click_while_one_step_is_running_is_refused_not_stacked(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()
    release = threading.Event()
    calls = []
    app.state_machine.repair_executor = lambda step: (
        calls.append(step.name),
        release.wait(timeout=5),
        "done",
    )[2]

    app.handle_dashboard_action("flush_dns_cache")
    first = app._action_thread
    time.sleep(0.1)
    app.handle_dashboard_action("check_default_route")

    assert app._action_thread is first
    assert "ignored" in app._dashboard.output_view.string()
    release.set()
    first.join(timeout=5)
    assert calls == ["flush_dns_cache"]


def test_full_diagnosis_runs_the_ladder_for_the_current_classification(tmp_path):
    """The fake prober reports reachable-but-DNS-broken, so this must run the DNS
    ladder rather than the network one.
    """
    app = make_app(tmp_path)
    app.open_dashboard()
    app.handle_dashboard_action("full_diagnosis")
    app._action_thread.join(timeout=5)
    app.ui_tick()

    output = app._dashboard.output_view.string()
    assert "classified as: dns" in output
    assert "flush_dns_cache" in output
    assert "check_interface_state" not in output  # that is the network ladder


def test_an_unknown_action_reports_itself_instead_of_raising(tmp_path):
    """A stale button label must not raise inside a click handler, where the
    traceback is invisible to whoever clicked.
    """
    app = make_app(tmp_path)
    app.open_dashboard()
    app.handle_dashboard_action("no_such_step")
    app._action_thread.join(timeout=5)
    app.ui_tick()
    assert "Unknown step" in app._dashboard.output_view.string()


def test_a_raising_step_is_reported_not_fatal(tmp_path):
    app = make_app(tmp_path)
    app.open_dashboard()

    def boom(step):
        raise RuntimeError("scutil vanished")

    app.state_machine.repair_executor = boom
    app.handle_dashboard_action("flush_dns_cache")
    app._action_thread.join(timeout=5)
    app.ui_tick()
    assert "raised" in app._dashboard.output_view.string()


def test_manual_steps_are_recorded_in_the_forensic_log(tmp_path):
    """A step someone ran by hand belongs in the record as much as an automatic
    one -- otherwise the document shows an outage nobody appears to have touched.
    """
    app = make_app(tmp_path, result=FAIL)
    heartbeat(app)  # opens an episode
    app.handle_dashboard_action("flush_dns_cache")
    app._action_thread.join(timeout=5)
    app.ui_tick()

    events = app.forensic.episode["events"]
    manual = [e for e in events if e["detector"] == "manual"]
    assert len(manual) == 1
    assert manual[0]["detail"] == "flush_dns_cache"
    assert manual[0]["reason"]
    assert manual[0]["result"] == "ran flush_dns_cache"


def test_the_worker_thread_never_touches_the_recorder_directly(tmp_path):
    """The recorder's episode state is mutated by the main-thread ping drain, so
    a worker writing to it concurrently could interleave two episodes' events.
    The worker returns events and the drain records them.
    """
    app = make_app(tmp_path)
    app.handle_dashboard_action("flush_dns_cache")
    app._action_thread.join(timeout=5)
    # Nothing recorded yet: the worker has finished but no drain has run.
    assert not (tmp_path / "forensic.jsonl").exists()
    app.ui_tick()
    assert (tmp_path / "forensic.jsonl").exists()


# --- forensic episodes -------------------------------------------------------


def test_a_ping_outage_opens_and_closes_one_episode(tmp_path):
    app = make_app(tmp_path, result=FAIL)
    heartbeat(app)
    assert app.forensic.is_open

    app.ping_job = lambda: (OK, (0, 0))
    heartbeat(app)
    assert not app.forensic.is_open
    written = list((tmp_path / "episodes").glob("*-episode.md"))
    assert len(written) == 1
    body = written[0].read_text(encoding="utf-8")
    assert "No remedial step ran" in body


def test_a_declared_incident_records_every_step_with_its_reason(tmp_path):
    """The literal ask: steps taken, why, and the results."""
    report = {
        "classification": "dns",
        "probe_results": {"external_reachable": True, "dns_ok": False},
        "ladder_results": [
            {
                "name": "flush_dns_cache",
                "kind": "repair",
                "reason": "A cached negative answer keeps failing.",
                "outcome": "ok",
            }
        ],
        "recheck_ok": False,
        "escalation": {"analysis": "looks like a resolver problem"},
        "started_at": "2026-08-04T12:00:00+00:00",
    }
    app = make_app(tmp_path, state_machine=FakeStateMachine("incident", 2, report=report))
    app.tick()

    events = app.forensic.episode["events"]
    assert [e["kind"] for e in events] == [DOWN, STEP, "recheck", "escalation"]
    step = events[1]
    assert step["detail"] == "flush_dns_cache"
    assert "cached negative answer" in step["reason"]
    assert step["result"] == "ok"


def test_a_gate_incident_joins_an_episode_the_heartbeat_already_opened(tmp_path):
    """The usual real ordering: the 5s heartbeat notices first, the 30s gate
    declares its incident seconds later. One outage, one document.
    """
    app = make_app(tmp_path, result=FAIL)
    heartbeat(app)
    started = app.forensic.episode["started_at"]

    app.state_machine = FakeStateMachine(
        "incident",
        2,
        report={
            "classification": "network",
            "probe_results": {},
            "ladder_results": [],
            "recheck_ok": False,
            "escalation": None,
        },
    )
    app.tick()
    assert app.forensic.episode["started_at"] == started
    assert kinds(app).count(DOWN) == 2


def test_an_episode_does_not_close_while_the_gate_is_still_in_incident(tmp_path):
    """Closing on ping recovery alone would end the episode while the ladder is
    still working and drop everything after that point.
    """
    app = make_app(tmp_path, result=FAIL)
    app.state_machine = FakeStateMachine("incident", 2)
    heartbeat(app)
    app.ping_job = lambda: (OK, (0, 0))
    heartbeat(app)
    assert app.forensic.is_open


def test_a_gate_only_incident_closes_when_the_gate_clears(tmp_path):
    """A DNS incident can be declared while ICMP still answers, so the heartbeat
    never goes down and cannot be what closes the episode.
    """
    app = make_app(tmp_path)
    app.state_machine = FakeStateMachine(
        "incident",
        2,
        report={
            "classification": "dns",
            "probe_results": {},
            "ladder_results": [],
            "recheck_ok": True,
            "escalation": None,
        },
    )
    app.tick()
    assert app.forensic.is_open

    app.state_machine.flap_gate.state = "healthy"
    app.tick()
    assert not app.forensic.is_open
    assert list((tmp_path / "episodes").glob("*-episode.md"))


def test_gate_recovery_without_a_prior_incident_writes_nothing(tmp_path):
    """Every healthy 30s tick must not produce a document."""
    app = make_app(tmp_path)
    app.tick()
    app.tick()
    assert not (tmp_path / "episodes").exists()


def test_the_window_shows_the_open_episode(tmp_path):
    app = make_app(tmp_path, result=FAIL)
    app.open_dashboard()
    heartbeat(app)
    app.ui_tick()
    assert "open since" in app._dashboard.stats_view.string()


def test_step_reasons_come_from_the_ladder_definition_not_the_dashboard(tmp_path):
    """The button only knows a step name; the reason has to come from ladder.py so
    the manual and automatic paths cannot disagree about why a step exists.
    """
    from netdnsmonitor.ladder import step_by_name

    step = step_by_name("flush_dns_cache")
    assert isinstance(step, LadderStep)
    assert step.reason
    app = make_app(tmp_path)
    app.open_dashboard()
    app.handle_dashboard_action("flush_dns_cache")
    app._action_thread.join(timeout=5)
    app.ui_tick()
    assert step.reason in app._dashboard.output_view.string()


# --- opening the window without the status item -------------------------------


def test_the_launch_tick_opens_the_window_without_stealing_focus(tmp_path):
    """This runs from a launchd agent at login. Ordering the window front is
    wanted; yanking focus away from whatever someone is doing, every login, is
    not -- so the launch path must pass activate=False.
    """
    calls = []
    app = make_app(tmp_path)
    app._dashboard = None
    import netdnsmonitor.dashboard as dashboard_module

    original = dashboard_module.DashboardWindow.show
    dashboard_module.DashboardWindow.show = lambda self, activate=True: calls.append(activate)
    try:
        app.launch_tick()
    finally:
        dashboard_module.DashboardWindow.show = original

    assert calls == [False]
    assert app._dashboard is not None


def test_the_launch_tick_runs_once(tmp_path):
    """It installs a menu and a notification observer; doing that on a repeating
    timer would stack duplicates for the life of the process.
    """
    app = make_app(tmp_path)
    stopped = []
    app.launch_timer.stop = lambda: stopped.append(1)
    app.launch_tick()
    assert stopped == [1]


def test_launch_can_be_configured_not_to_open_the_window(tmp_path):
    app = make_app(
        tmp_path,
    )
    app.config["open_dashboard_at_launch"] = False
    app.launch_tick()
    assert app._dashboard is None


def test_activation_opens_the_window_and_does_activate(tmp_path):
    """The Dock-click path. macOS asks the delegate via
    applicationShouldHandleReopen:, which rumps does not implement, so a Dock
    click on an app owning no windows used to activate it and do nothing else.
    """
    calls = []
    app = make_app(tmp_path)
    import netdnsmonitor.dashboard as dashboard_module

    original = dashboard_module.DashboardWindow.show
    dashboard_module.DashboardWindow.show = lambda self, activate=True: calls.append(activate)
    try:
        app._on_app_activated(None)
    finally:
        dashboard_module.DashboardWindow.show = original

    assert calls == [True]


def test_activation_is_not_reentrant(tmp_path):
    """show() activates the app, which can re-post the notification. Without the
    guard that recurses.
    """
    app = make_app(tmp_path)
    seen = []

    def reentrant(self, activate=True):
        seen.append(activate)
        app._on_app_activated(None)  # what the re-posted notification would do

    import netdnsmonitor.dashboard as dashboard_module

    original = dashboard_module.DashboardWindow.show
    dashboard_module.DashboardWindow.show = reentrant
    try:
        app._on_app_activated(None)
    finally:
        dashboard_module.DashboardWindow.show = original

    assert len(seen) == 1


def test_a_raising_open_releases_the_reentrancy_guard(tmp_path):
    """A guard left stuck on would silently disable the Dock click for the rest
    of the process's life -- the same shape as a bug that already bit this file,
    which is why it is released in a finally.
    """
    app = make_app(tmp_path)
    import netdnsmonitor.dashboard as dashboard_module

    original = dashboard_module.DashboardWindow.show

    def boom(self, activate=True):
        raise RuntimeError("AppKit said no")

    dashboard_module.DashboardWindow.show = boom
    try:
        app._on_app_activated(None)
        assert app._opening_dashboard is False
        calls = []
        dashboard_module.DashboardWindow.show = lambda self, activate=True: calls.append(activate)
        app._on_app_activated(None)
        assert calls == [True]
    finally:
        dashboard_module.DashboardWindow.show = original


def test_the_application_menu_is_populated_and_wired(tmp_path):
    """rumps never populates the application menu, so clicking "Net-DNS-Monitor"
    at the top-left did nothing at all -- the menu genuinely had no items.
    """
    import AppKit

    from netdnsmonitor.dashboard import install_main_menu

    dispatched = []
    target = install_main_menu(dispatched.append)
    main_menu = AppKit.NSApplication.sharedApplication().mainMenu()
    assert main_menu is not None

    app_menu = main_menu.itemAtIndex_(0).submenu()
    titles = [app_menu.itemAtIndex_(i).title() for i in range(app_menu.numberOfItems())]
    assert "Open Dashboard" in titles
    assert any("Quit" in t for t in titles)

    item = app_menu.itemAtIndex_(0)
    assert item.target() is not None
    assert item.action() == "invoke:"
    target.invoke_(item)
    assert dispatched == ["open_dashboard"]


def test_the_application_menu_item_opens_the_dashboard(tmp_path):
    """The id the menu dispatches has to be one handle_dashboard_action knows,
    or the menu would look wired and do nothing.
    """
    app = make_app(tmp_path)
    app.handle_dashboard_action("open_dashboard")
    assert app._dashboard is not None


# --- Dock tile throttling (deep-optimizer finding) --------------------------


def make_dock_recorder(app, monkeypatch):
    calls = []
    monkeypatch.setattr("netdnsmonitor.app.set_dock_icon", lambda *a, **k: calls.append(a))
    return calls


def test_the_dock_tile_is_not_repainted_on_every_heartbeat(tmp_path, monkeypatch):
    """setApplicationIconImage_ is synchronous and measured at ~2 seconds per call,
    on the main thread. Repainting it every 5-second heartbeat -- which is what the
    round-trip number changing means -- blocked the run loop for a large fraction
    of every cycle and starved the other three timers.
    """
    app = make_app(tmp_path)
    calls = make_dock_recorder(app, monkeypatch)

    for rtt in (61.0, 62.0, 63.0, 64.0):
        app.ping_stats = dict(app.ping_stats, rtt_ms=rtt, down=False)
        app._refresh_title()

    assert len(calls) <= 1, f"the number alone should not repaint the tile: {calls}"


def test_a_status_change_repaints_the_dock_tile_immediately(tmp_path, monkeypatch):
    """The throttle must not delay the thing that matters. Green to red is urgent
    and rare; the number changing is neither.
    """
    app = make_app(tmp_path)
    calls = make_dock_recorder(app, monkeypatch)

    app.ping_stats = dict(app.ping_stats, rtt_ms=61.0, down=False)
    app._refresh_title()
    before = len(calls)

    app.ping_stats = dict(app.ping_stats, rtt_ms=None, down=True)
    app._refresh_title()

    assert len(calls) > before
    assert calls[-1][0] == "incident"
