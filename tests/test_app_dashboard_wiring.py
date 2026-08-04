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
    monkeypatch.setattr("netdnsmonitor.dashboard.DashboardWindow.show", lambda self: None)
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
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert list(app.menu.keys())[0] == "Open dashboard"


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
