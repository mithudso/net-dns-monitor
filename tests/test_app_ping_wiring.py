"""The 5-second heartbeat's wiring into the rumps shell.

`ping_job` is replaced in every test, so nothing here pings a real host. That
also covers the property that matters most for the suite as a whole: none of
this may start a thread or a subprocess from `__init__`, because ten other
tests construct NetDnsMonitorApp directly and rumps timers never fire without a
run loop.
"""

import threading
import time

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.ping_monitor import PingMonitor
from netdnsmonitor.status import PING_DOWN_TEXT

OK = {"ok": True, "rtt_ms": 61.4, "error": None}
FAIL = {"ok": False, "rtt_ms": None, "error": "no reply from 8.8.8.8"}


class FakeFlapGate:
    def __init__(self, state="healthy", consecutive_failures=0):
        self.state = state
        self.consecutive_failures = consecutive_failures


class FakeStateMachine:
    def __init__(self, flap_state="healthy", consecutive_failures=0):
        self.flap_gate = FakeFlapGate(flap_state, consecutive_failures)

    def tick(self):
        return None


def make_app(tmp_path, result=OK, counters=(0, 0)):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    app.ping_job = lambda: (result, counters)
    pin_threshold(app)
    return app


def pin_threshold(app, failure_threshold=1):
    """Make these tests independent of the shipped alert threshold.

    They are wiring tests -- "a failed ping reaches the title, the alert and the
    forensic log" -- and how many failed pings that policy requires is a separate
    decision, pinned by its own test in test_config.py. Without this, changing the
    shipped default from 1 to 2 broke eleven tests that were not about it.
    """
    app.ping_monitor = PingMonitor(
        failure_threshold=failure_threshold,
        loss_window=app.config["ping_loss_window"],
        alert_repeat_seconds=app.config["ping_alert_repeat_seconds"],
    )
    return app


def run_heartbeat(app, cycles=1):
    """One full cadence per cycle: the worker runs, then the drain folds the
    result in and repaints. The split is deliberate -- see ping_tick.

    The final fold is an explicit `_drain_ping_results()` rather than one more
    `ping_tick()`, because a tick also *spawns* a worker. Ending on a tick
    leaves an unjoined thread alive, and the next call's overlap guard then
    skips its own ping -- which silently made a test pass for the wrong reason.
    """
    for _ in range(cycles):
        app.ping_tick()
        app._ping_thread.join(timeout=5)
        assert not app._ping_thread.is_alive()
    app._drain_ping_results()


def test_constructing_the_app_starts_no_ping_thread(tmp_path):
    """The guard the rest of the suite depends on. Pinging from __init__ would
    fire a real subprocess in every test that builds an app.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app._ping_thread is None
    assert app.ping_stats["rtt_ms"] is None
    assert app.ping_stats["down"] is False


def test_the_heartbeat_defaults_to_pinging_8_8_8_8_every_five_seconds(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app.config["ping_host"] == "8.8.8.8"
    assert app.config["ping_interval_seconds"] == 5
    assert app.ping_timer.interval == 5


def test_a_successful_ping_puts_the_round_trip_time_in_the_title(tmp_path):
    app = make_app(tmp_path, result=OK)
    run_heartbeat(app)
    assert "61ms" in app.title
    assert app.ping_stats["down"] is False


def test_throughput_appears_in_the_title_once_two_samples_exist(tmp_path):
    """The first reading is a baseline with no rate; only the second yields one."""
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    counters = [(0, 0), (1_000_000, 500_000)]
    app.ping_job = lambda: (OK, counters.pop(0) if counters else (1_000_000, 500_000))

    run_heartbeat(app)
    assert "↓" not in app.title  # baseline only
    run_heartbeat(app)
    assert "↓" in app.title
    assert "↑" in app.title


def test_a_failed_ping_shows_no_reply_and_turns_the_indicator_red(tmp_path):
    app = make_app(tmp_path, result=FAIL)
    run_heartbeat(app)
    assert PING_DOWN_TEXT in app.title
    assert "\U0001f534" in app.title
    assert app.ping_stats["down"] is True


def test_a_failed_ping_fires_the_alert(tmp_path, monkeypatch):
    alerts = []
    monkeypatch.setattr(
        "netdnsmonitor.alert.network_failed",
        lambda host, error=None, **kwargs: alerts.append((host, error)),
    )
    app = make_app(tmp_path, result=FAIL)
    run_heartbeat(app)
    assert len(alerts) == 1
    assert alerts[0][0] == "8.8.8.8"
    assert "no reply" in alerts[0][1]


def test_a_continuing_outage_does_not_re_alert_every_cadence(tmp_path, monkeypatch):
    alerts = []
    monkeypatch.setattr(
        "netdnsmonitor.alert.network_failed", lambda host, error=None, **kwargs: alerts.append(host)
    )
    app = make_app(tmp_path, result=FAIL)
    run_heartbeat(app, cycles=4)
    assert len(alerts) == 1


def test_recovery_cancels_the_bounce(tmp_path, monkeypatch):
    recovered = []
    monkeypatch.setattr("netdnsmonitor.alert.network_failed", lambda *a, **k: None)
    monkeypatch.setattr(
        "netdnsmonitor.alert.network_recovered", lambda host, **kwargs: recovered.append(host)
    )
    result = {"current": FAIL}
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    app.ping_job = lambda: (result["current"], (0, 0))
    pin_threshold(app)

    run_heartbeat(app)
    result["current"] = OK
    run_heartbeat(app)

    assert recovered == ["8.8.8.8"]
    assert app.ping_stats["down"] is False
    assert "61ms" in app.title


def test_a_healthy_ping_never_reports_recovery(tmp_path, monkeypatch):
    """Firing "recovered" on every good tick would cancel the *next* outage's
    Dock bounce as soon as it started.
    """
    recovered = []
    monkeypatch.setattr(
        "netdnsmonitor.alert.network_recovered", lambda host, **kwargs: recovered.append(host)
    )
    app = make_app(tmp_path, result=OK)
    run_heartbeat(app, cycles=3)
    assert recovered == []


def test_the_ping_never_runs_on_the_run_loop(tmp_path):
    """A failed ping takes ~3 seconds to give up. Inline, that would freeze the
    UI and both other timers for most of every cycle throughout an outage.
    """

    def slow_job():
        time.sleep(10)
        return OK, (0, 0)

    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    app.ping_job = slow_job

    started = time.monotonic()
    app.ping_tick()
    assert time.monotonic() - started < 1.0

    # The incident tick still runs while the ping is in flight.
    app.tick()
    assert "healthy" in app.title.lower()


def test_an_overlapping_heartbeat_is_skipped_not_stacked(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()
    release = threading.Event()
    calls = []

    def blocking_job():
        calls.append(1)
        release.wait(timeout=5)
        return OK, (0, 0)

    app.ping_job = blocking_job

    app.ping_tick()
    first = app._ping_thread
    time.sleep(0.1)
    app.ping_tick()

    assert app._ping_thread is first
    release.set()
    first.join(timeout=5)
    assert len(calls) == 1


def test_a_finished_heartbeat_is_respawned_next_cadence(tmp_path):
    """Keying the guard on is-not-None instead of is_alive() would run exactly
    one ping for the whole process lifetime, and the suite would stay green.
    """
    app = make_app(tmp_path)
    calls = []
    app.ping_job = lambda: (calls.append(1), (OK, (0, 0)))[1]

    app.ping_tick()
    first = app._ping_thread
    first.join(timeout=5)
    app.ping_tick()
    second = app._ping_thread
    second.join(timeout=5)

    assert second is not first
    assert len(calls) == 2


def test_a_raising_ping_job_does_not_kill_the_heartbeat(tmp_path):
    """Without the guard in _run_ping, one unforeseen exception stops the
    heartbeat for the rest of the process's life while the menu bar keeps
    showing the last good reading -- a dead monitor that looks healthy.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine()

    def boom():
        raise RuntimeError("netstat vanished")

    app.ping_job = boom
    run_heartbeat(app)

    app.ping_job = lambda: (OK, (0, 0))
    run_heartbeat(app)
    assert "61ms" in app.title


def test_every_queued_result_is_recorded_so_a_failure_edge_cannot_be_missed(tmp_path, monkeypatch):
    """The worker and the drain are paced by separate clocks, so two results can
    land between two drains. Reading only the newest would drop the failure in
    the middle of ok -> FAIL -> ok, and with it the alert.
    """
    alerts = []
    monkeypatch.setattr(
        "netdnsmonitor.alert.network_failed", lambda host, error=None, **kwargs: alerts.append(host)
    )
    monkeypatch.setattr("netdnsmonitor.alert.network_recovered", lambda *a, **k: None)

    app = make_app(tmp_path)
    now = time.monotonic()
    app._ping_results.put((OK, (0, 0), now))
    app._ping_results.put((FAIL, (0, 0), now + 5))
    app._ping_results.put((OK, (0, 0), now + 10))

    app._drain_ping_results()

    assert alerts == ["8.8.8.8"]
    # The newest result is what gets drawn.
    assert "61ms" in app.title
    assert app.ping_stats["down"] is False


def test_the_title_is_not_repainted_when_no_result_arrived(tmp_path):
    """A tick that drains nothing must leave the display alone rather than
    repainting from a stale snapshot.
    """
    app = make_app(tmp_path)
    app.title = "sentinel"
    app._drain_ping_results()
    assert app.title == "sentinel"


def test_ping_failure_and_a_resolution_failure_can_both_show_at_once(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.alert.network_failed", lambda *a, **k: None)
    app = make_app(tmp_path, result=FAIL)
    app.resolution_job = lambda: [
        {"domain": "a.example", "resolved": False, "error": "timed out", "elapsed_seconds": 2.0}
    ]
    app.resolution_tick()
    app._resolution_thread.join(timeout=5)
    run_heartbeat(app)
    assert PING_DOWN_TEXT in app.title
    assert "1/1 resolution fails" in app.title
