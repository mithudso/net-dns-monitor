"""Regression test for the bug the advisor caught: driving the menu bar
title off the last *report* (which is None on the incident->healthy
recovery edge) left it stuck on red forever after the network recovered.
tick() must read the state machine's LIVE flap_gate.state every call.
"""

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.status import STATS_UNKNOWN


class FakeFlapGate:
    def __init__(self, state, consecutive_failures=0):
        self.state = state
        self.consecutive_failures = consecutive_failures


class FakeStateMachine:
    def __init__(self, flap_state, consecutive_failures=0):
        self.flap_gate = FakeFlapGate(flap_state, consecutive_failures)

    def tick(self):
        return None  # exactly what a report-less recovery tick returns


def test_title_reflects_live_recovery_even_with_no_report(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.last_classification = "dns"

    app.state_machine = FakeStateMachine("incident")
    app.tick()
    assert "issue" in app.title.lower()

    app.state_machine = FakeStateMachine("healthy")
    app.tick()
    assert "healthy" in app.title.lower()
    assert "issue" not in app.title.lower()


def test_initial_title_before_any_tick_already_shows_a_stats_placeholder(tmp_path):
    """Regression on "menu bar showed no icon at all until the first tick"
    (commit be16640), now pinned against the stats segment that replaced the
    signal-bars glyph. The first ping is a cadence away, so this covers the
    window where there is nothing to report yet.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app.title.startswith(STATS_UNKNOWN)


def test_title_shows_flaky_on_a_single_failure_below_threshold(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy", consecutive_failures=1)
    app.tick()
    assert "flaky" in app.title.lower()


def _run_resolution_to_completion(app):
    """resolution_tick hands the batch to a worker thread and returns, so the
    title cannot be asserted until that thread finishes and a main-thread tick
    repaints. That split is deliberate -- see NetDnsMonitorApp.resolution_tick.
    """
    app.resolution_tick()
    app._resolution_thread.join(timeout=5)
    assert not app._resolution_thread.is_alive()
    app.tick()


def test_finished_resolution_thread_is_respawned_next_cycle(tmp_path):
    """The overlap guard keys on `is_alive()`, not on is-not-None: a FINISHED
    thread must be replaced so a batch runs on every cadence. Weakening the
    guard to `if self._resolution_thread is not None: return` runs exactly one
    batch for the whole process lifetime and leaves the rest of the suite
    green -- the cadence would silently stop being a cadence.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    calls = []
    app.resolution_job = lambda: calls.append(1) or []

    app.resolution_tick()
    first_thread = app._resolution_thread
    first_thread.join(timeout=5)

    app.resolution_tick()  # prior thread has finished -> a new one must start
    second_thread = app._resolution_thread
    second_thread.join(timeout=5)

    assert second_thread is not first_thread
    assert len(calls) == 2


def test_a_raising_resolution_job_does_not_kill_the_worker_silently(tmp_path):
    """Without the guard in _run_resolution, a job that raises every cycle
    leaves last_resolution_findings at its initial [] forever, so the title
    shows no resolution suffix at all -- indistinguishable from "everything
    resolved fine" while the monitor is dead.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")

    def boom():
        raise RuntimeError("resolution log is unwritable")

    app.resolution_job = boom

    app.resolution_tick()
    app._resolution_thread.join(timeout=5)
    assert not app._resolution_thread.is_alive()
    # The title cannot show it, so `:status` has to. Class name only: an
    # exception message can carry a path or a URL.
    status = app.status_snapshot()
    assert "resolution batch failed: RuntimeError" in status
    assert "unwritable" not in status

    # The next cycle still runs rather than the app wedging.
    app.resolution_job = lambda: []
    app.resolution_tick()
    app._resolution_thread.join(timeout=5)
    app.tick()
    assert "healthy" in app.title.lower()


def test_title_appends_resolution_failure_count_after_resolution_tick(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    app.resolution_job = lambda: [
        {"domain": "a.example", "resolved": True, "error": None, "elapsed_seconds": 0.01},
        {"domain": "b.example", "resolved": False, "error": "timed out", "elapsed_seconds": 2.0},
    ]
    _run_resolution_to_completion(app)
    assert "1/2" in app.title


def test_title_has_no_resolution_suffix_when_batch_all_resolved(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    app.resolution_job = lambda: [
        {"domain": "a.example", "resolved": True, "error": None, "elapsed_seconds": 0.01},
    ]
    _run_resolution_to_completion(app)
    assert "resolution fails" not in app.title


def test_resolution_tick_does_not_block_the_run_loop(tmp_path):
    """The incident tick is the app's primary job and shares the run loop with
    resolution_tick. A slow batch must not hold it up.
    """
    import threading
    import time

    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")

    release = threading.Event()

    def slow_job():
        assert release.wait(timeout=5)
        return []

    app.resolution_job = slow_job

    try:
        started = time.monotonic()
        app.resolution_tick()
        assert time.monotonic() - started < 1.0

        # The incident tick still runs while the batch is in flight.
        app.tick()
        assert "healthy" in app.title.lower()
    finally:
        release.set()
        if app._resolution_thread is not None:
            app._resolution_thread.join(timeout=5)
            assert not app._resolution_thread.is_alive()


def test_overlapping_resolution_cycle_is_skipped_not_stacked(tmp_path):
    """The stall list only grows, so a batch can outlast its own cadence.
    Starting a second thread on top of a running one would compound the load.
    """
    import threading
    import time

    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    release = threading.Event()
    calls = []

    def blocking_job():
        calls.append(1)
        release.wait(timeout=5)
        return []

    app.resolution_job = blocking_job

    app.resolution_tick()
    first_thread = app._resolution_thread
    time.sleep(0.1)
    app.resolution_tick()  # should be a no-op while the first is alive

    assert app._resolution_thread is first_thread
    release.set()
    first_thread.join(timeout=5)
    assert len(calls) == 1
