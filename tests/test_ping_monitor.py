"""The alerting policy. This is where "if it fails a ping then alert" is
reconciled with a 5-second cadence -- see ping_monitor.py's docstring.
"""

from netdnsmonitor.ping_monitor import PingMonitor

OK = {"ok": True, "rtt_ms": 61.4, "error": None}
FAIL = {"ok": False, "rtt_ms": None, "error": "no reply from 8.8.8.8"}


def test_a_single_failed_ping_alerts_by_default():
    """The literal reading of the request, and the default."""
    monitor = PingMonitor()
    snapshot = monitor.record(FAIL, now=0.0)
    assert snapshot["alert"] is True
    assert snapshot["down"] is True


def test_a_successful_ping_never_alerts():
    monitor = PingMonitor()
    snapshot = monitor.record(OK, now=0.0)
    assert snapshot["alert"] is False
    assert snapshot["down"] is False
    assert snapshot["rtt_ms"] == 61.4


def test_a_continuing_outage_alerts_only_once():
    """Twelve bounces a minute for the length of an outage is the failure mode
    this exists to prevent. Removing the edge check makes every tick alert.
    """
    monitor = PingMonitor()
    assert monitor.record(FAIL, now=0.0)["alert"] is True
    alerts = [monitor.record(FAIL, now=t)["alert"] for t in (5.0, 10.0, 15.0, 300.0)]
    assert alerts == [False, False, False, False]


def test_a_second_outage_after_recovery_alerts_again():
    """Recovery has to re-arm the alert, or the app goes silent for every
    outage after the first one for the rest of the process's life.
    """
    monitor = PingMonitor()
    monitor.record(FAIL, now=0.0)
    monitor.record(OK, now=5.0)
    assert monitor.record(FAIL, now=10.0)["alert"] is True


def test_recovery_clears_the_down_flag_and_does_not_alert():
    monitor = PingMonitor()
    monitor.record(FAIL, now=0.0)
    snapshot = monitor.record(OK, now=5.0)
    assert snapshot["down"] is False
    assert snapshot["alert"] is False
    assert snapshot["consecutive_failures"] == 0


def test_threshold_of_two_ignores_a_single_dropped_packet():
    """The documented escape hatch for Wi-Fi packet loss: one lost echo request
    is not an outage, two in a row is.
    """
    monitor = PingMonitor(failure_threshold=2)
    first = monitor.record(FAIL, now=0.0)
    assert first["alert"] is False
    assert first["down"] is False
    second = monitor.record(FAIL, now=5.0)
    assert second["alert"] is True
    assert second["down"] is True


def test_threshold_of_two_is_reset_by_a_success_in_between():
    monitor = PingMonitor(failure_threshold=2)
    monitor.record(FAIL, now=0.0)
    monitor.record(OK, now=5.0)
    assert monitor.record(FAIL, now=10.0)["alert"] is False


def test_threshold_below_one_is_clamped_to_one():
    """A successful ping returns early from _should_alert regardless, so the
    clamp is about the value reported matching the value acted on: 0 behaves
    exactly like 1, and must say so.
    """
    monitor = PingMonitor(failure_threshold=0)
    assert monitor.failure_threshold == 1
    assert monitor.record(OK, now=0.0)["alert"] is False
    assert monitor.record(FAIL, now=5.0)["alert"] is True


def test_a_negative_repeat_interval_does_not_alert_on_every_failing_tick():
    """A negative value from YAML is truthy, and `now - last >= negative` is
    always true -- twelve bounces a minute, the failure mode edge-triggering
    exists to prevent.
    """
    monitor = PingMonitor(alert_repeat_seconds=-5)
    assert monitor.record(FAIL, now=0.0)["alert"] is True
    assert [monitor.record(FAIL, now=t)["alert"] for t in (5.0, 10.0)] == [False, False]


def test_repeat_interval_re_alerts_only_after_it_elapses():
    monitor = PingMonitor(alert_repeat_seconds=60)
    assert monitor.record(FAIL, now=0.0)["alert"] is True
    assert monitor.record(FAIL, now=30.0)["alert"] is False
    assert monitor.record(FAIL, now=60.0)["alert"] is True


def test_repeat_interval_measures_from_the_last_alert_not_the_outage_start():
    monitor = PingMonitor(alert_repeat_seconds=60)
    monitor.record(FAIL, now=0.0)
    monitor.record(FAIL, now=60.0)  # second alert
    assert monitor.record(FAIL, now=90.0)["alert"] is False
    assert monitor.record(FAIL, now=120.0)["alert"] is True


def test_repeat_of_zero_means_never_re_alert():
    monitor = PingMonitor(alert_repeat_seconds=0)
    monitor.record(FAIL, now=0.0)
    assert monitor.record(FAIL, now=100_000.0)["alert"] is False


def test_a_negative_repeat_interval_is_clamped_rather_than_alerting_every_tick():
    """`now - last >= -300` is true on every tick, so an unclamped negative
    setting turned one alert per outage into one alert per failing ping --
    exactly what the edge trigger exists to prevent.
    """
    monitor = PingMonitor(alert_repeat_seconds=-300)
    alerts = [monitor.record(FAIL, now=t)["alert"] for t in (0.0, 5.0, 10.0)]
    assert alerts == [True, False, False]


def test_a_missing_repeat_interval_means_never_re_alert():
    """A blank YAML value arrives as None; it has always meant "never"."""
    monitor = PingMonitor(alert_repeat_seconds=None)
    monitor.record(FAIL, now=0.0)
    assert monitor.record(FAIL, now=100_000.0)["alert"] is False


def test_failed_ping_reports_no_rtt_and_carries_the_error():
    monitor = PingMonitor()
    snapshot = monitor.record(FAIL, now=0.0)
    assert snapshot["rtt_ms"] is None
    assert "no reply" in snapshot["error"]


def test_rtt_is_dropped_even_if_a_failed_result_carries_one():
    """Defensive: a stale rtt rendered beside a failure reads as a working
    network.
    """
    monitor = PingMonitor()
    snapshot = monitor.record({"ok": False, "rtt_ms": 12.0, "error": "x"}, now=0.0)
    assert snapshot["rtt_ms"] is None


def test_loss_percentage_over_the_recent_window():
    monitor = PingMonitor(failure_threshold=1, loss_window=4)
    monitor.record(OK, now=0.0)
    monitor.record(OK, now=5.0)
    monitor.record(OK, now=10.0)
    snapshot = monitor.record(FAIL, now=15.0)
    assert snapshot["loss_pct"] == 25.0


def test_loss_window_evicts_old_results():
    """Without a bounded window the loss figure becomes an all-time average
    that barely moves -- useless as a "current" statistic.
    """
    monitor = PingMonitor(loss_window=2)
    monitor.record(FAIL, now=0.0)
    monitor.record(FAIL, now=5.0)
    assert monitor.record(OK, now=10.0)["loss_pct"] == 50.0
    assert monitor.record(OK, now=15.0)["loss_pct"] == 0.0


def test_loss_is_none_before_any_ping():
    assert PingMonitor().loss_pct is None


def test_loss_window_of_zero_is_clamped_rather_than_crashing():
    """deque(maxlen=0) silently discards everything, so loss_pct would divide
    by an empty window forever.
    """
    monitor = PingMonitor(loss_window=0)
    assert monitor.record(FAIL, now=0.0)["loss_pct"] == 100.0


def test_consecutive_failures_is_exposed_for_the_flaky_indicator():
    monitor = PingMonitor(failure_threshold=3)
    monitor.record(FAIL, now=0.0)
    assert monitor.record(FAIL, now=5.0)["consecutive_failures"] == 2


def test_a_result_missing_keys_is_treated_as_a_failure_not_a_crash():
    """ping.py always returns the full shape, but this must not be the thing
    that kills the heartbeat if that ever changes.
    """
    snapshot = PingMonitor().record({}, now=0.0)
    assert snapshot["down"] is True
    assert snapshot["rtt_ms"] is None
