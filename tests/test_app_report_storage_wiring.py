"""What the incident tick does when the report cannot be written.

The report is the on-disk record; the notification and the forensic episode
are the other two outputs of the same incident. A `reports_dir` on a read-only
volume must cost the file, not the alert -- and it must be visible in `:status`
rather than looking like a quiet tick.
"""

from netdnsmonitor.app import NetDnsMonitorApp


class FakeFlapGate:
    def __init__(self, state):
        self.state = state
        self.consecutive_failures = 2


class FakeStateMachine:
    def __init__(self, report):
        self._report = report
        self.flap_gate = FakeFlapGate("incident")

    def tick(self):
        report, self._report = self._report, None
        return report


REPORT = {
    "classification": "dns",
    "started_at": "2026-08-05T12:00:00+00:00",
    "duration_seconds": 3.0,
    "resolved": False,
    "summary": "DNS-layer incident, unresolved.",
    "repair_outcome": None,
    "escalation": None,
    "probe_results": {"external_reachable": True, "dns_ok": False},
    "log_excerpts": [],
    "ladder_results": [],
    "recheck_ok": False,
}


def tick_and_deliver(app):
    app.tick()
    if app._notification_thread is not None:
        app._notification_thread.join(timeout=5)
        assert not app._notification_thread.is_alive(), "notification worker hung"


def test_a_report_that_cannot_be_saved_still_notifies_and_records_the_error(tmp_path, monkeypatch):
    def unwritable(report, directory):
        raise OSError("read-only volume")

    monkeypatch.setattr("netdnsmonitor.app.save_report", unwritable)
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.config.update(reports_dir=str(tmp_path / "reports"))
    sent = []
    app.notifier = lambda text: sent.append(text) or []
    app.state_machine = FakeStateMachine(REPORT)

    tick_and_deliver(app)

    assert len(sent) == 1
    assert "dns" in sent[0]
    assert "OSError" in app.last_tick_error
    assert "report not saved" in app.last_tick_error
    assert app.last_report_path is None
    assert app.last_classification == "dns"
    assert app.forensic.is_open


def test_a_saved_report_leaves_no_tick_error_behind(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "netdnsmonitor.app.save_report",
        lambda report, directory: {"markdown_path": str(tmp_path / "report.md")},
    )
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.notifier = lambda text: []
    app.state_machine = FakeStateMachine(REPORT)

    tick_and_deliver(app)

    assert app.last_tick_error is None
    assert app.last_report_path == str(tmp_path / "report.md")
