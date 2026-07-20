"""Regression test for the bug the advisor caught: driving the menu bar
title off the last *report* (which is None on the incident->healthy
recovery edge) left it stuck on red forever after the network recovered.
tick() must read the state machine's LIVE flap_gate.state every call.
"""

from types import SimpleNamespace

from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.status import NETWORK_GLYPH


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


def test_initial_title_before_any_tick_already_shows_the_network_glyph(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    assert app.title.startswith(NETWORK_GLYPH)


def test_title_shows_flaky_on_a_single_failure_below_threshold(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy", consecutive_failures=1)
    app.tick()
    assert "flaky" in app.title.lower()


def test_title_appends_resolution_failure_count_after_resolution_tick(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    app.resolution_job = lambda: [
        {"domain": "a.example", "resolved": True, "error": None, "elapsed_seconds": 0.01},
        {"domain": "b.example", "resolved": False, "error": "timed out", "elapsed_seconds": 2.0},
    ]
    app.resolution_tick()
    assert "1/2" in app.title


def test_title_has_no_resolution_suffix_when_batch_all_resolved(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine("healthy")
    app.resolution_job = lambda: [
        {"domain": "a.example", "resolved": True, "error": None, "elapsed_seconds": 0.01},
    ]
    app.resolution_tick()
    assert "resolution fails" not in app.title
