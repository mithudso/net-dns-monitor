"""Regression test for the bug the advisor caught: driving the menu bar
title off the last *report* (which is None on the incident->healthy
recovery edge) left it stuck on red forever after the network recovered.
tick() must read the state machine's LIVE flap_gate.state every call.
"""

from types import SimpleNamespace

from netdnsmonitor.app import NetDnsMonitorApp


class FakeFlapGate:
    def __init__(self, state):
        self.state = state


class FakeStateMachine:
    def __init__(self, flap_state):
        self.flap_gate = FakeFlapGate(flap_state)

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
