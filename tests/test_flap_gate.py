from netdnsmonitor.flap_gate import FlapGate


def test_starts_healthy():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    assert gate.state == "healthy"


def test_single_failure_does_not_declare_incident():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    assert gate.record(ok=False) == "healthy"


def test_second_consecutive_failure_declares_incident():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    gate.record(ok=False)
    assert gate.record(ok=False) == "incident"


def test_a_success_between_failures_resets_the_failure_streak():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    gate.record(ok=False)
    gate.record(ok=True)
    assert gate.record(ok=False) == "healthy"


def test_single_success_after_incident_does_not_resolve_it():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    gate.record(ok=False)
    gate.record(ok=False)
    assert gate.record(ok=True) == "incident"


def test_reaching_success_threshold_resolves_the_incident():
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    gate.record(ok=False)
    gate.record(ok=False)
    gate.record(ok=True)
    assert gate.record(ok=True) == "healthy"
