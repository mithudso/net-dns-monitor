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


def test_a_second_incident_can_be_declared_after_a_recovery():
    """Recovery has to re-arm the gate: the failure counter is reset by the
    successes, and the healthy->incident edge must fire again on the next
    streak, or every outage after the first goes unreported.
    """
    gate = FlapGate(failure_threshold=2, success_threshold=2)
    gate.record(ok=False)
    assert gate.record(ok=False) == "incident"
    gate.record(ok=True)
    assert gate.record(ok=True) == "healthy"
    assert gate.consecutive_failures == 0
    gate.record(ok=False)
    assert gate.record(ok=False) == "incident"


def test_failure_and_success_thresholds_are_not_interchangeable():
    """Every other test in this file uses 2/2, which makes the two thresholds
    indistinguishable: comparing consecutive_successes against
    failure_threshold (or the reverse) keeps the whole suite green. With a
    real config of failure_threshold=5 / success_threshold=1 that mix-up
    declares an incident on the *first* failure, defeating the debounce this
    module exists to provide. Asymmetric values pin each threshold to its own
    counter.
    """
    gate = FlapGate(failure_threshold=3, success_threshold=1)
    assert gate.record(ok=False) == "healthy"
    assert gate.record(ok=False) == "healthy"
    assert gate.record(ok=False) == "incident"
    assert gate.record(ok=True) == "healthy"


def test_default_thresholds_match_the_documented_config_defaults():
    """No test constructed a FlapGate without arguments, so the constructor
    defaults -- what StateMachine falls back to when a caller omits them --
    were unpinned. config.py and config.yaml both document 2 and 2.
    """
    gate = FlapGate()
    assert gate.failure_threshold == 2
    assert gate.success_threshold == 2
    gate.record(ok=False)
    assert gate.record(ok=False) == "incident"
