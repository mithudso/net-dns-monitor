from netdnsmonitor.state_machine import StateMachine


class FakeProber:
    def __init__(self, results):
        self._results = list(results)
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self._results:
            return self._results.pop(0)
        return {"external_reachable": True, "dns_ok": True}


class FakeRepairExecutor:
    def __init__(self):
        self.executed_steps = []
        self.classifications = []

    def __call__(self, step, classification=None):
        self.executed_steps.append(step.name)
        self.classifications.append(classification)
        return f"executed {step.name}"


class FakeEscalator:
    def __init__(self, response=None):
        self.response = response or {"analysis": "fake llm response"}
        self.received_bundles = []

    def __call__(self, redacted_bundle):
        self.received_bundles.append(redacted_bundle)
        return self.response


def make_sm(results, escalator=None):
    prober = FakeProber(results)
    repair = FakeRepairExecutor()
    escalate = escalator or FakeEscalator()
    sm = StateMachine(
        prober=prober,
        repair_executor=repair,
        escalator=escalate,
        failure_threshold=2,
        success_threshold=2,
    )
    return sm, prober, repair, escalate


def test_healthy_probe_produces_no_report():
    sm, prober, repair, escalate = make_sm([{"external_reachable": True, "dns_ok": True}])
    assert sm.tick() is None
    assert repair.executed_steps == []


def test_single_failure_below_threshold_produces_no_report():
    sm, prober, repair, escalate = make_sm([{"external_reachable": True, "dns_ok": False}])
    assert sm.tick() is None
    assert repair.executed_steps == []


def test_second_consecutive_failure_runs_ladder_and_reports_resolved():
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": True, "dns_ok": False},  # tick 1: below threshold
            {"external_reachable": True, "dns_ok": False},  # tick 2: declares incident
            {"external_reachable": True, "dns_ok": True},  # recheck: resolved
        ]
    )
    assert sm.tick() is None
    report = sm.tick()
    assert report is not None
    assert report["classification"] == "dns"
    assert report["resolved"] is True
    assert "flush_dns_cache" in repair.executed_steps
    assert escalate.received_bundles == []


def test_incident_still_failing_after_repair_escalates():
    escalator = FakeEscalator()
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": True, "dns_ok": False},
            {"external_reachable": True, "dns_ok": False},
            {"external_reachable": True, "dns_ok": False},  # recheck: still broken
        ],
        escalator=escalator,
    )
    sm.tick()
    report = sm.tick()
    assert report["resolved"] is False
    assert report["escalation"] == {"analysis": "fake llm response"}
    assert len(escalate.received_bundles) == 1


def test_unclassified_probe_result_escalates_without_a_ladder():
    escalator = FakeEscalator()
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": None, "dns_ok": None},
            {"external_reachable": None, "dns_ok": None},
            {"external_reachable": None, "dns_ok": None},  # recheck: still unknown
        ],
        escalator=escalator,
    )
    sm.tick()
    report = sm.tick()
    assert report["classification"] == "unclassified"
    assert repair.executed_steps == []
    assert report["escalation"] == {"analysis": "fake llm response"}


def test_a_half_probed_healthy_reading_is_not_counted_as_a_failure():
    """Not probed is not failed. With `control_domain: null` and the shipped
    `domains: []` the prober returns dns_ok=None on every tick while the
    network is reachable; scoring that UNCLASSIFIED reading as a failure
    declared an incident on a healthy network, ran an empty ladder, and
    escalated -- and the gate could never recover because no tick ever
    counted as a success.
    """
    sm, prober, repair, escalate = make_sm([{"external_reachable": True, "dns_ok": None}] * 4)
    assert [sm.tick() for _ in range(4)] == [None, None, None, None]
    assert sm.flap_gate.state == "healthy"
    assert repair.executed_steps == []
    assert escalate.received_bundles == []


def test_a_half_probed_failing_reading_still_counts_as_a_failure():
    """The other half of the truth table: a field that positively read False
    is evidence of a fault even when the other field was not probed.
    """
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": False, "dns_ok": None},
            {"external_reachable": False, "dns_ok": None},
            {"external_reachable": False, "dns_ok": None},
        ]
    )
    sm.tick()
    assert sm.tick() is not None
    assert sm.flap_gate.state == "incident"


def test_a_half_probed_healthy_recheck_does_not_escalate():
    """The same rule on the recheck: a (True, None) reading after the ladder
    is evidence of nothing, so it can neither claim the incident resolved nor
    justify a paid escalation. A (None, None) recheck still escalates -- see
    the test above.
    """
    escalator = FakeEscalator()
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": True, "dns_ok": False},
            {"external_reachable": True, "dns_ok": False},
            {"external_reachable": True, "dns_ok": None},  # recheck: half probed
        ],
        escalator=escalator,
    )
    sm.tick()
    report = sm.tick()
    assert report is not None
    assert report["escalation"] is None
    assert escalate.received_bundles == []
    assert report["recheck_ok"] is None
    assert report["resolved"] is False


def test_redacted_bundle_sent_to_escalator_strips_sensitive_strings():
    escalator = FakeEscalator()
    sm, prober, repair, escalate = make_sm(
        [
            {"external_reachable": True, "dns_ok": False, "note": "mail.corp.local down"},
            {"external_reachable": True, "dns_ok": False, "note": "mail.corp.local down"},
            {"external_reachable": True, "dns_ok": False, "note": "mail.corp.local down"},
        ],
        escalator=escalator,
    )
    sm.sensitive_strings = ["mail.corp.local"]
    sm.tick()
    sm.tick()
    sent = escalate.received_bundles[0]
    assert "mail.corp.local" not in str(sent)


def test_redaction_covers_the_log_and_ladder_fields_that_carry_real_hostnames():
    """Redaction is the last thing standing between this machine's internal
    names and an outbound API call, and the test above could not detect its
    removal.

    It asserts on a `note` key, but the real prober returns only
    external_reachable / internal_reachable / dns_ok -- all bool or None -- so
    probe_results cannot carry a hostname in production. The two bundle fields
    that can are log_excerpts (raw mDNSResponder lines) and ladder_results
    (raw `scutil --dns` and /etc/resolver output), and neither was covered.
    Three separate mutations kept the whole suite green: re-assigning
    log_excerpts raw after redact(), the same for ladder_results, and turning
    `sensitive_strings or []` into a hardcoded `[]` -- i.e. disabling redaction
    globally in production.

    This also goes through the constructor, which is the path app.py actually
    wires; the test above assigns sm.sensitive_strings afterwards and so proves
    nothing about how the app builds it.
    """
    escalator = FakeEscalator()
    failing = {"external_reachable": True, "internal_reachable": None, "dns_ok": False}
    sm = StateMachine(
        prober=FakeProber([failing, failing, failing]),
        repair_executor=lambda step, classification=None: (
            "/etc/resolver overrides present for: mail.corp.local"
        ),
        escalator=escalator,
        log_watcher=lambda: ["mDNSResponder: no answer for mail.corp.local"],
        failure_threshold=2,
        success_threshold=2,
        sensitive_strings=["mail.corp.local"],
    )

    sm.tick()
    sm.tick()

    sent = escalator.received_bundles[0]
    assert "mail.corp.local" not in str(sent["log_excerpts"])
    assert "mail.corp.local" not in str(sent["ladder_results"])
    assert "mail.corp.local" not in str(sent)
