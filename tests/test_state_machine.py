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
    sm, prober, repair, escalate = make_sm(
        [{"external_reachable": True, "dns_ok": True}]
    )
    assert sm.tick() is None
    assert repair.executed_steps == []


def test_single_failure_below_threshold_produces_no_report():
    sm, prober, repair, escalate = make_sm(
        [{"external_reachable": True, "dns_ok": False}]
    )
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
