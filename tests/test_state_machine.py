import threading

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


def test_a_sensitive_domain_used_as_a_domain_results_key_never_reaches_the_escalator():
    """The real prober keys probe_results.domain_results by domain name, so a
    value-only redaction sent every configured hostname as a dict key.
    """
    failing = {
        "external_reachable": True,
        "dns_ok": False,
        "domain_results": {"mail.corp.local": {"resolved": False}},
    }
    escalator = FakeEscalator()
    sm = StateMachine(
        prober=FakeProber([failing, failing, failing]),
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
        sensitive_strings=["mail.corp.local"],
    )
    sm.tick()
    report = sm.tick()

    assert "mail.corp.local" not in str(escalator.received_bundles[0])
    # The on-disk report is not redacted (non-negotiable 6).
    assert "mail.corp.local" in report["probe_results"]["domain_results"]


# --- the anti-flap edge fires once per incident --------------------------------

FAILING = {"external_reachable": True, "dns_ok": False}
HEALTHY = {"external_reachable": True, "dns_ok": True}


def test_a_long_incident_produces_exactly_one_report_and_a_new_incident_another():
    """Every other test stops at the second tick, so a gate that fired on every
    failing tick past onset kept the suite green. That is one alert per poll
    interval for the whole outage (non-negotiable 8).
    """
    sm, prober, repair, escalate = make_sm(
        [
            FAILING,  # tick 1
            FAILING,  # tick 2: incident declared
            FAILING,  # recheck inside the pipeline
            FAILING,  # tick 3
            FAILING,  # tick 4
            FAILING,  # tick 5
            FAILING,  # tick 6
            HEALTHY,  # tick 7
            HEALTHY,  # tick 8: incident cleared
            FAILING,  # tick 9
            FAILING,  # tick 10: new incident declared
            FAILING,  # recheck
        ]
    )
    reports = [sm.tick() for _ in range(10)]

    fired_on = [n for n, report in enumerate(reports, start=1) if report is not None]
    assert fired_on == [2, 10]
    assert prober.calls == 12
    assert repair.executed_steps.count("flush_dns_cache") == 2


# --- a raising injected callable must not consume the edge ---------------------
#
# The gate moves to "incident" before the pipeline runs, so an exception inside
# the pipeline used to lose the only edge this incident will ever get: no report,
# no alert, and no second chance until the gate clears and fails again.


def test_a_raising_repair_step_is_recorded_as_failed_and_the_ladder_continues():
    attempted = []

    def repair_executor(step, classification=None):
        attempted.append(step.name)
        if step.name == "flush_dns_cache":
            raise RuntimeError("token=hunter2")
        return "done"

    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, HEALTHY]),
        repair_executor=repair_executor,
        escalator=FakeEscalator(),
    )
    sm.tick()
    report = sm.tick()

    assert report is not None
    outcomes = {step["name"]: step["outcome"] for step in report["ladder_results"]}
    assert outcomes["flush_dns_cache"] == "failed: step raised RuntimeError"
    assert "resolve_against_public_resolver" in attempted  # the step after it
    assert report["repair_outcome"].startswith("flush_dns_cache: failed:")
    assert "hunter2" not in str(report)


def test_a_raising_recheck_is_not_reported_as_resolved():
    probes = iter([FAILING, FAILING])
    escalator = FakeEscalator()

    def prober():
        try:
            return next(probes)
        except StopIteration:
            raise OSError("probe exploded") from None

    sm = StateMachine(
        prober=prober,
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
    )
    sm.tick()
    report = sm.tick()

    assert report is not None
    assert report["resolved"] is False
    assert len(escalator.received_bundles) == 1


def test_a_raising_log_watcher_still_produces_a_report_with_no_excerpts():
    def log_watcher():
        raise PermissionError("log show denied")

    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, FAILING]),
        repair_executor=FakeRepairExecutor(),
        escalator=FakeEscalator(),
        log_watcher=log_watcher,
    )
    sm.tick()
    report = sm.tick()

    assert report is not None
    assert report["log_excerpts"] == []


def test_a_raising_escalator_is_recorded_by_class_name_only():
    """The exception text from an API failure can carry request details, so only
    the class name goes into the report (non-negotiable 4).
    """

    def escalator(bundle):
        raise ConnectionError("POST https://api.example/v1?key=sk-secret failed")

    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, FAILING]),
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
    )
    sm.tick()
    report = sm.tick()

    assert report is not None
    assert report["escalation"] == {"error": "escalation raised ConnectionError"}
    assert "sk-secret" not in str(report)


# --- manual actions and the tick pipeline share one lock -----------------------


def test_the_incident_pipeline_waits_while_a_manual_action_holds_the_lock():
    """app.py runs manual diagnosis steps on a worker thread. Without a shared
    lock, a manual step and the tick's ladder could run repairs, or two
    failovers, at the same time.
    """
    sm, prober, repair, escalate = make_sm([FAILING, FAILING, FAILING])
    sm.tick()
    results = []
    worker = threading.Thread(target=lambda: results.append(sm.tick()), daemon=True)

    with sm.lock:
        worker.start()
        worker.join(timeout=0.3)
        assert worker.is_alive()
        assert repair.executed_steps == []

    worker.join(timeout=5)
    assert not worker.is_alive()
    assert results and results[0] is not None
    assert "flush_dns_cache" in repair.executed_steps


def test_a_step_that_takes_the_lock_on_the_tick_thread_does_not_deadlock():
    """An RLock, so a step that itself takes the lock (as a shared helper in
    app.py may) re-enters instead of hanging the tick forever.
    """
    holder = {}

    def repair_executor(step, classification=None):
        with holder["sm"].lock:
            return "done"

    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, HEALTHY]),
        repair_executor=repair_executor,
        escalator=FakeEscalator(),
    )
    holder["sm"] = sm
    results = []

    def run():
        sm.tick()
        results.append(sm.tick())

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert results and results[0] is not None


# --- outbound log excerpts are capped; the on-disk report is not ---------------


def test_log_excerpts_sent_to_the_escalator_are_capped_but_the_report_keeps_all():
    lines = [f"{i:05d} " + "x" * 1000 for i in range(5000)]
    escalator = FakeEscalator()
    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, FAILING]),
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
        log_watcher=lambda: lines,
    )
    sm.tick()
    report = sm.tick()

    sent = escalator.received_bundles[0]["log_excerpts"]
    assert len(sent) <= 201
    assert all(len(line) <= 300 for line in sent)
    assert "4800" in sent[0]  # says how many earlier lines were left out
    assert sent[1].startswith("04800 ")
    assert sent[-1].startswith("04999 ")  # the most recent lines are the ones kept
    assert len(report["log_excerpts"]) == 5000
    assert report["log_excerpts"][0] == lines[0]


def test_truncating_a_log_line_cannot_cut_a_sensitive_string_past_redaction():
    """Truncating before redacting would leave "mail.corp." at the 300-char
    boundary, which no longer matches the configured string.
    """
    escalator = FakeEscalator()
    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING, FAILING]),
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
        log_watcher=lambda: ["a" * 290 + "mail.corp.local is unreachable"],
        sensitive_strings=["mail.corp.local"],
    )
    sm.tick()
    sm.tick()

    sent = escalator.received_bundles[0]["log_excerpts"]
    assert "mail.corp" not in str(sent)
    assert all(len(line) <= 300 for line in sent)


def test_a_sensitive_string_matching_a_bundle_key_cannot_cost_the_report():
    """The four top-level bundle keys are code-owned schema, not evidence. When
    redaction ran over them, a configured "excerpt" renamed "log_excerpts", the
    pipeline's own lookup of that key raised KeyError after the gate had moved to
    incident, and that incident's only report and alert were lost.
    """
    escalator = FakeEscalator()
    sm = StateMachine(
        prober=FakeProber([FAILING, FAILING]),
        repair_executor=FakeRepairExecutor(),
        escalator=escalator,
        log_watcher=lambda: ["excerpt from a result line"],
        failure_threshold=1,
        sensitive_strings=["excerpt", "result", "class"],
    )

    report = sm.tick()

    assert report is not None
    sent = escalator.received_bundles[0]
    assert set(sent) == {"classification", "probe_results", "log_excerpts", "ladder_results"}
    assert all(value is not None for value in sent.values())
    # Left unredacted: the escalator picks its model from this value.
    assert sent["classification"] == "dns"
    # The evidence under the fixed keys is still redacted.
    assert sent["log_excerpts"] == ["[REDACTED] from a [REDACTED] line"]
    assert sent["ladder_results"]
