"""Orchestrates the full incident lifecycle: monitor -> detect (via the
anti-flap gate) -> classify -> run the offline troubleshooting ladder ->
recheck -> escalate to Claude if still unresolved -> build the report.

The recheck step is what closes the loop: without re-probing after a repair
attempt, "repair" can't know whether it worked, and escalation timing would
be ambiguous. Escalation fires only after the ladder has been given its chance
and the recheck still shows the incident unresolved -- never on first
detection. An unclassified probe has no ladder to run, so that path escalates
with zero steps attempted; the report records the empty ladder_results rather
than implying a repair was tried.

All external effects (probing, running repair actions, calling the LLM) are
injected callables, so this orchestration logic is testable without any real
network, subprocess, or API calls.
"""

from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.classifier import Classification, classify
from netdnsmonitor.escalation import redact, should_escalate
from netdnsmonitor.flap_gate import FlapGate
from netdnsmonitor.ladder import DEFAULT_FAILOVER_CLASSIFICATIONS, ladder_for
from netdnsmonitor.report import build_report

ProbeResult = dict
Prober = Callable[[], ProbeResult]
# Takes (step) or (step, classification): the failover step needs to know what
# it is responding to, every other step ignores the second argument.
RepairExecutor = Callable[..., str]
Escalator = Callable[[dict], Optional[dict]]
LogWatcher = Callable[[], list]


class StateMachine:
    def __init__(
        self,
        prober: Prober,
        repair_executor: RepairExecutor,
        escalator: Escalator,
        log_watcher: Optional[LogWatcher] = None,
        failure_threshold: int = 2,
        success_threshold: int = 2,
        sensitive_strings: Optional[list[str]] = None,
        failover_classifications: frozenset = DEFAULT_FAILOVER_CLASSIFICATIONS,
    ):
        self.prober = prober
        self.repair_executor = repair_executor
        self.escalator = escalator
        self.log_watcher = log_watcher or (lambda: [])
        self.flap_gate = FlapGate(failure_threshold, success_threshold)
        self.sensitive_strings = sensitive_strings or []
        # The most recent probe, so fault localization can say what THIS machine
        # sees without re-probing. Kept here rather than recomputed by the caller
        # because a second probe seconds later can disagree with the one the gate
        # actually acted on, and then the verdict would explain a different event.
        self.last_probe: ProbeResult = {}
        self.failover_classifications = failover_classifications

    def tick(self) -> Optional[dict]:
        probe = self.prober()
        self.last_probe = probe
        classification = classify(probe.get("external_reachable"), probe.get("dns_ok"))
        # Not probed is not failed (non-negotiable 2). A probe that positively
        # confirmed one field and did not read the other is evidence of nothing,
        # so it must not move the gate in either direction:
        #   (True, None) / (None, True)    -> skip; the gate is left as it was
        #   (False, None) / (None, False)  -> failure; the False half is real
        #   (None, None)                   -> falls through as a failure: a
        #                                     prober that read neither field is
        #                                     broken, and that is worth escalating
        # Scoring the first row as a failure declared an incident on a healthy
        # network the moment `control_domain` was null with the shipped
        # `domains: []`, and the gate could never recover, because no tick ever
        # counted as a success.
        if classification == Classification.UNCLASSIFIED and any(
            probe.get(field) for field in ("external_reachable", "dns_ok")
        ):
            return None
        ok = classification == Classification.HEALTHY

        prev_state = self.flap_gate.state
        state = self.flap_gate.record(ok)
        if not (prev_state == "healthy" and state == "incident"):
            return None

        return self._run_incident_pipeline(classification, probe)

    def _run_incident_pipeline(self, classification: Classification, probe: ProbeResult) -> dict:
        started_at = datetime.now(timezone.utc)

        ladder_results = []
        repair_outcomes = []
        for step in ladder_for(classification, self.failover_classifications):
            outcome = self.repair_executor(step, classification.value)
            ladder_results.append(
                {
                    "name": step.name,
                    "kind": step.kind,
                    # Carried through so the report and the forensic log can say
                    # why each step ran, not just that it did.
                    "reason": step.reason,
                    "outcome": outcome,
                }
            )
            if step.kind == "repair":
                repair_outcomes.append(f"{step.name}: {outcome}")
        repair_outcome = "; ".join(repair_outcomes) if repair_outcomes else None

        recheck_probe = self.prober()
        recheck_classification = classify(
            recheck_probe.get("external_reachable"), recheck_probe.get("dns_ok")
        )
        # The same rule as tick(): a recheck that confirmed one field and did
        # not read the other is evidence of nothing. It can neither claim the
        # incident resolved (so the report carries recheck_ok=None, not True)
        # nor justify a paid escalation on a network that may be fine. A
        # recheck that read neither field still escalates -- that is a broken
        # prober, and the report records it as unresolved.
        recheck_inconclusive = recheck_classification == Classification.UNCLASSIFIED and any(
            recheck_probe.get(field) for field in ("external_reachable", "dns_ok")
        )
        recheck_ok: Optional[bool] = (
            None if recheck_inconclusive else recheck_classification == Classification.HEALTHY
        )

        escalation = None
        if not recheck_inconclusive and should_escalate(
            ladder_completed=True,
            repair_attempted_or_na=True,
            recheck_ok=bool(recheck_ok),
        ):
            log_excerpts = self.log_watcher()
            bundle = {
                "classification": classification.value,
                "probe_results": probe,
                "log_excerpts": log_excerpts,
                "ladder_results": ladder_results,
            }
            escalation = self.escalator(redact(bundle, self.sensitive_strings))
        else:
            log_excerpts = self.log_watcher()

        ended_at = datetime.now(timezone.utc)
        return build_report(
            started_at=started_at,
            ended_at=ended_at,
            classification=classification,
            probe_results=probe,
            log_excerpts=log_excerpts,
            ladder_results=ladder_results,
            repair_outcome=repair_outcome,
            recheck_ok=recheck_ok,
            escalation=escalation,
        )
