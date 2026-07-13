"""Orchestrates the full incident lifecycle: monitor -> detect (via the
anti-flap gate) -> classify -> run the offline troubleshooting ladder ->
recheck -> escalate to Claude if still unresolved -> build the report.

The recheck step is what closes the loop: without re-probing after a repair
attempt, "repair" can't know whether it worked, and escalation timing would
be ambiguous. Escalation fires only after the ladder has run and the recheck
still shows the incident unresolved -- never on first detection.

All external effects (probing, running repair actions, calling the LLM) are
injected callables, so this orchestration logic is testable without any real
network, subprocess, or API calls.
"""

from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.classifier import Classification, classify
from netdnsmonitor.escalation import redact, should_escalate
from netdnsmonitor.flap_gate import FlapGate
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.report import build_report

ProbeResult = dict
Prober = Callable[[], ProbeResult]
RepairExecutor = Callable[[object], str]
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
    ):
        self.prober = prober
        self.repair_executor = repair_executor
        self.escalator = escalator
        self.log_watcher = log_watcher or (lambda: [])
        self.flap_gate = FlapGate(failure_threshold, success_threshold)
        self.sensitive_strings = sensitive_strings or []

    def tick(self) -> Optional[dict]:
        probe = self.prober()
        classification = classify(
            probe.get("external_reachable"), probe.get("dns_ok")
        )
        ok = classification == Classification.HEALTHY

        prev_state = self.flap_gate.state
        state = self.flap_gate.record(ok)
        if not (prev_state == "healthy" and state == "incident"):
            return None

        return self._run_incident_pipeline(classification, probe)

    def _run_incident_pipeline(
        self, classification: Classification, probe: ProbeResult
    ) -> dict:
        started_at = datetime.now(timezone.utc)

        ladder_results = []
        repair_outcomes = []
        for step in ladder_for(classification):
            outcome = self.repair_executor(step)
            ladder_results.append(
                {"name": step.name, "kind": step.kind, "outcome": outcome}
            )
            if step.kind == "repair":
                repair_outcomes.append(f"{step.name}: {outcome}")
        repair_outcome = "; ".join(repair_outcomes) if repair_outcomes else None

        recheck_probe = self.prober()
        recheck_classification = classify(
            recheck_probe.get("external_reachable"), recheck_probe.get("dns_ok")
        )
        recheck_ok = recheck_classification == Classification.HEALTHY

        escalation = None
        if should_escalate(
            ladder_completed=True,
            repair_attempted_or_na=True,
            recheck_ok=recheck_ok,
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
