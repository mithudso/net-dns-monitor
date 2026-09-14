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

import threading
from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.classifier import Classification, classify
from netdnsmonitor.escalation import redact, should_escalate
from netdnsmonitor.flap_gate import FlapGate
from netdnsmonitor.ladder import DEFAULT_FAILOVER_CLASSIFICATIONS, LadderStep, ladder_for
from netdnsmonitor.report import build_report

ProbeResult = dict
Prober = Callable[[], ProbeResult]
# Takes (step) or (step, classification): the failover step needs to know what
# it is responding to, every other step ignores the second argument.
RepairExecutor = Callable[..., str]
Escalator = Callable[[dict], Optional[dict]]
LogWatcher = Callable[[], list]

# Caps for the escalation bundle only. The on-disk report keeps every raw line
# because it stays on this machine. The bundle leaves it, and a long lookback on
# a noisy machine returns thousands of lines.
MAX_OUTBOUND_LOG_LINES = 200
MAX_OUTBOUND_LOG_LINE_CHARS = 300


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
        # Held around the incident pipeline. A caller that runs repair steps
        # outside tick() (the app's manual diagnosis runs on a worker thread)
        # holds it too, so a manual repair or failover cannot interleave with the
        # ladder's. The cost: tick() waits until that caller releases it. An
        # RLock, so a step that takes the lock on the tick's own thread re-enters
        # instead of deadlocking.
        self.lock = threading.RLock()

    def tick(self) -> Optional[dict]:
        probe = self.prober()
        self.last_probe = probe
        classification = classify(probe.get("external_reachable"), probe.get("dns_ok"))
        ok = classification == Classification.HEALTHY

        prev_state = self.flap_gate.state
        state = self.flap_gate.record(ok)
        if not (prev_state == "healthy" and state == "incident"):
            return None

        with self.lock:
            return self._run_incident_pipeline(classification, probe)

    # The gate has already moved to "incident" when the pipeline starts, and it
    # reports only on that edge. So every injected call below fails as data: an
    # exception escaping here would lose the only report, and the only alert,
    # this incident will ever get. Exception messages are dropped in favour of
    # the class name, because they can carry command output or request URLs.

    def _run_step(self, step: LadderStep, classification: Classification) -> str:
        try:
            return self.repair_executor(step, classification.value)
        except Exception as exc:  # noqa: BLE001 - a raising step must not cost the report
            return f"failed: step raised {type(exc).__name__}"

    def _recheck(self) -> Classification:
        try:
            probe = self.prober()
            return classify(probe.get("external_reachable"), probe.get("dns_ok"))
        except Exception:  # noqa: BLE001 - a recheck that did not run proves nothing
            # UNCLASSIFIED, not HEALTHY: an unknown must never read as resolved.
            return Classification.UNCLASSIFIED

    def _read_log_excerpts(self) -> list:
        try:
            return list(self.log_watcher() or [])
        except Exception:  # noqa: BLE001 - missing evidence must not cost the report
            return []

    def _escalate(self, bundle: dict) -> Optional[dict]:
        try:
            return self.escalator(bundle)
        except Exception as exc:  # noqa: BLE001 - a failed API call must not cost the report
            return {"error": f"escalation raised {type(exc).__name__}"}

    def _outbound_bundle(
        self,
        classification: Classification,
        probe: ProbeResult,
        log_excerpts: list,
        ladder_results: list,
    ) -> dict:
        omitted = max(0, len(log_excerpts) - MAX_OUTBOUND_LOG_LINES)
        # Redact the values, never the four top-level keys. Those keys are this
        # code's schema, not evidence: redacting them let a sensitive string such
        # as "excerpt" rename "log_excerpts", and the lookup below then raised
        # after the gate had moved to incident. The escalator also picks its
        # model from the classification value. Keys nested inside the values are
        # still redacted, because domain_results is keyed by hostname.
        # Truncate after redacting. Cutting first can split a sensitive string at
        # the boundary into a fragment that no longer matches it, and the
        # fragment then leaves the machine unredacted.
        capped = [
            str(line)[:MAX_OUTBOUND_LOG_LINE_CHARS]
            for line in redact(log_excerpts[omitted:], self.sensitive_strings)
        ]
        if omitted:
            capped.insert(0, f"[{omitted} earlier log lines omitted]")
        return {
            "classification": classification.value,
            "probe_results": redact(probe, self.sensitive_strings),
            "log_excerpts": capped,
            "ladder_results": redact(ladder_results, self.sensitive_strings),
        }

    def _run_incident_pipeline(self, classification: Classification, probe: ProbeResult) -> dict:
        started_at = datetime.now(timezone.utc)

        ladder_results = []
        repair_outcomes = []
        for step in ladder_for(classification, self.failover_classifications):
            outcome = self._run_step(step, classification)
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

        recheck_ok = self._recheck() == Classification.HEALTHY

        log_excerpts = self._read_log_excerpts()
        escalation = None
        if should_escalate(
            ladder_completed=True,
            repair_attempted_or_na=True,
            recheck_ok=recheck_ok,
        ):
            escalation = self._escalate(
                self._outbound_bundle(classification, probe, log_excerpts, ladder_results)
            )

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
