"""Debounce transient blips: only declare an incident after N consecutive
probe failures, and only clear it after N consecutive successes. A single
missed check (e.g. a laptop briefly asleep or roaming Wi-Fi) must not trigger
the full triage/repair/report pipeline.

`consecutive_failures` is public (not just internal debounce state) because
the menu bar title uses it as an early-warning heuristic: a probe has
started failing but hasn't yet crossed failure_threshold, so it's worth
showing the user a "flaky" indicator before a full incident is declared.
"""


class FlapGate:
    def __init__(self, failure_threshold: int = 2, success_threshold: int = 2):
        # Coerced here because an uncoerced "3" from YAML does not fail until
        # `int >= str` on the first failing tick, inside the tick guard, so no
        # incident is ever declared and nothing says why. A None still raises,
        # but at construction. The clamp changes nothing observable: the counter
        # is incremented before the comparison, so 0 already behaved like 1.
        self.failure_threshold = max(1, int(failure_threshold))
        self.success_threshold = max(1, int(success_threshold))
        self.state = "healthy"
        self.consecutive_failures = 0
        self.consecutive_successes = 0

    def record(self, ok: bool) -> str:
        if ok:
            self.consecutive_failures = 0
            self.consecutive_successes += 1
            if self.state == "incident" and self.consecutive_successes >= self.success_threshold:
                self.state = "healthy"
        else:
            self.consecutive_successes = 0
            self.consecutive_failures += 1
            if self.state == "healthy" and self.consecutive_failures >= self.failure_threshold:
                self.state = "incident"
        return self.state
