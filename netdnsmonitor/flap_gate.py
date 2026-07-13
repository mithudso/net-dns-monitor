"""Debounce transient blips: only declare an incident after N consecutive
probe failures, and only clear it after N consecutive successes. A single
missed check (e.g. a laptop briefly asleep or roaming Wi-Fi) must not trigger
the full triage/repair/report pipeline.
"""


class FlapGate:
    def __init__(self, failure_threshold: int = 2, success_threshold: int = 2):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.state = "healthy"
        self._consecutive_failures = 0
        self._consecutive_successes = 0

    def record(self, ok: bool) -> str:
        if ok:
            self._consecutive_failures = 0
            self._consecutive_successes += 1
            if self.state == "incident" and self._consecutive_successes >= self.success_threshold:
                self.state = "healthy"
        else:
            self._consecutive_successes = 0
            self._consecutive_failures += 1
            if self.state == "healthy" and self._consecutive_failures >= self.failure_threshold:
                self.state = "incident"
        return self.state
