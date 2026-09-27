"""Decides what a stream of ping results means: is the network down, what is
the recent loss rate, and should an alert fire right now.

Pure state, no I/O and no AppKit, so the alerting policy is testable without a
run loop -- the same split status.py has from app.py. ping.py performs the
pings; alert.py raises the alert; this decides.

Why the alert is edge-triggered
-------------------------------
"If it fails a ping, alert" taken literally at a 5-second cadence means twelve
Dock bounces and twelve notifications per minute for as long as the network is
down, which is when the user can least do anything about it. So the alert fires
on the transition into failure and then stays quiet. One outage, one alert.
Recovery re-arms it, so a second outage alerts again.

`failure_threshold` defaults to 1 *here*, which is the literal reading of the
request: a single dropped echo request alerts. The shipped config default is 2,
changed on measured evidence that lone dropped Wi-Fi packets were each opening a
forensic episode and bouncing the Dock (see config.py). This class keeps 1 so the
literal behaviour stays the documented, tested primitive and the policy decision
lives in one place -- the config.

`alert_repeat_seconds` defaults to 0, meaning never re-alert during one
outage. Set it to e.g. 300 to be nagged every 5 minutes while it stays down.
Note the Dock bounce itself is a critical-priority request, which keeps
bouncing until the app is activated, so a long outage remains visible without
any repeat.
"""

from collections import deque
from typing import Optional


class PingMonitor:
    def __init__(
        self,
        failure_threshold: int = 1,
        loss_window: int = 12,
        alert_repeat_seconds: float = 0,
    ):
        # A threshold of 0 or below behaves exactly like 1: _should_alert
        # returns early on a successful ping, so a healthy network cannot
        # alert either way. Clamp so the value reported is the value acted on.
        self.failure_threshold = max(1, failure_threshold)
        self.alert_repeat_seconds = alert_repeat_seconds
        self.consecutive_failures = 0
        self.down = False
        self._window: deque[bool] = deque(maxlen=max(1, loss_window))
        self._last_alert_at: Optional[float] = None

    def record(self, result: dict, now: float) -> dict:
        """Fold one ping result in and report what to display and whether to alert.

        Returns a snapshot: rtt_ms, loss_pct, down, alert, consecutive_failures,
        error. `alert` is true only on the tick the alert should actually fire.
        """
        ok = bool(result.get("ok"))
        self._window.append(ok)

        if ok:
            self.consecutive_failures = 0
            self.down = False
            # Re-arm, so the next outage alerts on its own edge.
            self._last_alert_at = None
        else:
            self.consecutive_failures += 1

        alert = self._should_alert(ok, now)
        if alert:
            self._last_alert_at = now

        return {
            "rtt_ms": result.get("rtt_ms") if ok else None,
            "loss_pct": self.loss_pct,
            "down": self.down,
            "alert": alert,
            "consecutive_failures": self.consecutive_failures,
            "error": None if ok else result.get("error"),
        }

    def _should_alert(self, ok: bool, now: float) -> bool:
        if ok or self.consecutive_failures < self.failure_threshold:
            return False

        if not self.down:
            self.down = True
            return True  # the failure edge

        # `> 0`, not truthiness: a negative repeat interval from YAML is truthy
        # and `now - last >= negative` is always true, which is the alert on
        # every failing tick this whole class exists to prevent.
        if self.alert_repeat_seconds > 0 and self._last_alert_at is not None:
            return now - self._last_alert_at >= self.alert_repeat_seconds
        return False

    @property
    def loss_pct(self) -> Optional[float]:
        """Loss across the recent window, or None before the first ping."""
        if not self._window:
            return None
        lost = sum(1 for ok in self._window if not ok)
        return 100.0 * lost / len(self._window)
