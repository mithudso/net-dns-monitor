"""Decide whether to move to the backup network, move back, or do nothing.

Pure function of the inputs -- no clock of its own, no sockets, no subprocess.
`now` is passed in so every rule below is testable without sleeping.

The whole point of this layer is to be *reluctant*. The link this was written
for flaps, and a switcher that reacts to every dip rewrites the system's
network order several times a minute. Four separate brakes have to release
before a switch happens: the incident must be the kind we act on, the other
side must be independently verified as working, the cooldown must have
expired, and the hourly budget must not be spent. A refusal is never silent --
every decision carries the reason it was made, and that reason lands in the
incident report.
"""

from dataclasses import dataclass
from typing import Optional

BUDGET_WINDOW_SECONDS = 3600.0

FAILOVER = "failover"
FAILBACK = "failback"
NONE = "none"

PREFERRED = "preferred"
BACKUP = "backup"


@dataclass(frozen=True)
class FailoverDecision:
    action: str
    reason: str


def next_preferred_streak(current: int, preferred_ok: Optional[bool]) -> int:
    """Count of consecutive checks where the preferred link answered.

    `None` -- the interface is absent, so the question was never asked --
    resets the streak rather than holding it. Holding it would let an adapter
    unplugged for an hour trigger a failback on its first good probe after
    being plugged back in, before there is any evidence it is stable.
    """
    if preferred_ok is True:
        return current + 1
    return 0


def _recent_switches(switch_times: list[float], now: float) -> list[float]:
    # A clock that jumped backwards (sleep/wake, NTP correction) would other-
    # wise leave future-dated entries pinned in the window forever.
    return [t for t in switch_times if 0 <= now - t < BUDGET_WINDOW_SECONDS]


def _brakes(
    *,
    now: float,
    last_switch_at: Optional[float],
    cooldown_seconds: float,
    switch_times: list[float],
    max_switches_per_hour: int,
) -> Optional[str]:
    """Returns a refusal reason, or None if both rate brakes are released.

    These apply to failback as well as failover. Blocking only failover would
    still permit a half-oscillation every cooldown; and when the budget is
    spent, the safe place to come to rest is the side that is currently
    carrying traffic.
    """
    if last_switch_at is not None and now >= last_switch_at:
        elapsed = now - last_switch_at
        if elapsed < cooldown_seconds:
            return f"cooldown: {cooldown_seconds - elapsed:.0f}s remaining since the last switch"
    recent = _recent_switches(switch_times, now)
    if max_switches_per_hour >= 0 and len(recent) >= max_switches_per_hour:
        return (
            f"switch budget exhausted: {len(recent)} switch(es) in the last hour, "
            f"limit {max_switches_per_hour}"
        )
    return None


def decide(
    *,
    active_side: str,
    classification: str,
    preferred_ok: Optional[bool],
    backup_ok: Optional[bool],
    consecutive_preferred_ok: int,
    failback_threshold: int,
    now: float,
    last_switch_at: Optional[float] = None,
    cooldown_seconds: float = 300.0,
    switch_times: Optional[list[float]] = None,
    max_switches_per_hour: int = 4,
    trigger_classifications: frozenset = frozenset({"network"}),
) -> FailoverDecision:
    switch_times = switch_times or []

    if active_side == BACKUP:
        return _decide_failback(
            preferred_ok=preferred_ok,
            consecutive_preferred_ok=consecutive_preferred_ok,
            failback_threshold=failback_threshold,
            now=now,
            last_switch_at=last_switch_at,
            cooldown_seconds=cooldown_seconds,
            switch_times=switch_times,
            max_switches_per_hour=max_switches_per_hour,
        )

    return _decide_failover(
        classification=classification,
        preferred_ok=preferred_ok,
        backup_ok=backup_ok,
        now=now,
        last_switch_at=last_switch_at,
        cooldown_seconds=cooldown_seconds,
        switch_times=switch_times,
        max_switches_per_hour=max_switches_per_hour,
        trigger_classifications=trigger_classifications,
    )


def _decide_failover(
    *,
    classification,
    preferred_ok,
    backup_ok,
    now,
    last_switch_at,
    cooldown_seconds,
    switch_times,
    max_switches_per_hour,
    trigger_classifications,
) -> FailoverDecision:
    if classification not in trigger_classifications:
        return FailoverDecision(
            NONE, f"classification '{classification}' is not a failover trigger"
        )
    if backup_ok is None:
        return FailoverDecision(
            NONE,
            "backup interface was not probed (absent, or no device resolved) -- "
            "not switching to an unverified path",
        )
    if backup_ok is False:
        return FailoverDecision(
            NONE,
            "backup interface did not answer either -- switching would trade one "
            "dead path for another",
        )
    if preferred_ok is True:
        # The default route is failing while the preferred interface answers on
        # its own. That is not a path-specific outage, so moving the traffic
        # elsewhere is not indicated -- something else is wrong.
        return FailoverDecision(
            NONE,
            "preferred interface is reachable when probed directly -- the outage "
            "is not specific to this path",
        )
    brake = _brakes(
        now=now,
        last_switch_at=last_switch_at,
        cooldown_seconds=cooldown_seconds,
        switch_times=switch_times,
        max_switches_per_hour=max_switches_per_hour,
    )
    if brake:
        return FailoverDecision(NONE, brake)
    return FailoverDecision(
        FAILOVER,
        "preferred interface unreachable and backup verified reachable through "
        "its own interface",
    )


def _decide_failback(
    *,
    preferred_ok,
    consecutive_preferred_ok,
    failback_threshold,
    now,
    last_switch_at,
    cooldown_seconds,
    switch_times,
    max_switches_per_hour,
) -> FailoverDecision:
    if preferred_ok is None:
        return FailoverDecision(
            NONE, "preferred interface is absent -- staying on the backup"
        )
    if preferred_ok is False:
        return FailoverDecision(
            NONE, "preferred interface still unreachable -- staying on the backup"
        )
    if consecutive_preferred_ok < failback_threshold:
        return FailoverDecision(
            NONE,
            f"preferred interface healthy for {consecutive_preferred_ok}/"
            f"{failback_threshold} consecutive checks -- not yet stable enough",
        )
    brake = _brakes(
        now=now,
        last_switch_at=last_switch_at,
        cooldown_seconds=cooldown_seconds,
        switch_times=switch_times,
        max_switches_per_hour=max_switches_per_hour,
    )
    if brake:
        return FailoverDecision(NONE, brake)
    return FailoverDecision(
        FAILBACK,
        f"preferred interface healthy for {consecutive_preferred_ok} consecutive "
        "checks",
    )
