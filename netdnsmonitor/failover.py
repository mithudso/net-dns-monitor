"""Execute network failover by rewriting the macOS service order.

Every side effect is an injected callable, so the whole control flow is
testable without touching the machine's network configuration.

Three properties this module is built around:

1. **It reports what happened, not what was attempted.** `networksetup` can
   exit 0 without the order changing, so a switch is only called `ok` after the
   order is read back and confirmed. Anything else is `failed:` or
   `NEEDS_PRIVILEGE:` -- the same discipline `flush_dns_cache` follows.

2. **Which side is live is read from the system, never remembered.** The active
   side is derived from the current service order on every call. A remembered
   flag drifts the moment the user reorders services by hand, or the app is
   restarted mid-outage, and then the app acts on a fiction.

3. **The pre-failover order is preserved verbatim.** Failing back by promoting
   the preferred service would leave the backup permanently second instead of
   wherever the user had it. The real order is recorded before the first switch
   and restored exactly -- unless the set of services has changed since, in
   which case the stale record is discarded and the reason is reported.
"""

import json
import math
import os
import subprocess
import time
from types import SimpleNamespace
from typing import Callable, Optional

from netdnsmonitor.failover_policy import (
    BACKUP,
    FAILBACK,
    FAILOVER,
    PREFERRED,
    decide,
    next_preferred_streak,
)
from netdnsmonitor.service_order import (
    find_service,
    is_order_intact,
    parse_service_order,
    promote,
)

# networksetup's wording when the SystemConfiguration write is refused. Matched
# to tell "you may not do this" apart from "this did not work", because the two
# call for completely different things from the user.
_PRIVILEGE_MARKERS = (
    "you must be running as root",
    "permission denied",
    "not permitted",
    "administrator",
    "authorization",
)


def _looks_like_privilege_error(text: str) -> bool:
    lowered = (text or "").lower()
    return any(marker in lowered for marker in _PRIVILEGE_MARKERS)


def _is_finite_number(value) -> bool:
    """`json.load` accepts bare NaN and Infinity, and both are instances of
    float. A NaN timestamp then defeats both rate brakes at once -- every
    comparison against it is False, so the cooldown looks expired and the
    hourly window looks empty. Booleans are rejected for the same reason they
    are not timestamps, despite being ints.
    """
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def default_run(args: list[str]) -> object:
    """A subprocess failure has to arrive as data, not an exception: this runs
    under the rumps timer, where an escaping error kills monitoring for the
    rest of the session.
    """
    # 5s to match repair_executor's ladder commands. A failover attempt spends
    # three of these back to back (list, reorder, read back), all on the rumps
    # timer thread, and networksetup contends with SystemConfiguration during
    # exactly the network churn being diagnosed -- a longer ceiling turns one
    # attempt into a menu-bar freeze.
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=5)
    except (subprocess.SubprocessError, OSError) as exc:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))


class FailoverStore:
    """Persists only what cannot be re-derived from the live system: the order
    that was in place before the first failover, and the switch timestamps the
    rate brakes need. Deliberately not persisted: which side is active (read
    from the system) and the healthy streak (reset on restart so a failback has
    to re-earn its evidence).
    """

    def __init__(self, path: str):
        self.path = os.path.expanduser(path)
        self.original_order: Optional[list[str]] = None
        self.last_switch_at: Optional[float] = None
        self.switch_times: list[float] = []
        self.load()

    def load(self) -> None:
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            # A missing or corrupt file must not stop monitoring; it only means
            # the exact pre-failover order is unknown.
            return
        if not isinstance(data, dict):
            return
        order = data.get("original_order")
        self.original_order = (
            [str(n) for n in order] if isinstance(order, list) and order else None
        )
        last = data.get("last_switch_at")
        self.last_switch_at = last if _is_finite_number(last) else None
        times = data.get("switch_times")
        self.switch_times = (
            [float(t) for t in times if _is_finite_number(t)]
            if isinstance(times, list)
            else []
        )

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w") as f:
                json.dump(
                    {
                        "original_order": self.original_order,
                        "last_switch_at": self.last_switch_at,
                        "switch_times": self.switch_times[-32:],
                    },
                    f,
                    indent=2,
                )
        except OSError:
            # Losing the record degrades failback to a promote(); it must never
            # take down the tick.
            pass

    def record_attempt(self, at: float) -> None:
        """Arms the cooldown without spending hourly budget.

        A write that was refused or silently did nothing still has to space out
        the retry. Without this, a failback that keeps failing -- an admin
        right revoked after the failover, or networksetup exiting 0 without
        doing anything -- re-runs the whole reorder on every single tick,
        because nothing else about the situation changes. Budget is deliberately
        not spent: failures should slow switching down, not use up a user's
        ability to switch when it would finally work.
        """
        self.last_switch_at = at
        self.save()

    def record_switch(self, at: float) -> None:
        self.last_switch_at = at
        self.switch_times.append(at)
        self.save()


class NetworkFailover:
    def __init__(
        self,
        preferred_service: str,
        backup_service: str,
        store: FailoverStore,
        interface_prober: Callable[[Optional[str]], Optional[bool]],
        run_fn: Callable[[list[str]], object] = default_run,
        failback_threshold: int = 3,
        cooldown_seconds: float = 300.0,
        max_switches_per_hour: int = 4,
        trigger_classifications: frozenset = frozenset({"network"}),
        time_fn: Callable[[], float] = time.time,
        auto_enabled: bool = True,
    ):
        # Automatic switching and manual switching are separate capabilities.
        # With auto off and both service names set, the menu bar button still
        # works and nothing ever moves on its own -- which is how you try this
        # feature before trusting it to act unattended.
        self.auto_enabled = auto_enabled
        self.preferred_service = preferred_service
        self.backup_service = backup_service
        self.store = store
        self.interface_prober = interface_prober
        self.run_fn = run_fn
        self.failback_threshold = failback_threshold
        self.cooldown_seconds = cooldown_seconds
        self.max_switches_per_hour = max_switches_per_hour
        self.trigger_classifications = trigger_classifications
        self.time_fn = time_fn
        self.preferred_streak = 0
        self.last_event: Optional[str] = None

    # --- system reads -------------------------------------------------------

    def _list_services(self):
        result = self.run_fn(["networksetup", "-listnetworkserviceorder"])
        if getattr(result, "returncode", 1) != 0:
            return []
        return parse_service_order(getattr(result, "stdout", "") or "")

    def _active_side(self, services) -> str:
        return BACKUP if services and services[0].name == self.backup_service else PREFERRED

    # --- system write -------------------------------------------------------

    def _apply_order(self, services, new_order: list[str]) -> str:
        """Apply and then verify. Returns an outcome string starting with
        'ok:', 'failed:' or 'NEEDS_PRIVILEGE:'.
        """
        if not is_order_intact(services, new_order):
            # The guard that stops a parser slip from deleting a network
            # service. Refusing is always safe; applying may not be.
            return (
                "failed: refused to apply a service order that is not a permutation "
                "of the current one"
            )
        result = self.run_fn(["networksetup", "-ordernetworkservices", *new_order])
        stderr = (getattr(result, "stderr", "") or "").strip()
        stdout = (getattr(result, "stdout", "") or "").strip()
        if getattr(result, "returncode", 1) != 0:
            if _looks_like_privilege_error(stderr + " " + stdout):
                return (
                    "NEEDS_PRIVILEGE: reordering network services was refused; "
                    "an administrator right is required"
                )
            return f"failed: networksetup exited {getattr(result, 'returncode', '?')}: {stderr or stdout}"
        # networksetup can exit 0 without changing anything, so the claim is
        # only made after reading the order back.
        after = self._list_services()
        if not after:
            return "failed: could not read the service order back to confirm the change"
        if [s.name for s in after] != new_order:
            return (
                "failed: networksetup reported success but the service order is "
                "unchanged"
            )
        return f"ok: service order now starts with '{new_order[0]}'"

    # --- entry points -------------------------------------------------------

    def attempt_failover(self, classification: str) -> str:
        """Ladder repair step. Runs once per incident onset."""
        if not self.auto_enabled:
            return "disabled: automatic switching is off (manual switching still works)"
        return self._attempt(classification=classification, allow=FAILOVER)

    def switch_now(self, target: str) -> str:
        """Manual switch from the menu bar.

        Skips the policy entirely -- the brakes exist to stop the app acting on
        its own judgement too often, and a person clicking a button has already
        supplied the judgement. What it does NOT skip is the execution safety:
        the permutation guard still refuses a corrupting order, and the result
        is still read back before anything is claimed.

        The switch is recorded, so an automatic switch cannot immediately
        follow a manual one.
        """
        services = self._list_services()
        if not services:
            return "failed: could not read the current network service order"
        for name in (self.preferred_service, self.backup_service):
            if find_service(services, name) is None:
                return (
                    f"failed: service '{name}' not found; available: "
                    + ", ".join(s.name for s in services)
                )

        active_side = self._active_side(services)
        if target == BACKUP and active_side == BACKUP:
            return "no switch: already on the backup network"
        if target == PREFERRED and active_side == PREFERRED:
            return "no switch: already on the preferred network"

        outcome = (
            self._do_failover(services)
            if target == BACKUP
            else self._do_failback(services)
        )
        if outcome.startswith("ok:"):
            self.store.record_switch(self.time_fn())
            self.preferred_streak = 0
        else:
            self.store.record_attempt(self.time_fn())
        self.last_event = outcome
        return outcome

    def snapshot(self) -> dict:
        """What the menu bar shows: which side is live, and whether each side
        can actually carry traffic right now.

        Probes both interfaces, so this costs up to two timeouts and a
        subprocess. Only ever called from an explicit user action or straight
        after a switch -- never from the poll path.
        """
        services = self._list_services()
        if not services:
            return {
                "error": "could not read the network service order",
                "auto_enabled": self.auto_enabled,
                "last_event": self.last_event,
            }

        def describe(name: str) -> dict:
            service = find_service(services, name)
            if service is None:
                return {"name": name, "device": None, "found": False, "reachable": None}
            return {
                "name": name,
                "device": service.device,
                "found": True,
                "reachable": self.interface_prober(service.device),
            }

        return {
            "error": None,
            "active_side": self._active_side(services),
            "active_service": services[0].name,
            "preferred": describe(self.preferred_service),
            "backup": describe(self.backup_service),
            "auto_enabled": self.auto_enabled,
            "last_event": self.last_event,
        }

    def attempt_failback(self) -> Optional[str]:
        """Tick path. Returns None when nothing was attempted, so an ordinary
        healthy tick stays silent.

        Gated on having a recorded pre-failover order, which is set on failover
        and cleared on failback. Without that gate this would spend a
        `networksetup` subprocess plus two interface probes on the rumps timer
        thread every 30 seconds forever, to answer a question whose answer is
        almost always "nothing to do".
        """
        if self.store.original_order is None or not self.auto_enabled:
            return None
        outcome = self._attempt(classification="healthy", allow=FAILBACK)
        return outcome if outcome.startswith(("ok:", "failed:", "NEEDS_PRIVILEGE:")) else None

    def _attempt(self, *, classification: str, allow: str) -> str:
        services = self._list_services()
        if not services:
            return "failed: could not read the current network service order"

        preferred = find_service(services, self.preferred_service)
        backup = find_service(services, self.backup_service)
        available = ", ".join(s.name for s in services)
        if preferred is None:
            return (
                f"failed: preferred service '{self.preferred_service}' not found; "
                f"available: {available}"
            )
        if backup is None:
            return (
                f"failed: backup service '{self.backup_service}' not found; "
                f"available: {available}"
            )

        active_side = self._active_side(services)
        # Decide which side we are on before probing anything. Probing costs up
        # to one timeout per interface on the UI thread, and the wrong-direction
        # request needs no probe at all to answer.
        if allow == FAILBACK and active_side == PREFERRED:
            self.preferred_streak = 0
            # Self-heal the failback gate. The pre-failover order is recorded
            # before the write, so a switch that landed but could not be read
            # back is still undoable -- the cost is a record left behind when
            # the write was refused outright, which on a machine that denies
            # the administrator right is every time. Left alone it holds the
            # gate open and spends a networksetup subprocess on the timer
            # thread every tick, forever, across restarts. Clearing keys off
            # the live order rather than the outcome string, so a real failover
            # whose read-back failed keeps its record.
            if self.store.original_order is not None:
                self.store.original_order = None
                self.store.save()
            return "no switch: already on the preferred network"
        if allow == FAILOVER and active_side == BACKUP:
            return "no switch: already on the backup network"

        preferred_ok = self.interface_prober(preferred.device)
        # The backup only needs verifying when we are considering moving onto
        # it; on the failback path its health is not part of the decision.
        backup_ok = self.interface_prober(backup.device) if allow == FAILOVER else None
        if active_side == BACKUP:
            self.preferred_streak = next_preferred_streak(
                self.preferred_streak, preferred_ok
            )
        else:
            self.preferred_streak = 0

        decision = decide(
            active_side=active_side,
            classification=classification,
            preferred_ok=preferred_ok,
            backup_ok=backup_ok,
            consecutive_preferred_ok=self.preferred_streak,
            failback_threshold=self.failback_threshold,
            now=self.time_fn(),
            last_switch_at=self.store.last_switch_at,
            cooldown_seconds=self.cooldown_seconds,
            switch_times=self.store.switch_times,
            max_switches_per_hour=self.max_switches_per_hour,
            trigger_classifications=self.trigger_classifications,
        )

        if decision.action != allow:
            return f"no switch: {decision.reason}"

        if decision.action == FAILOVER:
            outcome = self._do_failover(services)
        else:
            outcome = self._do_failback(services)

        if outcome.startswith("ok:"):
            self.store.record_switch(self.time_fn())
            self.preferred_streak = 0
        else:
            self.store.record_attempt(self.time_fn())
        self.last_event = outcome
        return outcome

    def _do_failover(self, services) -> str:
        new_order = promote(services, self.backup_service)
        if new_order is None:
            return f"failed: backup service '{self.backup_service}' disappeared mid-check"
        # Recorded before the change, so failback can restore it exactly.
        self.store.original_order = [s.name for s in services]
        self.store.save()
        outcome = self._apply_order(services, new_order)
        return (
            f"{outcome} (failed over to backup '{self.backup_service}')"
            if outcome.startswith("ok:")
            else outcome
        )

    def _do_failback(self, services) -> str:
        current_names = {s.name for s in services}
        recorded = self.store.original_order
        note = ""
        if recorded and set(recorded) == current_names and len(recorded) == len(services):
            new_order = recorded
        else:
            # The stale record cannot be applied without dropping or inventing a
            # service, so fall back to promoting the preferred link and say so.
            new_order = promote(services, self.preferred_service)
            if recorded:
                note = (
                    " (the recorded pre-failover order no longer matches the current "
                    "services, so the preferred link was promoted instead of an exact "
                    "restore)"
                )
        if new_order is None:
            return f"failed: preferred service '{self.preferred_service}' disappeared mid-check"
        outcome = self._apply_order(services, new_order)
        if outcome.startswith("ok:"):
            self.store.original_order = None
            self.store.save()
            return f"{outcome} (failed back to preferred '{self.preferred_service}'){note}"
        return outcome
