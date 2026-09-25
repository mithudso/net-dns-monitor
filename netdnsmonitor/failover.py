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
    Candidate,
    best_candidate,
    decide,
    next_preferred_streak,
)
from netdnsmonitor.service_order import (
    find_service,
    order_argv,
    parse_service_order,
    promote,
)
from netdnsmonitor.throughput import measure_all

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
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


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
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))


def apply_service_order(run_fn, services, new_order: list[str]) -> str:
    """Write a new service order and confirm it landed.

    Free function rather than a method because the CLI reorders services
    without any of the failover machinery -- and this is the one operation that
    must never be reimplemented, since it carries the permutation guard and the
    read-back verification that stop a slip from deleting a network service.

    Returns a string starting 'ok:', 'failed:' or 'NEEDS_PRIVILEGE:'.
    """
    argv = order_argv(services, new_order)
    if argv is None:
        return (
            "failed: refused to apply a service order that is not a permutation of the current one"
        )
    result = run_fn(argv)
    stderr = (getattr(result, "stderr", "") or "").strip()
    stdout = (getattr(result, "stdout", "") or "").strip()
    if getattr(result, "returncode", 1) != 0:
        if _looks_like_privilege_error(stderr + " " + stdout):
            return (
                "NEEDS_PRIVILEGE: reordering network services was refused; "
                "an administrator right is required"
            )
        return (
            f"failed: networksetup exited {getattr(result, 'returncode', '?')}: {stderr or stdout}"
        )
    # networksetup can exit 0 without changing anything, so the claim is only
    # made after reading the order back.
    listing = run_fn(["networksetup", "-listnetworkserviceorder"])
    after = (
        parse_service_order(getattr(listing, "stdout", "") or "")
        if getattr(listing, "returncode", 1) == 0
        else []
    )
    if not after:
        return "failed: could not read the service order back to confirm the change"
    if [s.name for s in after] != new_order:
        return "failed: networksetup reported success but the service order is unchanged"
    return f"ok: service order now starts with '{new_order[0]}'"


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
        # A service this app turned on, so failback can turn it back off.
        self.enabled_by_us: Optional[str] = None
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
        self.original_order = [str(n) for n in order] if isinstance(order, list) and order else None
        enabled_by_us = data.get("enabled_by_us")
        self.enabled_by_us = enabled_by_us if isinstance(enabled_by_us, str) else None
        last = data.get("last_switch_at")
        self.last_switch_at = last if _is_finite_number(last) else None
        times = data.get("switch_times")
        self.switch_times = (
            [float(t) for t in times if _is_finite_number(t)] if isinstance(times, list) else []
        )

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w") as f:
                json.dump(
                    {
                        "original_order": self.original_order,
                        "enabled_by_us": self.enabled_by_us,
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
        backup_service: Optional[str] = None,
        store: Optional[FailoverStore] = None,
        interface_prober: Optional[Callable[[Optional[str]], Optional[bool]]] = None,
        run_fn: Callable[[list[str]], object] = default_run,
        backup_services: Optional[list[str]] = None,
        throughput_meter: Optional[Callable[[Optional[str]], Optional[float]]] = None,
        measure_timeout: float = 5.0,
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
        if store is None or interface_prober is None:
            raise ValueError("NetworkFailover needs a store and an interface prober")
        self.auto_enabled = auto_enabled
        self.preferred_service = preferred_service
        # One backup or several. The singular form stays accepted because it is
        # the simpler config and most setups have exactly one; internally there
        # is only ever a list, so no code path has to care which was written.
        names = list(backup_services) if backup_services else []
        if backup_service and backup_service not in names:
            names.insert(0, backup_service)
        self.backup_services = names
        self.throughput_meter = throughput_meter
        self.measure_timeout = measure_timeout
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
        # Which backup was actually chosen last time, for the menu bar and the
        # report. None until a choice has been made.
        self.chosen_backup: Optional[str] = None

    @property
    def backup_service(self) -> Optional[str]:
        """The backup currently in play: whichever was last chosen, else the
        first configured. Kept so callers that only ever deal with one backup
        do not have to know about ranking.
        """
        if self.chosen_backup:
            return self.chosen_backup
        return self.backup_services[0] if self.backup_services else None

    # --- system reads -------------------------------------------------------

    def _list_services(self):
        result = self.run_fn(["networksetup", "-listnetworkserviceorder"])
        if getattr(result, "returncode", 1) != 0:
            return []
        return parse_service_order(getattr(result, "stdout", "") or "")

    def _active_side(self, services) -> str:
        """Any configured backup sitting first counts as "on the backup" -- not
        just the one most recently chosen. Otherwise a restart, or a switch to a
        different candidate, would read as being on the preferred link and
        invite a second switch on top of the first.
        """
        if not services:
            return PREFERRED
        return BACKUP if services[0].name in self.backup_services else PREFERRED

    def evaluate_candidates(self, services, measure: bool = True) -> list[Candidate]:
        """Probe (and optionally benchmark) every configured backup.

        Benchmarking costs seconds per candidate, so it is skipped for anything
        that did not answer a probe first -- there is nothing to measure on a
        path that carries no traffic, and paying for it would put the whole
        cost on the UI thread for no information.
        """
        found = []
        for name in self.backup_services:
            service = find_service(services, name)
            if service is None:
                found.append((name, None, None, True))
                continue
            found.append(
                (name, service.device, self.interface_prober(service.device), service.enabled)
            )

        # Benchmark every reachable candidate at once against a single
        # deadline. Serially this is one timeout each, on the timer thread,
        # during the outage being diagnosed.
        speeds: dict = {}
        if measure and self.throughput_meter is not None:
            devices = [d for _, d, ok, _ in found if ok is True and d]
            if devices:
                speeds = measure_all(devices, self.throughput_meter, self.measure_timeout)

        return [
            Candidate(
                name=name,
                device=device,
                reachable=reachable,
                throughput_mbps=speeds.get(device),
                enabled=enabled,
            )
            for name, device, reachable, enabled in found
        ]

    # --- system write -------------------------------------------------------

    def _enable_service(self, name: str) -> str:
        """A disabled service is skipped by macOS no matter where it sits in the
        order, so promoting one without enabling it produces a confident no-op.
        Both of this machine's hotspot paths ship disabled, which is exactly the
        case that made this necessary.

        Returns "" when nothing needed doing, otherwise a failure string.
        """
        result = self.run_fn(["networksetup", "-setnetworkserviceenabled", name, "on"])
        stderr = (getattr(result, "stderr", "") or "").strip()
        stdout = (getattr(result, "stdout", "") or "").strip()
        if getattr(result, "returncode", 1) != 0:
            if _looks_like_privilege_error(stderr + " " + stdout):
                return (
                    f"NEEDS_PRIVILEGE: enabling '{name}' was refused; an "
                    "administrator right is required"
                )
            return f"failed: could not enable '{name}': {stderr or stdout}"
        after = self._list_services()
        if not after:
            return f"failed: could not read the service order back to confirm '{name}' is enabled"
        service = find_service(after, name)
        if service is None:
            return f"failed: '{name}' disappeared mid-check"
        if not service.enabled:
            return f"failed: '{name}' reports success but is still disabled in the service order"
        return ""

    def _apply_order(self, services, new_order: list[str]) -> str:
        return apply_service_order(self.run_fn, services, new_order)

    # --- entry points -------------------------------------------------------

    def attempt_failover(self, classification: str) -> str:
        """Ladder repair step. Runs once per incident onset."""
        if not self.auto_enabled:
            return "disabled: automatic switching is off (manual switching still works)"
        return self._attempt(classification=classification, allow=FAILOVER)

    def switch_now(self, target: str, service: Optional[str] = None) -> str:
        """Manual switch from the menu bar.

        Skips the policy entirely -- the brakes exist to stop the app acting on
        its own judgement too often, and a person clicking a button has already
        supplied the judgement. What it does NOT skip is the execution safety:
        the permutation guard still refuses a corrupting order, and the result
        is still read back before anything is claimed.

        The switch is recorded, so an automatic switch cannot immediately
        follow a manual one.
        """
        # Early failures arm the cooldown here too, as in `_attempt`: nothing
        # about them changes by the next tick, and an automatic switch must not
        # follow straight after a manual one that failed for the same reason.
        services = self._list_services()
        if not services:
            self.store.record_attempt(self.time_fn())
            return "failed: could not read the current network service order"
        if find_service(services, self.preferred_service) is None:
            self.store.record_attempt(self.time_fn())
            return f"failed: service '{self.preferred_service}' not found; available: " + ", ".join(
                s.name for s in services
            )

        missing = [n for n in self.backup_services if find_service(services, n) is None]
        if self.backup_services and len(missing) == len(self.backup_services):
            self.store.record_attempt(self.time_fn())
            return (
                "failed: backup service(s) not found: "
                f"{', '.join(repr(n) for n in missing)}; available: "
                + ", ".join(s.name for s in services)
            )

        active_side = self._active_side(services)
        # Switching between two backups is a real request: "already on the
        # backup" is only a no-op when no particular one was named.
        if target == BACKUP and active_side == BACKUP and not service:
            return "no switch: already on the backup network"
        if target == BACKUP and service and services[0].name == service:
            return f"no switch: already on '{service}'"
        # Keyed off the head of the order, not `active_side`: a third service
        # promoted by hand is "not on a backup" without being on the preferred
        # link, and the restore is exactly what that situation needs.
        if target == PREFERRED and services[0].name == self.preferred_service:
            return "no switch: already on the preferred network"

        outcome = (
            self._do_failover(services, allow_unverified=True, prefer_name=service)
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

        Probes the preferred service and every configured backup, so this
        costs one subprocess plus up to one probe timeout per configured
        service. Called from explicit user actions and, on the tick path, only
        when a failback was actually attempted.
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
                return {
                    "name": name,
                    "device": None,
                    "found": False,
                    "reachable": None,
                    "enabled": None,
                    "throughput_mbps": None,
                }
            return {
                "name": name,
                "device": service.device,
                "found": True,
                "enabled": service.enabled,
                "reachable": self.interface_prober(service.device),
                "throughput_mbps": None,
            }

        backups = [describe(name) for name in self.backup_services]
        return {
            "error": None,
            "active_side": self._active_side(services),
            "active_service": services[0].name,
            "preferred": describe(self.preferred_service),
            # The single `backup` key stays for callers that only show one; the
            # list is what the console and the ranking actually use.
            "backup": backups[0]
            if backups
            else {
                "name": None,
                "device": None,
                "found": False,
                "reachable": None,
                "enabled": None,
                "throughput_mbps": None,
            },
            "backups": backups,
            "chosen_backup": self.chosen_backup,
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
        if not self.auto_enabled:
            return None
        # The CLI (`netdns failover backup`) writes this same file from its own
        # process. The store was loaded at startup, so without re-reading it a
        # CLI-initiated failover is invisible here: it is never undone, and the
        # next save() overwrites its record with nothing. A file read only --
        # no subprocess, no probe -- so the healthy tick stays free.
        self.store.load()
        if self.store.original_order is None:
            return None
        # The policy would refuse inside the cooldown anyway; checking here
        # saves paying a subprocess and a probe on every tick to hear it.
        last = self.store.last_switch_at
        if last is not None and 0 <= self.time_fn() - last < self.cooldown_seconds:
            return None
        outcome = self._attempt(classification="healthy", allow=FAILBACK)
        return outcome if outcome.startswith(("ok:", "failed:", "NEEDS_PRIVILEGE:")) else None

    def _attempt(self, *, classification: str, allow: str) -> str:
        # Each early failure arms the cooldown: nothing about "the listing
        # cannot be read" or "the preferred service is not in it" changes
        # between ticks, so without it the same doomed attempt re-runs its
        # subprocess every 30 seconds.
        services = self._list_services()
        if not services:
            self.store.record_attempt(self.time_fn())
            return "failed: could not read the current network service order"

        preferred = find_service(services, self.preferred_service)
        available = ", ".join(s.name for s in services)
        if preferred is None:
            self.store.record_attempt(self.time_fn())
            return (
                f"failed: preferred service '{self.preferred_service}' not found; "
                f"available: {available}"
            )
        if not self.backup_services:
            self.store.record_attempt(self.time_fn())
            return "failed: no backup services configured"
        missing = [n for n in self.backup_services if find_service(services, n) is None]
        if len(missing) == len(self.backup_services):
            self.store.record_attempt(self.time_fn())
            return (
                "failed: backup service(s) not found: "
                f"{', '.join(repr(n) for n in missing)}; available: {available}"
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
            #
            # Only when the preferred service is *actually* at the head. A
            # third service on top (the user promoted something by hand) also
            # reads as "not on a backup", and clearing there would destroy the
            # restore point while the machine is on neither side.
            if self.store.original_order is not None and services[0].name == self.preferred_service:
                self.store.original_order = None
                # The enable goes with it. Kept, it would be undone by some
                # later unrelated failback -- switching off a service the
                # user may have left on deliberately. Leaving a service on
                # is the safer mistake.
                self.store.enabled_by_us = None
                self.store.save()
            if services[0].name != self.preferred_service:
                return (
                    f"no switch: '{services[0].name}' is at the head of the order, "
                    "which is neither the preferred link nor a configured backup"
                )
            return "no switch: already on the preferred network"
        if allow == FAILOVER and active_side == BACKUP:
            return "no switch: already on the backup network"

        preferred_ok = self.interface_prober(preferred.device)
        # The backups only need evaluating when we are considering moving onto
        # one; on the failback path their health is not part of the decision,
        # and benchmarking them there would be seconds spent for nothing.
        candidates: list[Candidate] = []
        winner: Optional[Candidate] = None
        if allow == FAILOVER:
            candidates = self.evaluate_candidates(services)
            winner = best_candidate(candidates)
        # Tri-state, deliberately. "Every candidate was probed and none
        # answered" is a different fact from "no candidate could be probed at
        # all" -- the second is the unplugged-dongle case, and the policy
        # refuses it with a different reason.
        if winner is not None:
            backup_ok = True
        elif any(c.reachable is False for c in candidates):
            backup_ok = False
        else:
            backup_ok = None
        if active_side == BACKUP:
            self.preferred_streak = next_preferred_streak(self.preferred_streak, preferred_ok)
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
            outcome = self._do_failover(services, winner)
        else:
            outcome = self._do_failback(services)

        if outcome.startswith("ok:"):
            self.store.record_switch(self.time_fn())
            self.preferred_streak = 0
        else:
            self.store.record_attempt(self.time_fn())
        self.last_event = outcome
        return outcome

    def _do_failover(
        self,
        services,
        winner: Optional[Candidate] = None,
        allow_unverified: bool = False,
        prefer_name: Optional[str] = None,
    ) -> str:
        note_unverified = ""
        if winner is None:
            # Manual switches arrive without a ranking, so one is computed here
            # rather than defaulting to the first configured name -- picking the
            # fastest is the point of allowing several.
            candidates = self.evaluate_candidates(services)
            if prefer_name:
                # An explicitly named target is an instruction, not a suggestion.
                winner = next((c for c in candidates if c.name == prefer_name), None)
                if winner is None:
                    return (
                        f"failed: '{prefer_name}' is not one of the configured backups "
                        f"({', '.join(self.backup_services)})"
                    )
                if winner.device is None:
                    # Configured, but not present in the live service order --
                    # which is a different thing from vanishing mid-operation.
                    return (
                        f"failed: '{prefer_name}' is configured but not in the service "
                        "order; available: " + ", ".join(s.name for s in services)
                    )
                # Naming the target is an instruction, not evidence: the
                # outcome still has to say whether the path was proven.
                if winner.reachable is not True:
                    note_unverified = " -- WARNING: this path was not verified reachable"
            else:
                winner = best_candidate(candidates)
            if winner is None and allow_unverified:
                # A person asked for this. Refusing because nothing answered
                # would make the button useless in exactly the situation it
                # exists for -- but the outcome has to say the path is unproven.
                winner = next((c for c in candidates if c.device is not None), None)
                note_unverified = " -- WARNING: this path was not verified reachable"
        if winner is None:
            return "failed: no backup service is reachable"

        target = winner.name
        new_order = promote(services, target)
        if new_order is None:
            return f"failed: backup service '{target}' disappeared mid-check"

        # Recorded before the change, so failback can restore it exactly.
        self.store.original_order = [s.name for s in services]
        self.store.save()

        # Enable before promoting. A disabled service sits in the order and is
        # skipped, so promoting one on its own is a change that looks like a
        # success and routes nothing.
        note = ""
        if not winner.enabled:
            problem = self._enable_service(target)
            if problem:
                return problem
            # Recorded so failback can put it back the way it was. Enabling is
            # a change to the machine's configuration just as much as the
            # reorder is, and leaving it on afterwards is a change the user
            # never asked for and is not told about.
            self.store.enabled_by_us = target
            self.store.save()
            note = " (also enabled the service, which was off)"
            # Re-read: enabling rewrites the listing, and the order about to be
            # applied has to be a permutation of what is there *now*.
            services = self._list_services() or services
            new_order = promote(services, target) or new_order

        outcome = self._apply_order(services, new_order)
        if not outcome.startswith("ok:"):
            return outcome
        self.chosen_backup = target
        speed = (
            f" at {winner.throughput_mbps:.1f} Mbps"
            if winner.throughput_mbps is not None
            else " (speed not measured)"
        )
        return f"{outcome} (failed over to backup '{target}'{speed}){note}{note_unverified}"

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
        if not outcome.startswith("ok:"):
            return outcome

        # Put back the enable this app made, so the machine ends up in the
        # state it started in rather than one the user never asked for.
        undone = ""
        if self.store.enabled_by_us:
            name = self.store.enabled_by_us
            result = self.run_fn(["networksetup", "-setnetworkserviceenabled", name, "off"])
            # Read back before claiming, as with every other write here: exit
            # 0 does not mean the service went off.
            after = self._list_services()
            service = find_service(after, name) if after else None
            if (
                getattr(result, "returncode", 1) == 0
                and service is not None
                and not service.enabled
            ):
                undone = f" and disabled '{name}' again, which this app had enabled"
                self.store.enabled_by_us = None
            else:
                undone = f" (could not re-disable '{name}', which this app enabled)"

        self.store.original_order = None
        self.store.save()
        return f"{outcome} (failed back to preferred '{self.preferred_service}'{undone}){note}"
