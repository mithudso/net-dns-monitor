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
import threading
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
from netdnsmonitor.interface_probe import make_interface_prober
from netdnsmonitor.report_storage import _atomic_write
from netdnsmonitor.service_order import (
    find_service,
    is_order_intact,
    parse_service_order,
    promote,
)
from netdnsmonitor.throughput import make_throughput_meter, measure_all

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


_BUSY = "no switch: another switch attempt is in progress"


def _neither_side(head: str) -> str:
    return (
        f"no switch: '{head}' is at the head of the order, "
        "which is neither the preferred link nor a configured backup"
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


def default_run(args: list[str], timeout: float = 5) -> object:
    """A subprocess failure has to arrive as data, not an exception: this runs
    under the rumps timer. rumps catches the exception, but the rest of that
    tick is skipped, and on an incident edge that loses the report and alert.

    `timeout` exists for the console, whose catalogue commands (traceroute)
    need far longer than a networksetup call. Failover callers keep the default.
    """
    # 5s to match repair_executor's ladder commands. A failover attempt spends
    # several of these back to back (list, re-list, reorder, read back), all on
    # the rumps timer thread, and networksetup contends with SystemConfiguration
    # during exactly the network churn being diagnosed -- a longer ceiling turns
    # one attempt into a menu-bar freeze.
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (subprocess.SubprocessError, OSError) as exc:
        return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))


def apply_service_order(run_fn, services, new_order: list[str]) -> str:
    """Write a new service order and confirm it landed.

    Free function rather than a method because the CLI reorders services
    without any of the failover machinery -- and this is the one operation that
    must never be reimplemented, since it carries the permutation guard and the
    read-back verification that stop a slip from deleting a network service.

    Returns a string starting 'ok:', 'failed:' or 'NEEDS_PRIVILEGE:'.
    """
    if not is_order_intact(services, new_order):
        return (
            "failed: refused to apply a service order that is not a permutation of the current one"
        )
    # `services` was listed before the probes, which can take seconds. A
    # service added in that window is absent from `new_order`, the guard above
    # cannot see it, and the write would drop it from the order -- after which
    # the read-back matches and reports `ok`. So the order is listed again right
    # before the write, and any difference from the listing the new order was
    # built from refuses.
    fresh_listing = run_fn(["networksetup", "-listnetworkserviceorder"])
    fresh = (
        parse_service_order(getattr(fresh_listing, "stdout", "") or "")
        if getattr(fresh_listing, "returncode", 1) == 0
        else []
    )
    if not fresh:
        return (
            "failed: could not re-read the service order right before writing; nothing was applied"
        )
    if [s.name for s in fresh] != [s.name for s in services]:
        return "failed: the service order changed during the check; nothing was applied"
    result = run_fn(["networksetup", "-ordernetworkservices", *new_order])
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
        # Identity of the file as last loaded. The CLI and the console build
        # their own store on the same path, so a record one process writes has
        # to reach the others -- see refresh().
        self._file_signature: Optional[tuple] = None
        self.load()

    def _stat_signature(self) -> Optional[tuple]:
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        # save() replaces the file, so the inode changes on every write; mtime
        # and size cover an editor that rewrites it in place.
        return (st.st_ino, st.st_mtime_ns, st.st_size)

    def refresh(self) -> None:
        """Reload when another process has written the file since the last load.

        One stat, no subprocess, so it is cheap enough for the healthy-tick
        gate. Without it, a failover started from the terminal never reaches
        the running app's failback gate, and the app's next save overwrites
        the terminal's record with its own stale one.
        """
        signature = self._stat_signature()
        if signature is not None and signature != self._file_signature:
            self.load()

    def load(self) -> None:
        # Stat before reading, so a write that lands mid-read is still seen as
        # a change on the next refresh().
        self._file_signature = self._stat_signature()
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
            # Atomic, because truncate-then-write leaves an empty or partial
            # file if the write fails, and load() then reads no record at all.
            _atomic_write(
                self.path,
                json.dumps(
                    {
                        "original_order": self.original_order,
                        "enabled_by_us": self.enabled_by_us,
                        "last_switch_at": self.last_switch_at,
                        "switch_times": self.switch_times[-32:],
                    },
                    indent=2,
                ),
            )
            # Our own write is not a change to reload. Leaving the old
            # signature would also let a later *failed* save be undone: the
            # next refresh() would reload this file over the newer in-memory
            # record.
            self._file_signature = self._stat_signature()
        except OSError:
            # A failed save must never take down the tick. The in-memory record
            # still drives failback for this session. After a restart it is
            # gone, the failback gate stays shut, and automatic failback never
            # runs -- only a manual switch to preferred, which then promotes the
            # preferred link instead of restoring the exact order.
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
        store: FailoverStore = None,
        interface_prober: Callable[[Optional[str]], Optional[bool]] = None,
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
        # The dashboard worker runs the ladder (attempt_failover) while the
        # timer tick runs attempt_failback. Interleaved, the tick reads the
        # pre-write order, self-heals the record away, and the switch that then
        # lands can never be failed back. Acquired non-blocking, so a tick
        # never waits behind a switch that takes several subprocess timeouts.
        self._lock = threading.Lock()
        # Set once an attempt reaches the write, so the tick only surfaces
        # outcomes that changed (or tried to change) something.
        self._wrote = False

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

        Returns "" when the enable is confirmed, otherwise a failure string.
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
        # Exit 0 means the enable may have landed even if the read-back below
        # cannot confirm it, so it is recorded first: failback can then undo
        # it. The record has one slot. A service already in it stays there, so
        # a second enable never erases the first from what gets undone.
        previous = self.store.enabled_by_us
        if previous is None:
            self.store.enabled_by_us = name
            self.store.save()
        after = self._list_services()
        if not after:
            return f"failed: could not read the order back to confirm '{name}' was enabled"
        service = find_service(after, name)
        if service is None:
            return f"failed: '{name}' is no longer in the service order after enabling it"
        if not service.enabled:
            if previous is None:
                # Confirmed not enabled, so there is nothing to undo. Keeping
                # the record would make a later failback claim it turned off a
                # service this app never turned on.
                self.store.enabled_by_us = None
                self.store.save()
            return f"failed: '{name}' reports success but is still disabled in the service order"
        return ""

    def _undo_enable(self, head: Optional[str]) -> str:
        """Put back the enable this app made, so the machine ends up in the
        state it started in rather than one the user never asked for.

        Returns a fragment for the outcome. The claim comes from a read-back,
        not the exit code, because `-setnetworkserviceenabled` can exit 0 and
        change nothing, just as the reorder can. The record is cleared either
        way, and the caller saves it: a record kept after a failed undo would
        make some later, unrelated failback turn the service off.
        """
        name = self.store.enabled_by_us
        if not name:
            return ""
        self.store.enabled_by_us = None
        if name == head:
            # The service now carries the traffic (the config changed since it
            # was enabled). Turning it off would take the live link down.
            return f" (left '{name}' on, which this app enabled, because it is now at the head)"
        result = self.run_fn(["networksetup", "-setnetworkserviceenabled", name, "off"])
        if getattr(result, "returncode", 1) != 0:
            return f" (could not re-disable '{name}', which this app enabled)"
        service = find_service(self._list_services(), name)
        if service is not None and service.enabled is False:
            return f" and disabled '{name}' again, which this app had enabled"
        return f" (could not confirm '{name}' was disabled again)"

    def _apply_order(self, services, new_order: list[str]) -> str:
        return apply_service_order(self.run_fn, services, new_order)

    # --- entry points -------------------------------------------------------

    def attempt_failover(self, classification: str) -> str:
        """Ladder repair step. Runs once per incident onset."""
        if not self.auto_enabled:
            return "disabled: automatic switching is off (manual switching still works)"
        if not self._lock.acquire(blocking=False):
            return _BUSY
        try:
            self.store.refresh()
            return self._attempt(classification=classification, allow=FAILOVER)
        finally:
            self._lock.release()

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
        if not self._lock.acquire(blocking=False):
            return _BUSY
        try:
            self.store.refresh()
            return self._switch_now(target, service)
        finally:
            self._lock.release()

    def _switch_now(self, target: str, service: Optional[str]) -> str:
        services = self._list_services()
        if not services:
            return "failed: could not read the current network service order"
        if find_service(services, self.preferred_service) is None:
            return f"failed: service '{self.preferred_service}' not found; available: " + ", ".join(
                s.name for s in services
            )

        missing = [n for n in self.backup_services if find_service(services, n) is None]
        if self.backup_services and len(missing) == len(self.backup_services):
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
        if target == PREFERRED and active_side == PREFERRED:
            if services[0].name != self.preferred_service:
                return _neither_side(services[0].name)
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
        almost always "nothing to do". The store refresh ahead of it is one
        stat, which is neither.

        Only an attempt that reached a write returns its outcome. A pre-write
        failure (a misspelt preferred service, an unreadable order) would
        otherwise come back every tick, and each return makes the app re-list
        and re-probe for its menu.
        """
        if not self.auto_enabled:
            return None
        if not self._lock.acquire(blocking=False):
            # A switch is running on another thread; this tick has nothing to add.
            return None
        try:
            self.store.refresh()
            if self.store.original_order is None:
                return None
            self._wrote = False
            outcome = self._attempt(classification="healthy", allow=FAILBACK)
            if self._wrote and outcome.startswith(("ok:", "failed:", "NEEDS_PRIVILEGE:")):
                return outcome
            return None
        finally:
            self._lock.release()

    def _attempt(self, *, classification: str, allow: str) -> str:
        services = self._list_services()
        if not services:
            return "failed: could not read the current network service order"

        preferred = find_service(services, self.preferred_service)
        available = ", ".join(s.name for s in services)
        if preferred is None:
            return (
                f"failed: preferred service '{self.preferred_service}' not found; "
                f"available: {available}"
            )
        if not self.backup_services:
            return "failed: no backup services configured"
        missing = [n for n in self.backup_services if find_service(services, n) is None]
        if len(missing) == len(self.backup_services):
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
            # Only when the preferred service is *actually* at the head, or the
            # live order is exactly the record (the write never landed, from
            # whatever order it started). A third service on top that the user
            # promoted by hand also reads as "not on a backup", and clearing
            # there would destroy the restore point while the machine is on
            # neither side.
            #
            # An enable this app made goes with the record. A failed reorder
            # can leave one behind, and a record kept past this point would be
            # undone by some later, unrelated failback.
            names = [s.name for s in services]
            undone = ""
            if self.store.original_order is not None and (
                names[0] == self.preferred_service or names == self.store.original_order
            ):
                self.store.original_order = None
                undone = self._undo_enable(head=names[0])
                self.store.save()
            if names[0] != self.preferred_service:
                outcome = _neither_side(names[0]) + undone
            else:
                outcome = "no switch: already on the preferred network" + undone
            if undone:
                self.last_event = outcome
            return outcome
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

        self._wrote = True
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
                if find_service(services, prefer_name) is None:
                    # Configured, but not present in the live service order --
                    # which is a different thing from vanishing mid-operation.
                    return (
                        f"failed: '{prefer_name}' is configured but not in the service "
                        "order; available: " + ", ".join(s.name for s in services)
                    )
                if winner.device is None:
                    # In the order, but with no device (a VPN-style service).
                    # Calling it absent would send someone looking for a
                    # service that is right there.
                    return (
                        f"failed: '{prefer_name}' is in the service order but has no "
                        "device, so there is nothing to probe; not switching"
                    )
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

        # Recorded before the change, so failback can restore it exactly. Only
        # from the preferred side, or when nothing is recorded yet: on a switch
        # from one backup to another, recording would make the first backup the
        # "original", and failback would restore it and call that preferred.
        if self.store.original_order is None or self._active_side(services) == PREFERRED:
            self.store.original_order = [s.name for s in services]
            self.store.save()

        # Enable before promoting. A disabled service sits in the order and is
        # skipped, so promoting one on its own is a change that looks like a
        # success and routes nothing.
        note = ""
        if not winner.enabled:
            # _enable_service records the enable so failback can put it back.
            # Enabling is a change to the machine's configuration just as much
            # as the reorder is, and leaving it on afterwards is a change the
            # user never asked for and is not told about.
            problem = self._enable_service(target)
            if problem:
                return problem
            if self.store.enabled_by_us == target:
                note = " (also enabled the service, which was off)"
            else:
                note = (
                    " (also enabled the service, which was off; it will stay on after "
                    f"failback, because the record already holds '{self.store.enabled_by_us}')"
                )
            # Re-read: enabling rewrites the listing, and the order about to be
            # applied has to be a permutation of what is there *now*.
            services = self._list_services() or services
            new_order = promote(services, target) or new_order

        outcome = self._apply_order(services, new_order)
        if not outcome.startswith("ok:"):
            if not winner.enabled:
                outcome += f" ('{target}' was enabled first and is still on)"
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
        matches = (
            bool(recorded) and set(recorded) == current_names and len(recorded) == len(services)
        )
        note = ""
        if matches and recorded[0] not in self.backup_services:
            new_order = recorded
        else:
            # A stale record cannot be applied without dropping or inventing a
            # service. A record that starts on a backup (taken while already
            # failed over) would, restored verbatim, leave the machine on that
            # backup under an outcome saying it failed back. Both promote the
            # preferred link instead, and say so.
            new_order = promote(services, self.preferred_service)
            if matches:
                note = (
                    " (the recorded pre-failover order starts with a backup, so the "
                    "preferred link was promoted instead of an exact restore)"
                )
            elif recorded:
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

        undone = self._undo_enable(head=new_order[0])
        self.store.original_order = None
        self.store.save()
        return f"{outcome} (failed back to preferred '{self.preferred_service}'{undone}){note}"


# --- construction from config -------------------------------------------------
#
# Here rather than in app.py so the CLI can build the same failover without
# importing the menu bar module, and with it rumps and AppKit.


def build_failover(config: dict):
    """Returns a NetworkFailover, or None when the feature is off or not fully
    configured.

    Both service names are required and neither is guessed. The machine this
    was written for has three wired adapters with near-identical names, so a
    "helpful" default here would reorder the wrong physical link.
    """
    preferred = config.get("failover_preferred_service")
    backups = failover_backup_names(config)
    if not preferred or not backups:
        return None
    timeout = float(config["failover_speedtest_timeout_seconds"])
    return NetworkFailover(
        preferred_service=preferred,
        backup_services=backups,
        throughput_meter=make_throughput_meter(
            host=config.get("failover_speedtest_host", ""),
            path=config["failover_speedtest_path"],
            port=int(config["failover_speedtest_port"]),
            timeout=timeout,
            max_bytes=int(config["failover_speedtest_max_bytes"]),
        ),
        # The configured timeout, not NetworkFailover's 5s default: measure_all
        # stops waiting at this deadline, so a longer per-meter timeout was cut
        # short and a slow but working backup read as no measurement at all.
        measure_timeout=timeout,
        store=FailoverStore(config["failover_state_path"]),
        interface_prober=make_interface_prober(
            targets=failover_probe_targets(config),
            timeout=failover_probe_timeout(config),
        ),
        failback_threshold=int(config["failover_failback_threshold"]),
        cooldown_seconds=float(config["failover_cooldown_seconds"]),
        max_switches_per_hour=max(0, int(config["failover_max_switches_per_hour"])),
        trigger_classifications=failover_trigger_classifications(config),
        auto_enabled=bool(config.get("failover_enabled")),
    )


def failover_probe_targets(config: dict) -> list[tuple]:
    """What the interface prober aims at, which is not always what the ordinary
    probe aims at.

    Both defaulted to `external_targets` until a machine turned up where that
    could not work. The ordinary probe asks "is the internet reachable" and
    wants a target out on it. The interface probe asks "would this specific
    adapter carry traffic" and pins the socket to it with IP_BOUND_IF -- which
    bypasses any VPN tunnel, so on a machine routing through one, every
    physical interface reads unreachable against an internet target while the
    machine is plainly online. See docs/known-issues.md.

    Splitting them is the fix, and it has to be a split rather than a
    repointing: aiming `external_targets` at a LAN gateway would make the
    ordinary probe call the network healthy through an ISP outage, because the
    gateway answers either way.

    Empty means "use external_targets", which keeps the previous behaviour for
    every machine that does not need the split.
    """
    configured = config.get("failover_probe_targets") or config["external_targets"]
    return [tuple(t) for t in configured]


def failover_probe_timeout(config: dict) -> float:
    """The interface prober's deadline, which is not the ordinary probe's.

    `make_interface_prober` spends ONE deadline across all targets, deliberately
    -- see its comment about the additive stall. That makes the budget a
    function of how many targets are listed, and the per-link gateways this
    feature wants are unreachable from every link but their own: measured here,
    the wired gateway blackholes for the full 2s from Wi-Fi rather than
    refusing, so a 2s budget is consumed entirely by the first target and the
    reachable one is never tried. The probe then reports "unreachable" about a
    link that works.

    Sized for the target list rather than shared with `probe_timeout_seconds`,
    which bounds a different thing on every tick. This budget is only ever spent
    once the machine has actually failed over or is in an incident -- a healthy
    tick that has never failed over runs no probes at all.

    0 means "use probe_timeout_seconds".
    """
    configured = float(config.get("failover_probe_timeout_seconds") or 0)
    if configured > 0:
        return configured
    return float(config.get("probe_timeout_seconds", 2.0))


def failover_backup_names(config: dict) -> list[str]:
    """The ordered backup list, however it was written.

    The singular key stays accepted because most setups have exactly one
    backup and a list of one is noise. Duplicates are collapsed and the
    preferred service is refused as its own backup -- promoting a service above
    itself is not a failover.
    """
    names: list[str] = []
    for name in [config.get("failover_backup_service")] + list(
        config.get("failover_backup_services") or []
    ):
        if name and name not in names and name != config.get("failover_preferred_service"):
            names.append(name)
    return names


def failover_trigger_classifications(config: dict) -> frozenset:
    """An explicitly empty list means "nothing triggers a switch" and must be
    honoured. `config.get(key) or [...]` would treat it as absent and re-arm
    the default, so setting `failover_trigger_classifications: []` to stage the
    feature inert while checking service names would still rewrite the service
    order on the next incident. Only a missing or null key takes the default.
    """
    if not config.get("failover_enabled"):
        # Manual-only mode: the menu bar button still switches, but no incident
        # puts the failover step on the ladder.
        return frozenset()
    configured = config.get("failover_trigger_classifications")
    if configured is None:
        configured = ["network"]
    return frozenset(configured)
