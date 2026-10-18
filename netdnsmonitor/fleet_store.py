"""What the central server remembers: an append-only event log and a per-machine
state file, plus the text that answers "which machines have problems, what are
they, and what was done about them".

No sockets here. `fleet_server.py` receives datagrams and calls `record`; the
`netdns fleet` command reads the two files this module wrote, so the report is
available whether or not the server process is running.

**Two files, two jobs.**

    events.jsonl   every accepted event, in arrival order, appended as it
                   happens (a crashed server loses nothing already logged)
    state.json     the current picture: one entry per machine, rewritten
                   atomically after each change

**What is logged, and what is not.** Heartbeats update `last_seen` and the
status but are not logged each time: a log line per machine per five minutes
would bury the incidents. A heartbeat is logged only when it changes the
picture -- a machine appearing, returning after silence, or contradicting the
state (see below).

**A lost `resolved` does not leave an incident open forever.** If a heartbeat
says the machine is healthy while the server holds an open incident, the server
closes it and logs `resolved` with `inferred: true`. The log therefore says the
close was deduced from a heartbeat, not reported.

**Silence is reported, not assumed healthy.** A machine not heard from for
`stale_seconds` is marked `silent` and logged once. A silent machine's last known
status is shown beside it, never "healthy": it may be the machine whose network
is down, which is the one case where it cannot tell the server so.

**Duplicates.** A report is re-sent until acknowledged, so a lost ack produces a
duplicate. Each machine's last event ids are remembered and a repeat is
acknowledged but not logged twice.

**Rate limit.** A machine id may log at most `RATE_LIMIT_EVENTS` events a minute.
Beyond that the server refuses and counts it, so unsigned trial mode, or a
buggy client, cannot fill the disk.
"""

import json
import os
from collections import deque
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from netdnsmonitor import fleet_protocol as proto

REFUSED_RATE = "rate_limited"
REFUSED_TOO_MANY = "too_many_machines"

MAX_MACHINES = 1000
RECENT_EVENT_IDS = 30
RATE_LIMIT_EVENTS = 30
RATE_WINDOW_SECONDS = 60.0
LOG_ROTATE_BYTES = 10 * 1024 * 1024

ONLINE = "online"
SILENT = "silent"
INCIDENT = proto.INCIDENT
RESOLVED = proto.RESOLVED


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class FleetStore:
    def __init__(
        self,
        log_path: str,
        state_path: str,
        stale_seconds: float = 900.0,
        now_fn: Callable[[], float] = lambda: datetime.now(timezone.utc).timestamp(),
    ):
        self.log_path = os.path.expanduser(log_path)
        self.state_path = os.path.expanduser(state_path)
        self.stale_seconds = stale_seconds
        self.now_fn = now_fn
        self.machines: dict[str, dict[str, Any]] = {}
        self.refused: dict[str, int] = {}
        self.started_at = now_fn()
        self._recent: dict[str, deque[float]] = {}
        self.load()

    # --- persistence -------------------------------------------------------

    def load(self) -> None:
        try:
            with open(self.state_path, encoding="utf-8") as handle:
                state = json.load(handle)
        except (OSError, ValueError):
            return
        if isinstance(state, dict):
            machines = state.get("machines")
            refused = state.get("refused")
            if isinstance(machines, dict):
                self.machines = {
                    key: value
                    for key, value in machines.items()
                    if isinstance(key, str) and isinstance(value, dict)
                }
            if isinstance(refused, dict):
                self.refused = {
                    key: value
                    for key, value in refused.items()
                    if isinstance(key, str) and isinstance(value, int)
                }

    def save(self) -> None:
        os.makedirs(os.path.dirname(self.state_path) or ".", exist_ok=True)
        temporary = f"{self.state_path}.tmp"
        with open(temporary, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "machines": self.machines,
                    "refused": self.refused,
                    "saved_at": _iso(self.now_fn()),
                },
                handle,
                indent=2,
                sort_keys=True,
            )
        os.replace(temporary, self.state_path)

    def _append(self, event: dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
        try:
            if os.path.getsize(self.log_path) > LOG_ROTATE_BYTES:
                os.replace(self.log_path, f"{self.log_path}.1")
        except OSError:
            pass
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True) + "\n")

    # --- receiving ---------------------------------------------------------

    def note_refused(self, reason: str) -> None:
        self.refused[reason] = self.refused.get(reason, 0) + 1
        self.save()

    def _rate_ok(self, machine_id: str, now: float) -> bool:
        window = self._recent.setdefault(machine_id, deque())
        while window and now - window[0] > RATE_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= RATE_LIMIT_EVENTS:
            return False
        window.append(now)
        return True

    def record(self, message: dict[str, Any], address: str) -> str:
        """Fold one accepted message into the log and state.

        Returns "logged", "duplicate" or a refusal reason (REFUSED_*). Anything
        but a refusal is acknowledged to the sender.
        """
        now = self.now_fn()
        machine_id = message["id"]
        if not machine_id:
            self.note_refused(proto.REFUSED_MALFORMED)
            return proto.REFUSED_MALFORMED
        machine = self.machines.get(machine_id)
        if machine is None and len(self.machines) >= MAX_MACHINES:
            self.note_refused(REFUSED_TOO_MANY)
            return REFUSED_TOO_MANY
        if not self._rate_ok(machine_id, now):
            self.note_refused(REFUSED_RATE)
            return REFUSED_RATE

        is_new = machine is None
        if machine is None:
            machine = {
                "id": machine_id,
                "first_seen": _iso(now),
                "incidents_total": 0,
                "open_incident": None,
                "last_incident": None,
                "recent_event_ids": [],
            }
            self.machines[machine_id] = machine

        duplicate = message["eid"] in machine["recent_event_ids"]
        was_silent = bool(machine.get("silent"))
        machine.update(
            {
                "host": message["host"],
                "address": address,
                "last_seen_epoch": now,
                "last_seen": _iso(now),
                "silent": False,
                "signed": message["signed"],
            }
        )
        version = message["data"].get("version")
        if version:
            machine["version"] = version
        if message["eid"]:
            machine["recent_event_ids"] = (machine["recent_event_ids"] + [message["eid"]])[
                -RECENT_EVENT_IDS:
            ]

        if duplicate:
            self.save()
            return "duplicate"

        kind = message["t"]
        if kind == proto.HELLO:
            self._on_hello(machine, message, now, is_new, was_silent)
        elif kind == proto.INCIDENT:
            self._on_incident(machine, message, now)
        elif kind == proto.RESOLVED:
            self._on_resolved(machine, message, now)
        self.save()
        return "logged"

    def _event(self, kind: str, machine: dict[str, Any], now: float, **fields: Any) -> None:
        self._append(
            {
                "at": _iso(now),
                "kind": kind,
                "machine_id": machine["id"],
                "host": machine.get("host", ""),
                "address": machine.get("address", ""),
                **{key: value for key, value in fields.items() if value not in (None, "", [])},
            }
        )

    def _on_hello(self, machine, message, now, is_new, was_silent) -> None:
        status = message["data"].get("status") or proto.STATUS_UNKNOWN
        machine["status"] = status
        if is_new or was_silent:
            self._event(ONLINE, machine, now, status=status, signed=message["signed"])
        if status == proto.STATUS_HEALTHY and machine.get("open_incident"):
            # The resolved event was lost, or never sent. Close on the heartbeat's
            # word, and say so in the log.
            self._close_incident(machine, now, inferred=True, data={})

    def _on_incident(self, machine, message, now) -> None:
        data = message["data"]
        previous = machine.get("open_incident")
        machine["status"] = proto.STATUS_INCIDENT
        machine["incidents_total"] = machine.get("incidents_total", 0) + 1
        machine["open_incident"] = {
            "since": _iso(now),
            "since_epoch": now,
            "classification": data.get("classification", ""),
            "steps": data.get("steps", []),
            "recheck_ok": data.get("recheck_ok"),
            "escalated": data.get("escalated"),
            "occurred_at": data.get("occurred_at", ""),
        }
        self._event(
            INCIDENT,
            machine,
            now,
            classification=data.get("classification"),
            steps=data.get("steps"),
            steps_omitted=data.get("steps_omitted"),
            recheck_ok=data.get("recheck_ok"),
            external_reachable=data.get("external_reachable"),
            dns_ok=data.get("dns_ok"),
            escalated=data.get("escalated"),
            occurred_at=data.get("occurred_at"),
            replaced_open_incident=bool(previous) or None,
        )

    def _on_resolved(self, machine, message, now) -> None:
        self._close_incident(machine, now, inferred=False, data=message["data"])

    def _close_incident(self, machine, now, inferred: bool, data: dict[str, Any]) -> None:
        opened = machine.get("open_incident") or {}
        machine["status"] = proto.STATUS_HEALTHY
        duration = data.get("duration_seconds")
        if duration is None and opened.get("since_epoch") is not None:
            duration = round(now - opened["since_epoch"], 1)
        steps = data.get("steps") or opened.get("steps") or []
        machine["open_incident"] = None
        machine["last_incident"] = {
            "classification": opened.get("classification") or data.get("classification", ""),
            "since": opened.get("since", ""),
            "resolved": _iso(now),
            "duration_seconds": duration,
            "steps": steps,
            "inferred": inferred,
        }
        self._event(
            RESOLVED,
            machine,
            now,
            classification=machine["last_incident"]["classification"],
            duration_seconds=duration,
            steps=steps,
            recovery=data.get("recovery")
            or ("inferred from a healthy heartbeat" if inferred else None),
            inferred=inferred or None,
        )

    # --- silence -----------------------------------------------------------

    def sweep(self) -> list[str]:
        """Mark machines not heard from for `stale_seconds`. Returns their ids."""
        now = self.now_fn()
        newly_silent = []
        for machine in self.machines.values():
            last = machine.get("last_seen_epoch")
            if last is None or machine.get("silent") or now - last <= self.stale_seconds:
                continue
            machine["silent"] = True
            newly_silent.append(machine["id"])
            self._event(
                SILENT,
                machine,
                now,
                last_seen=machine.get("last_seen"),
                last_status=machine.get("status"),
                open_incident=bool(machine.get("open_incident")) or None,
            )
        if newly_silent:
            self.save()
        return newly_silent


# --- reading and rendering ----------------------------------------------------


def read_state(state_path: str) -> dict[str, Any]:
    try:
        with open(os.path.expanduser(state_path), encoding="utf-8") as handle:
            state = json.load(handle)
    except (OSError, ValueError):
        return {"machines": {}, "refused": {}}
    return state if isinstance(state, dict) else {"machines": {}, "refused": {}}


def read_events(log_path: str, limit: int = 50) -> list[dict[str, Any]]:
    """The last `limit` events, oldest first. A damaged line is skipped."""
    try:
        with open(os.path.expanduser(log_path), encoding="utf-8", errors="replace") as handle:
            lines = deque(handle, maxlen=max(1, limit))
    except OSError:
        return []
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def machine_status(machine: dict[str, Any], now: float, stale_seconds: float) -> str:
    """The word shown for a machine: incident, silent, healthy or unknown.

    An open incident wins over silence -- a machine that went quiet mid-incident
    is the worst case, and "silent" alone would hide that it was already down.
    """
    last = machine.get("last_seen_epoch")
    silent = machine.get("silent") or last is None or now - last > stale_seconds
    if machine.get("open_incident"):
        return "incident (silent)" if silent else "incident"
    if silent:
        return "silent"
    return str(machine.get("status") or proto.STATUS_UNKNOWN)


def _steps_text(steps) -> str:
    if not steps:
        return "no steps recorded"
    return "; ".join(f"{step.get('name', '?')}: {step.get('outcome', '')}" for step in steps)


def render_fleet(state: dict[str, Any], now: float, stale_seconds: float = 900.0) -> str:
    machines = sorted(
        (state.get("machines") or {}).values(),
        key=lambda machine: (machine.get("host") or "", machine.get("id") or ""),
    )
    if not machines:
        return "No machines have reported yet."
    lines = []
    problems = [m for m in machines if machine_status(m, now, stale_seconds) != "healthy"]
    lines.append(f"{len(machines)} machine(s) known; {len(problems)} not healthy.")
    lines.append("")
    for machine in machines:
        status = machine_status(machine, now, stale_seconds)
        lines.append(
            f"{machine.get('host') or '?'} ({machine.get('address') or '?'})  [{status}]  "
            f"last heard {machine.get('last_seen', 'never')}"
        )
        opened = machine.get("open_incident")
        if opened:
            lines.append(
                f"    PROBLEM since {opened.get('since')}: {opened.get('classification') or '?'}"
            )
            lines.append(f"    steps run: {_steps_text(opened.get('steps'))}")
            if opened.get("recheck_ok") is False:
                lines.append("    the recheck after those steps still failed")
        last = machine.get("last_incident")
        if last:
            how = " (closed from a heartbeat, not reported)" if last.get("inferred") else ""
            lines.append(
                f"    last incident: {last.get('classification') or '?'}, "
                f"{last.get('since')} to {last.get('resolved')}, "
                f"{last.get('duration_seconds')}s{how}"
            )
            lines.append(f"    steps run: {_steps_text(last.get('steps'))}")
    refused = state.get("refused") or {}
    if refused:
        lines.append("")
        lines.append(
            "Refused datagrams: "
            + ", ".join(f"{key}={value}" for key, value in sorted(refused.items()))
        )
    return "\n".join(lines)


def render_events(events: list[dict[str, Any]]) -> str:
    if not events:
        return "No events logged yet."
    lines = []
    for event in events:
        head = f"{event.get('at')}  {event.get('host') or event.get('machine_id')}  {event.get('kind')}"
        detail = []
        if event.get("classification"):
            detail.append(str(event["classification"]))
        if event.get("duration_seconds") is not None:
            detail.append(f"{event['duration_seconds']}s")
        if event.get("inferred"):
            detail.append("inferred from heartbeat")
        lines.append(head + (f"  ({', '.join(detail)})" if detail else ""))
        if event.get("steps"):
            lines.append(f"    steps: {_steps_text(event['steps'])}")
    return "\n".join(lines)
