"""The reporting side of fleet monitoring: send this machine's events to the
central server and keep trying until it acknowledges them.

**Why an outbox.** An incident is declared at the moment the network is broken,
so the first send very often cannot get out. Every incident and resolved event
therefore waits in a bounded in-memory outbox and is re-sent, oldest first, on
every pass of the worker until the server acks it. A pass stops at the first
failure: if the oldest event cannot be delivered, the network is still down and
the rest would fail the same way. The oldest event is dropped, and counted, only
when the outbox is full -- a machine offline for days must not grow without
bound.

Heartbeats (`hello`) are not queued. A heartbeat is only worth anything while it
is fresh, so one that could not be sent is replaced by the next, never replayed.

**Re-signed per attempt.** The protocol's signed timestamp is the send time (see
fleet_protocol.py), so a report held through a long outage is still accepted when
it finally gets through. The event's real time travels as `occurred_at`.

**Never raises into the monitor.** Everything that touches the network is inside
`_deliver`, and the worker catches the rest. A reporting failure is data
(`last_error`, `dropped`), not an exception: the monitor's job is the network,
not the reporter.

**What is sent.** Classification, the names and verbatim outcomes of the ladder
steps (redacted with `sensitive_strings`), and booleans. No probe results, no
log excerpts, no report path, no credential. See CLAUDE.md non-negotiable 6.
"""

import contextlib
import socket
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from typing import Any, Optional

from netdnsmonitor import fleet_protocol as proto

DEFAULT_PORT = 45738
MAX_OUTBOX = 100
ACK_TIMEOUT_SECONDS = 2.0
SEND_ATTEMPTS = 2


def default_transport(payload: bytes, targets: list[str], port: int, timeout: float) -> list[bytes]:
    """Send `payload` to each target and return every datagram that came back.

    One short-lived socket per exchange, bound to an ephemeral port, so the
    server's unicast ack finds its way back even when the request went out as a
    broadcast. A target that cannot be reached is skipped: a down interface still
    lists a broadcast address.
    """
    replies: list[bytes] = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sent = 0
        for address in targets:
            try:
                sock.sendto(payload, (address, port))
                sent += 1
            except (OSError, UnicodeError, OverflowError):
                continue
        if not sent:
            return replies
        try:
            data, _ = sock.recvfrom(proto.MAX_RECEIVE_BYTES)
        except OSError:  # socket.timeout is an OSError: no ack arrived in time
            return replies
        replies.append(data)
    finally:
        with contextlib.suppress(OSError):
            sock.close()
    return replies


class FleetReporter:
    def __init__(
        self,
        machine_id: str,
        host: str,
        server_address: str = "",
        port: int = DEFAULT_PORT,
        secret: Optional[str] = None,
        redact_fn: Callable[[str], str] = lambda text: text,
        status_fn: Callable[[], str] = lambda: proto.STATUS_UNKNOWN,
        heartbeat_seconds: float = 300.0,
        now_fn: Callable[[], float] = time.time,
        transport: Callable[..., list[bytes]] = default_transport,
        broadcast_fn: Optional[Callable[[], list[str]]] = None,
        version: str = "",
    ):
        self.machine_id = machine_id
        self.host = host
        self.server_address = (server_address or "").strip()
        self.port = port
        self.secret = secret or None
        self.redact_fn = redact_fn
        self.status_fn = status_fn
        self.heartbeat_seconds = heartbeat_seconds
        self.now_fn = now_fn
        self.transport = transport
        self.version = version
        if broadcast_fn is None:
            from netdnsmonitor.peer_net import broadcast_addresses

            broadcast_fn = broadcast_addresses
        self.broadcast_fn = broadcast_fn
        self.outbox: deque = deque()
        self.dropped = 0
        self.delivered = 0
        self.last_error: Optional[str] = None
        self.last_delivery_at: Optional[float] = None
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._next_heartbeat_at = 0.0

    # --- what to send ------------------------------------------------------

    def incident(self, report: dict, escalated: Optional[bool] = None) -> None:
        """Queue the declared incident. The ladder has already run by now, so the
        steps it took are part of this event; the recovery follows as `resolved`.
        """
        data = {
            "status": proto.STATUS_INCIDENT,
            "classification": self._safe(report.get("classification", "unknown")),
            "occurred_at": self._safe(report.get("started_at") or ""),
            "recheck_ok": _tristate(report.get("recheck_ok")),
            "steps": proto.step_summaries(report.get("ladder_results"), self.redact_fn),
            "escalated": bool(report.get("escalation")) if escalated is None else escalated,
        }
        probe = report.get("probe_results") or {}
        data["external_reachable"] = _tristate(probe.get("external_reachable"))
        data["dns_ok"] = _tristate(probe.get("dns_ok"))
        self._enqueue(proto.INCIDENT, data)

    def resolved(
        self,
        classification: str,
        duration_seconds: Optional[float],
        steps: Optional[list] = None,
        occurred_at: str = "",
    ) -> None:
        """Queue the recovery.

        Says the network recovered and lists the steps that had run, with their
        outcomes. It does not say a step fixed it: the gate clears an incident on
        consecutive healthy probes, which is what happened, and a transient fault
        clears the same way.
        """
        data: dict[str, Any] = {
            "status": proto.STATUS_HEALTHY,
            "classification": self._safe(classification),
            "recovery": "network recovered; no step is credited",
            "occurred_at": self._safe(occurred_at),
            "steps": proto.step_summaries(steps, self.redact_fn),
        }
        if duration_seconds is not None:
            data["duration_seconds"] = max(0.0, float(duration_seconds))
        self._enqueue(proto.RESOLVED, data)

    def _safe(self, text) -> str:
        return proto.clean(self.redact_fn(str(text)))

    def _enqueue(self, kind: str, data: dict) -> None:
        with self._lock:
            if len(self.outbox) >= MAX_OUTBOX:
                self.outbox.popleft()
                self.dropped += 1
            self.outbox.append((kind, uuid.uuid4().hex[:16], data))
        self._wake.set()

    # --- delivery ----------------------------------------------------------

    def targets(self) -> list[str]:
        """The configured server, or every broadcast address when none is set."""
        if self.server_address:
            return [self.server_address]
        try:
            return list(self.broadcast_fn())
        except Exception:  # noqa: BLE001 - no address is a delivery failure, not a crash
            return []

    def _deliver(self, kind: str, event_id: str, data: dict) -> bool:
        targets = self.targets()
        if not targets:
            self.last_error = "no server address and no broadcast address"
            return False
        for _ in range(SEND_ATTEMPTS):
            try:
                payload = proto.build_message(
                    kind, self.machine_id, self.host, event_id, self.now_fn(), data, self.secret
                )
                replies = self.transport(payload, targets, self.port, ACK_TIMEOUT_SECONDS)
            except Exception as exc:  # noqa: BLE001 - reported as data, never raised
                self.last_error = type(exc).__name__
                continue
            for reply in replies:
                message, _reason = proto.parse_message(
                    reply, self.now_fn(), self.secret, allow_unsigned=not self.secret
                )
                if message and message["t"] == proto.ACK and message["eid"] == event_id:
                    self.last_error = None
                    self.last_delivery_at = self.now_fn()
                    self.delivered += 1
                    return True
            self.last_error = "no acknowledgement from the server"
        return False

    def flush(self) -> int:
        """Send queued events oldest first. Stops at the first failure."""
        sent = 0
        while True:
            with self._lock:
                if not self.outbox:
                    break
                kind, event_id, data = self.outbox[0]
            if not self._deliver(kind, event_id, data):
                break
            with self._lock:
                # Only the head we sent: the outbox may have rotated meanwhile.
                if self.outbox and self.outbox[0][1] == event_id:
                    self.outbox.popleft()
            sent += 1
        return sent

    def heartbeat(self) -> bool:
        # Passed through, not coerced: a monitor that has not probed yet is
        # "unknown", and reporting that as "healthy" would be a claim.
        data: dict[str, Any] = {"status": proto.clean(self.status_fn(), 32)}
        if self.version:
            data["version"] = self.version
        return self._deliver(proto.HELLO, uuid.uuid4().hex[:16], data)

    def pending(self) -> int:
        with self._lock:
            return len(self.outbox)

    # --- worker ------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="fleet-reporter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush()
                now = time.monotonic()
                if now >= self._next_heartbeat_at:
                    self.heartbeat()
                    self._next_heartbeat_at = now + self.heartbeat_seconds
            except Exception as exc:  # noqa: BLE001 - the reporter must outlive any one pass
                self.last_error = type(exc).__name__
            # A queued event wakes the worker at once; otherwise it sleeps until
            # the next heartbeat, but never longer than a minute so an outbox
            # that failed to send is retried promptly after the network returns.
            wait = max(1.0, min(60.0, self._next_heartbeat_at - time.monotonic()))
            if self.outbox:
                wait = min(wait, 15.0)
            self._wake.wait(wait)
            self._wake.clear()


def _tristate(value) -> Optional[bool]:
    return value if isinstance(value, bool) else None
