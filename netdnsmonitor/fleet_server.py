"""The central server: listen for fleet reports on the local network, log them.

Binds a UDP port on every interface, so it hears both a machine that unicasts to
its address and one that broadcasts to the subnet (a machine with no configured
server address does the latter). Each accepted event is acknowledged with a
signed `ack`; a refused datagram gets no reply, so the port tells a scanner
nothing.

**The listener never raises.** A bad packet is counted by reason in the store
and dropped. The reader thread survives a receive error the way peer_net's does:
it ends only when the socket is closed under it, and `alive()` then goes False so
the owner can rebuild it.

**Trust.** Datagrams are accepted only when their HMAC verifies against the
shared secret (see fleet_protocol.py). With no secret configured the server
refuses everything unless `allow_unsigned` is set, in which case any host on the
network can claim any machine id -- a trial setting, not a deployment.

**Silence detection** runs on the same thread: the read timeout is short, and
each time it fires the store is swept for machines not heard from.
"""

import contextlib
import socket
import threading
import time
import traceback
from typing import Callable, Optional

from netdnsmonitor import fleet_protocol as proto
from netdnsmonitor.fleet_store import FleetStore

SWEEP_SECONDS = 30.0


class FleetServer:
    def __init__(
        self,
        store: FleetStore,
        port: int = 45738,
        secret: Optional[str] = None,
        allow_unsigned: bool = False,
        now_fn: Callable[[], float] = time.time,
        bind_host: str = "",
    ):
        self.store = store
        self.port = port
        self.secret = secret or None
        self.allow_unsigned = allow_unsigned
        self.now_fn = now_fn
        self.bind_host = bind_host
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.started = False
        self.start_error: Optional[str] = None
        self._stop = threading.Event()
        self._swept_at = 0.0

    def start(self) -> bool:
        """Bind and listen. False if the port could not be opened; never raises."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            # No SO_REUSEPORT, for the reason peer_net.start gives: two servers
            # sharing a port would each see only some of the datagrams.
            sock.bind((self.bind_host, self.port))
            self.port = sock.getsockname()[1]
            sock.settimeout(1.0)
        except (OSError, OverflowError, ValueError, TypeError) as exc:
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()
            self.start_error = f"{type(exc).__name__}: {exc}"
            return False
        self.socket = sock
        self._stop.clear()
        self.thread = threading.Thread(target=self._read_loop, name="fleet-server", daemon=True)
        self.thread.start()
        self.started = True
        return True

    def stop(self) -> None:
        self._stop.set()
        if self.socket is not None:
            with contextlib.suppress(OSError):
                self.socket.close()
        self.started = False

    def alive(self) -> bool:
        return (
            self.started
            and not self._stop.is_set()
            and self.thread is not None
            and self.thread.is_alive()
        )

    def _read_loop(self) -> None:
        sock = self.socket
        if sock is None:
            return
        while not self._stop.is_set():
            self._maybe_sweep()
            try:
                payload, sender = sock.recvfrom(proto.MAX_RECEIVE_BYTES + 1)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set() or sock.fileno() < 0:
                    return
                self._stop.wait(1.0)
                continue
            try:
                self.handle(payload, sender[0], sender[1])
            except Exception:  # noqa: BLE001 - one bad packet must not end the server
                traceback.print_exc()

    def _maybe_sweep(self) -> None:
        now = time.monotonic()
        if now - self._swept_at < SWEEP_SECONDS:
            return
        self._swept_at = now
        try:
            self.store.sweep()
        except Exception:  # noqa: BLE001 - an unwritable log must not end the listener
            traceback.print_exc()

    def handle(self, payload: bytes, address: str, port: int = 0) -> Optional[str]:
        """Process one datagram. Returns the store's verdict, or the refusal reason."""
        message, reason = proto.parse_message(
            payload, self.now_fn(), self.secret, self.allow_unsigned
        )
        if message is None:
            self.store.note_refused(reason or proto.REFUSED_MALFORMED)
            return reason
        if message["t"] not in proto.EVENT_KINDS:
            # An ack addressed to a server is noise.
            self.store.note_refused(proto.REFUSED_MALFORMED)
            return proto.REFUSED_MALFORMED
        verdict = self.store.record(message, address)
        if verdict in ("logged", "duplicate") and port:
            self._ack(message, address, port)
        return verdict

    def _ack(self, message: dict, address: str, port: int) -> None:
        if self.socket is None:
            return
        reply = proto.build_message(
            proto.ACK, "server", "", message["eid"], self.now_fn(), {}, self.secret
        )
        # To the datagram's source port, not this server's: the client sends from
        # an ephemeral port and listens on that same socket for the ack.
        with contextlib.suppress(OSError):
            self.socket.sendto(reply, (address, port))
