"""Announce this instance on the local network, find the others, and heartbeat
them.

**Why UDP broadcast rather than Bonjour.** NSNetService/NSNetServiceBrowser is
the idiomatic macOS answer, but it is delegate-driven and only progresses while
an AppKit run loop is turning, which makes it untestable without one and couples
peer discovery to the GUI. A single UDP port with a JSON payload is a few dozen
lines, is exercisable over loopback in the test suite, and works the same whether
a run loop exists or not.

**The protocol**, all of it:

    announce   broadcast, "I exist, here is my id, hostname and status"
    probe      unicast, "are you still there"
    pong       unicast reply to a probe

There is no notion of a leader, no shared state, and no commands. A peer can
learn another peer's hostname and monitor status and nothing else.

**Liveness is just recency.** A pong updates `last_seen` exactly as an
announcement does, so there is no separate health flag that could disagree with
the timestamps. A peer that stops answering ages out of `current` on its own.
The sweep counts a miss when a probe went out and nothing came back before the
next sweep, which is what surfaces "was here, isn't answering" before the bucket
changes.

**Nothing blocks startup.** `start()` binds the socket, spawns a daemon reader
thread, and returns. If the bind fails -- port already taken by another copy on
this machine, or a sandbox denies it -- discovery is simply off and the monitor
carries on; a network-monitoring tool that will not start because it could not
open a discovery socket has its priorities backwards.

**What this discloses.** Any host on the same LAN can learn this machine's
hostname and whether its network is currently healthy. That is the point of the
feature, but it is a disclosure, so it is gated on `peer_discovery_enabled` and
can be turned off in the config. Received packets are parsed defensively (size
cap, JSON only, protocol tag checked, every string sanitised by peers.py) and
nothing in a packet is ever used as a path, a command, or an argument.
"""

import contextlib
import json
import socket
import subprocess
import threading
import traceback
from typing import Callable, Optional

from netdnsmonitor.peers import PeerRegistry, sanitise

PROTOCOL = "ndm-peer/1"
ANNOUNCE = "announce"
PROBE = "probe"
PONG = "pong"

# Bigger than any legitimate message here (a full announce is ~200 bytes). A
# datagram larger than this is not one of ours, so it is read and dropped rather
# than parsed.
MAX_DATAGRAM = 2048

IFCONFIG_BIN = "/sbin/ifconfig"
FALLBACK_BROADCAST = "255.255.255.255"


def build_message(kind: str, self_id: str, host: str, status: str, port: int) -> bytes:
    return json.dumps(
        {
            "proto": PROTOCOL,
            "t": kind,
            "id": self_id,
            "host": host,
            "status": status,
            "port": port,
        }
    ).encode("utf-8")


def parse_message(payload: bytes) -> Optional[dict]:
    """Decode a datagram, or None if it is not a well-formed message of ours.

    Deliberately silent about malformed input: this socket is reachable by
    anything on the LAN, and logging every stray packet would hand a remote host
    control of the log file's size.
    """
    if not payload or len(payload) > MAX_DATAGRAM:
        return None
    try:
        message = json.loads(payload.decode("utf-8", errors="replace"))
    except ValueError:
        return None
    if not isinstance(message, dict) or message.get("proto") != PROTOCOL:
        return None
    kind = message.get("t")
    if kind not in (ANNOUNCE, PROBE, PONG):
        return None
    return {
        "t": kind,
        "id": sanitise(message.get("id"), 64),
        "host": sanitise(message.get("host")),
        "status": sanitise(message.get("status"), 32),
    }


def broadcast_addresses(run_fn: Callable = subprocess.run) -> list:
    """Per-interface broadcast addresses, from ifconfig.

    Subnet broadcast (192.168.1.255) rather than only the limited broadcast
    address: 255.255.255.255 is dropped by some interfaces and configurations,
    and sending to both costs one extra datagram every five minutes. Absolute
    path for the launchd PATH, same as everywhere else in this project.
    """
    addresses = []
    try:
        result = run_fn(
            [IFCONFIG_BIN],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
        if result.returncode == 0:
            for line in (result.stdout or "").splitlines():
                fields = line.split()
                if "broadcast" in fields:
                    candidate = fields[fields.index("broadcast") + 1]
                    if candidate not in addresses:
                        addresses.append(candidate)
    except (subprocess.SubprocessError, OSError, IndexError, UnicodeError):
        pass
    if FALLBACK_BROADCAST not in addresses:
        addresses.append(FALLBACK_BROADCAST)
    return addresses


class PeerNetwork:
    """Owns the socket and the reader thread. All registry updates land in
    `registry`, which is not thread-safe -- see the note on `on_change`.
    """

    def __init__(
        self,
        registry: PeerRegistry,
        host: str,
        bind_port: int = 45737,
        send_port: Optional[int] = None,
        status_fn: Callable[[], str] = lambda: "unknown",
        broadcast_fn: Callable[[], list] = broadcast_addresses,
        on_change: Optional[Callable[[], None]] = None,
    ):
        self.registry = registry
        self.host = host
        self.bind_port = bind_port
        # Normally the same port; separable so the tests can run two instances
        # over loopback instead of broadcasting onto a real network.
        self.send_port = send_port or bind_port
        self.status_fn = status_fn
        self.broadcast_fn = broadcast_fn
        self.on_change = on_change
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.started = False
        self.start_error: Optional[str] = None
        self._stop = threading.Event()
        self._awaiting_pong: set = set()
        self._lock = threading.Lock()

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        """Bind and start listening. False if discovery could not start.

        Never raises. A monitor that refuses to run because a UDP port was busy
        would be worse than one running without peer discovery.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Two copies on one machine (a dev run beside the installed app) both
            # need to receive, rather than the second one failing to bind.
            if hasattr(socket, "SO_REUSEPORT"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            sock.bind(("", self.bind_port))
            # So the reader wakes up regularly enough to notice _stop.
            sock.settimeout(1.0)
        except (OSError, OverflowError, ValueError, TypeError) as exc:
            # The three non-OSError cases are not hypothetical: `peer_port` comes
            # from a hand-editable YAML file and goes straight to bind(), where
            # 70000 raises OverflowError and the quoted "45737" that YAML happily
            # produces raises TypeError. Both were reaching the caller before a
            # test pinned them.
            self.start_error = str(exc)
            return False

        self.socket = sock
        self._stop.clear()
        self.thread = threading.Thread(target=self._read_loop, name="peer-listener", daemon=True)
        self.thread.start()
        self.started = True
        return True

    def stop(self) -> None:
        self._stop.set()
        if self.socket is not None:
            with contextlib.suppress(OSError):
                self.socket.close()
        self.started = False

    # --- sending -----------------------------------------------------------

    def announce(self) -> int:
        """Broadcast our presence. Returns how many datagrams went out."""
        return self._send_to_all(ANNOUNCE, self.broadcast_fn())

    def probe(self, addresses) -> int:
        """Unicast a probe to each known peer address, and remember we asked.

        Anything already outstanding from the previous sweep counts as a miss:
        the probe went out, the sweep came round again, nothing answered.
        """
        with self._lock:
            outstanding = set(self._awaiting_pong)
            self._awaiting_pong = {peer_id for peer_id, _ in addresses}
        for peer_id in outstanding:
            self.registry.note_healthcheck_miss(peer_id)
        return self._send_to_all(PROBE, [address for _, address in addresses])

    def _send_to_all(self, kind: str, addresses) -> int:
        if self.socket is None:
            return 0
        payload = build_message(
            kind, self.registry.self_id, self.host, self.status_fn(), self.bind_port
        )
        sent = 0
        for address in addresses:
            try:
                self.socket.sendto(payload, (address, self.send_port))
                sent += 1
            except OSError:
                # A single unroutable interface must not stop the others. Common
                # and expected: a down interface still lists a broadcast address.
                continue
        return sent

    # --- receiving ---------------------------------------------------------

    def _read_loop(self) -> None:
        while not self._stop.is_set():
            try:
                payload, sender = self.socket.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                # The socket was closed under us by stop(), or the interface
                # went away. Either way there is nothing left to read.
                return
            try:
                self._handle(payload, sender[0])
            except Exception:  # noqa: BLE001 - one bad packet must not end discovery
                traceback.print_exc()

    def _handle(self, payload: bytes, address: str) -> None:
        message = parse_message(payload)
        if message is None or not message["id"]:
            return
        if message["id"] == self.registry.self_id:
            # Our own broadcast, looped back on the same host.
            return

        self.registry.observe(
            peer_id=message["id"],
            host=message["host"],
            address=address,
            status=message["status"],
            via=message["t"],
        )
        if message["t"] in (ANNOUNCE, PONG):
            with self._lock:
                self._awaiting_pong.discard(message["id"])
        if message["t"] == PROBE:
            self._reply_pong(address)
        if self.on_change is not None:
            self.on_change()

    def _reply_pong(self, address: str) -> None:
        if self.socket is None:
            return
        with contextlib.suppress(OSError):
            self.socket.sendto(
                build_message(
                    PONG, self.registry.self_id, self.host, self.status_fn(), self.bind_port
                ),
                (address, self.send_port),
            )
