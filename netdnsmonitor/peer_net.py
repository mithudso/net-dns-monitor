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
open a discovery socket has its priorities backwards. The port is not shared
(no SO_REUSEPORT; see start()), so a second copy on the same machine lands in
this case rather than binding a port it would never hear pongs on.

**What this discloses.** Any host that can reach the port can learn this
machine's hostname and whether its network is currently healthy. That is the
point of the feature, but it is a disclosure, so it is gated on
`peer_discovery_enabled` and can be turned off in the config. The socket binds
every interface, so the listener drops any sender outside the IPv4 subnets
attached to this machine's interfaces (loopback is always allowed). That limits
who is recorded and who is sent a pong. It is not authentication: UDP source
addresses can be forged.

**What this trusts.** Messages are not authenticated. A sender on the local
subnet can claim any id, including a known peer's, and report any status,
`ext` and `dns`. Those values are stored and used by fault localization as
reported. Received packets are parsed defensively (size cap, JSON only,
protocol tag checked, every string sanitised by peers.py) and nothing in a
packet is ever used as a path, a command, or an argument.
"""

import contextlib
import ipaddress
import json
import socket
import subprocess
import threading
import time
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

# How long the listener trusts its list of local subnets. Interfaces change (a
# Wi-Fi join, a DHCP renewal, a VPN), so the list is re-read, but never per
# datagram: the port is reachable by anything on the network, and a flood of
# packets must not become a flood of ifconfig subprocesses.
LOCAL_NETWORKS_TTL_SECONDS = 60.0
# A sender outside the known subnets triggers an early re-read, so a network
# that has just come up is not ignored for a whole minute -- but at most this
# often, for the same reason.
LOCAL_NETWORKS_MISS_REFRESH_SECONDS = 5.0


def build_message(
    kind: str,
    self_id: str,
    host: str,
    status: str,
    port: int,
    external_reachable=None,
    dns_ok=None,
) -> bytes:
    """Encode one message.

    `external_reachable` and `dns_ok` are what make peer-assisted fault
    localization possible -- a peer's three-state `status` says it is unhappy but
    not at which layer. They are omitted when unknown rather than sent as false,
    and added WITHOUT bumping the protocol tag: a receiver running the older build
    ignores unknown keys, and a newer receiver treats absence as "did not say",
    which localize.py handles as a distinct case from "said no".
    """
    message = {
        "proto": PROTOCOL,
        "t": kind,
        "id": self_id,
        "host": host,
        "status": status,
        "port": port,
    }
    if external_reachable is not None:
        message["ext"] = bool(external_reachable)
    if dns_ok is not None:
        message["dns"] = bool(dns_ok)
    return json.dumps(message).encode("utf-8")


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
        # Absent means "did not say", which is not the same as False.
        "external_reachable": _tristate(message.get("ext")),
        "dns_ok": _tristate(message.get("dns")),
    }


def _tristate(value):
    """None when absent, a real bool otherwise.

    Coerced rather than passed through: this comes off the network, and a JSON
    string "false" is truthy in Python -- which would invert a fault-localization
    verdict and send someone to reboot the wrong thing.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return bool(value)


def broadcast_addresses(run_fn: Callable = subprocess.run) -> list:
    """Per-interface broadcast addresses, from ifconfig.

    Subnet broadcast (192.168.1.255) rather than only the limited broadcast
    address: 255.255.255.255 is dropped by some interfaces and configurations,
    and sending to both costs one extra datagram every five minutes. Absolute path
    for explicitness, as everywhere else here; see ping.py for why.
    """
    addresses = []
    try:
        for line in (_ifconfig_output(run_fn) or "").splitlines():
            fields = line.split()
            if "broadcast" in fields:
                candidate = fields[fields.index("broadcast") + 1]
                if candidate not in addresses:
                    addresses.append(candidate)
    except IndexError:
        pass
    if FALLBACK_BROADCAST not in addresses:
        addresses.append(FALLBACK_BROADCAST)
    return addresses


def local_networks(run_fn: Callable = subprocess.run) -> Optional[list]:
    """The IPv4 subnets attached to this machine's interfaces, from ifconfig.

    None when ifconfig cannot be read. That means "unknown", not "no subnets":
    the listener treats None as "accept the sender" so that an unreadable
    ifconfig does not switch discovery off without a word.
    """
    output = _ifconfig_output(run_fn)
    if output is None:
        return None
    networks = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 2 or fields[0] != "inet" or "netmask" not in fields:
            continue
        try:
            # macOS prints the mask as hex ("netmask 0xffffff00"). A point-to-point
            # line ("inet A --> B netmask ...") still has the local address second.
            mask = ipaddress.IPv4Address(int(fields[fields.index("netmask") + 1], 16))
            network = ipaddress.IPv4Network(f"{fields[1]}/{mask}", strict=False)
        except (IndexError, ValueError):
            continue
        if network not in networks:
            networks.append(network)
    return networks


def _ifconfig_output(run_fn: Callable) -> Optional[str]:
    try:
        result = run_fn(
            [IFCONFIG_BIN],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (subprocess.SubprocessError, OSError, UnicodeError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout or ""


class PeerNetwork:
    """Owns the socket and the reader thread.

    Registry updates happen on the reader thread; PeerRegistry takes its own lock
    for them. `on_change` is also called on the reader thread, so the app's
    callback only sets a flag and does its file writing on the main thread.
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
        state_fn: Optional[Callable[[], dict]] = None,
        local_networks_fn: Optional[Callable[[], Optional[list]]] = None,
    ):
        self.registry = registry
        self.host = host
        self.bind_port = bind_port
        # Normally the same port; separable so the tests can run two instances
        # over loopback instead of broadcasting onto a real network.
        self.send_port = send_port or bind_port
        self.status_fn = status_fn
        # Returns {"external_reachable": ..., "dns_ok": ...} for what we advertise
        # about our own connectivity. Default says nothing, which peers read as
        # "did not say" rather than as a denial.
        self.state_fn = state_fn or (lambda: {})
        self.broadcast_fn = broadcast_fn
        self.on_change = on_change
        self.socket: Optional[socket.socket] = None
        self.thread: Optional[threading.Thread] = None
        self.started = False
        self.start_error: Optional[str] = None
        self._stop = threading.Event()
        self._awaiting_pong: set = set()
        self._lock = threading.Lock()
        # Looked up on the module at call time rather than bound as a default, so
        # a test can substitute it the same way it substitutes broadcast_addresses.
        self.local_networks_fn = local_networks_fn or (lambda: local_networks())
        self._networks: Optional[list] = None
        self._networks_read_at: Optional[float] = None
        # Pause after a receive error before reading again. An attribute so the
        # tests can drive the reader loop without real sleeps.
        self.read_error_backoff_seconds = 1.0

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> bool:
        """Bind and start listening. False if discovery could not start.

        Never raises. A monitor that refuses to run because a UDP port was busy
        would be worse than one running without peer discovery.
        """
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # SO_REUSEPORT is deliberately not set. With it, a second copy on this
            # machine (a dev run beside the installed app) binds the same port,
            # but macOS hands each unicast datagram to only one of the two
            # sockets: over loopback, 5 of 5 went to the first-bound socket and
            # none to the second. The second copy never hears its pongs, every
            # peer looks silent, and during an outage fault localization blames
            # this machine's own link. Without it, the second wildcard bind fails
            # with EADDRINUSE (SO_REUSEADDR alone does not allow it on Darwin),
            # and that copy runs with discovery off and gives no peer verdict.
            sock.bind(("", self.bind_port))
            # Read back, because a bind to port 0 gets a kernel-assigned port and
            # the advertised port and the default send port must be the real one.
            self.bind_port = sock.getsockname()[1]
            if not self.send_port:
                self.send_port = self.bind_port
            # So the reader wakes up regularly enough to notice _stop.
            sock.settimeout(1.0)
        except (OSError, OverflowError, ValueError, TypeError) as exc:
            # The three non-OSError cases are not hypothetical: `peer_port` comes
            # from a hand-editable YAML file and goes straight to bind(), where
            # 70000 raises OverflowError and the quoted "45737" that YAML happily
            # produces raises TypeError. Both were reaching the caller before a
            # test pinned them.
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()
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

    def alive(self) -> bool:
        """True while the reader thread is still running.

        `started` only records that start() succeeded. The reader thread can end
        afterwards (its socket closed under it) while `started` stays True, and a
        caller that checks only `started` never notices discovery has stopped.
        """
        return (
            self.started
            and not self._stop.is_set()
            and self.thread is not None
            and self.thread.is_alive()
        )

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
        state = self.state_fn() or {}
        payload = build_message(
            kind,
            self.registry.self_id,
            self.host,
            self.status_fn(),
            self.bind_port,
            external_reachable=state.get("external_reachable"),
            dns_ok=state.get("dns_ok"),
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
                # One byte over the cap. recvfrom() silently truncates a datagram
                # to the buffer size, so a buffer of exactly MAX_DATAGRAM hands
                # parse_message a cut-down copy that always passes its size check.
                payload, sender = self.socket.recvfrom(MAX_DATAGRAM + 1)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set() or self._socket_closed():
                    # stop() closed it, or something else did. A closed socket
                    # never delivers again, so alive() goes False and the owner
                    # can rebuild discovery.
                    return
                # Anything else (ENOBUFS, an interface going away) can pass.
                # Returning here ended discovery for the rest of the session
                # while `started` still read True.
                self._stop.wait(self.read_error_backoff_seconds)
                continue
            try:
                self._handle(payload, sender[0])
            except Exception:  # noqa: BLE001 - one bad packet must not end discovery
                traceback.print_exc()

    def _socket_closed(self) -> bool:
        if self.socket is None:
            return True
        try:
            return self.socket.fileno() < 0
        except OSError:
            return True

    def _sender_allowed(self, address: str) -> bool:
        """Is `address` inside a subnet attached to one of our interfaces?

        Reader thread only, so the cached list needs no lock.
        """
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            return False
        if ip.is_loopback:
            return True
        now = time.monotonic()
        read_at = self._networks_read_at
        refresh = read_at is None or now - read_at >= LOCAL_NETWORKS_TTL_SECONDS
        if (
            not refresh
            and self._networks is not None
            and not any(ip in network for network in self._networks)
        ):
            refresh = now - read_at >= LOCAL_NETWORKS_MISS_REFRESH_SECONDS
        if refresh:
            self._networks = self.local_networks_fn()
            self._networks_read_at = now
        if self._networks is None:
            return True
        return any(ip in network for network in self._networks)

    def _handle(self, payload: bytes, address: str) -> None:
        message = parse_message(payload)
        if message is None or not message["id"]:
            return
        if message["id"] == self.registry.self_id:
            # Our own broadcast, looped back on the same host.
            return
        # Checked after parsing, so only well-formed messages of ours can cause
        # the interface list to be re-read.
        if not self._sender_allowed(address):
            return

        self.registry.observe(
            peer_id=message["id"],
            host=message["host"],
            address=address,
            status=message["status"],
            via=message["t"],
            external_reachable=message["external_reachable"],
            dns_ok=message["dns_ok"],
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
        state = self.state_fn() or {}
        with contextlib.suppress(OSError):
            self.socket.sendto(
                build_message(
                    PONG,
                    self.registry.self_id,
                    self.host,
                    self.status_fn(),
                    self.bind_port,
                    external_reachable=state.get("external_reachable"),
                    dns_ok=state.get("dns_ok"),
                ),
                (address, self.send_port),
            )
