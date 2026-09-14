"""Peer discovery over the wire.

Two real PeerNetwork instances talk to each other over loopback with real UDP
sockets -- `broadcast_fn` is overridden to return `["127.0.0.1"]` so nothing is
ever sent onto a real network from the test suite, and the two use different
ports so they can coexist on one host.

Each instance binds port 0 and the kernel assigns the port, which is then read
back from the socket. Probing for a free port, closing it, and binding it again
later raced with a parallel test run; with SO_REUSEPORT set, two tests handed the
same port would both bind it and hear each other's traffic.
"""

import errno
import ipaddress
import json
import socket
import time

import pytest

from netdnsmonitor.peer_net import (
    ANNOUNCE,
    MAX_DATAGRAM,
    PONG,
    PROBE,
    PROTOCOL,
    PeerNetwork,
    broadcast_addresses,
    build_message,
    local_networks,
    parse_message,
)
from netdnsmonitor.peers import PeerRegistry


def connect(a: PeerNetwork, b: PeerNetwork) -> None:
    """Point two started instances at each other's kernel-assigned ports."""
    a.send_port = b.bind_port
    b.send_port = a.bind_port


def wait_for(predicate, timeout=3.0):
    """Poll until true. UDP delivery is asynchronous even over loopback, so a
    bare assert after send is a flake waiting to happen.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture
def pair():
    """Two instances pointed at each other over loopback."""
    a = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=0,
        status_fn=lambda: "healthy",
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    b = PeerNetwork(
        registry=PeerRegistry(self_id="id-b"),
        host="mac-b",
        bind_port=0,
        status_fn=lambda: "incident",
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    assert a.start(), a.start_error
    assert b.start(), b.start_error
    connect(a, b)
    yield a, b
    a.stop()
    b.stop()


# --- message encoding ------------------------------------------------------


def test_a_message_round_trips():
    parsed = parse_message(build_message(ANNOUNCE, "id-a", "mac-a", "healthy", 45737))
    assert parsed == {
        "t": ANNOUNCE,
        "id": "id-a",
        "host": "mac-a",
        "status": "healthy",
        # Not sent, so "did not say" rather than "said no" -- localize.py treats
        # those as completely different evidence.
        "external_reachable": None,
        "dns_ok": None,
    }


def test_connectivity_state_round_trips_when_it_is_known():
    """What makes peer-assisted fault localization possible: a peer's three-state
    status says it is unhappy, not at which layer.
    """
    parsed = parse_message(
        build_message(
            ANNOUNCE, "id-a", "mac-a", "incident", 45737, external_reachable=False, dns_ok=True
        )
    )
    assert parsed["external_reachable"] is False
    assert parsed["dns_ok"] is True


def test_unknown_state_is_omitted_from_the_wire_not_sent_as_false():
    """Sent as false, an older peer that cannot report would look like a peer
    asserting it has no connectivity -- and two machines "both down" is the
    signal that means an upstream outage.
    """
    import json as _json

    decoded = _json.loads(build_message(ANNOUNCE, "id-a", "mac-a", "healthy", 1).decode())
    assert "ext" not in decoded
    assert "dns" not in decoded


def test_a_string_state_off_the_wire_cannot_invert_a_verdict():
    """`"false"` is truthy in Python. Passed through unchecked it would flip a
    localization verdict and send someone to reboot the wrong thing.
    """
    payload = json.dumps(
        {"proto": PROTOCOL, "t": ANNOUNCE, "id": "x", "ext": "false", "dns": "false"}
    ).encode()
    parsed = parse_message(payload)
    assert parsed["external_reachable"] is False
    assert parsed["dns_ok"] is False


def test_an_older_peer_message_still_parses():
    """Backward compatibility is why the protocol tag was not bumped: the two new
    keys are optional and their absence is meaningful.
    """
    payload = json.dumps(
        {"proto": PROTOCOL, "t": ANNOUNCE, "id": "old-peer", "host": "h", "status": "healthy"}
    ).encode()
    parsed = parse_message(payload)
    assert parsed["id"] == "old-peer"
    assert parsed["external_reachable"] is None


def test_non_json_is_rejected():
    """This socket is reachable by anything on the LAN, including unrelated
    software that happens to use the same port.
    """
    assert parse_message(b"not json at all") is None
    assert parse_message(b"") is None
    assert parse_message(None) is None


def test_an_oversized_datagram_is_rejected_without_parsing():
    """A legitimate announce is ~200 bytes. Refusing to even parse anything
    larger caps the work a remote host can make this process do.
    """
    assert parse_message(b"x" * (MAX_DATAGRAM + 1)) is None


def test_a_message_from_another_protocol_is_rejected():
    assert parse_message(json.dumps({"proto": "something-else", "t": ANNOUNCE}).encode()) is None


def test_an_unknown_message_kind_is_rejected():
    payload = json.dumps({"proto": PROTOCOL, "t": "shutdown", "id": "x"}).encode()
    assert parse_message(payload) is None


def test_a_json_scalar_or_list_is_rejected_not_treated_as_a_message():
    assert parse_message(b"42") is None
    assert parse_message(b'["announce"]') is None


def test_fields_from_the_wire_are_sanitised_on_the_way_in():
    payload = json.dumps(
        {"proto": PROTOCOL, "t": ANNOUNCE, "id": "a" * 500, "host": "mac\n\x1bx", "status": 7}
    ).encode()
    parsed = parse_message(payload)
    assert len(parsed["id"]) == 64
    assert "\n" not in parsed["host"]
    assert parsed["status"] == "7"


# --- discovery over loopback -----------------------------------------------


def test_an_announcement_makes_two_instances_find_each_other(pair):
    a, b = pair
    a.announce()
    assert wait_for(lambda: "id-a" in b.registry.peers)
    peer = b.registry.peers["id-a"]
    assert peer["host"] == "mac-a"
    assert peer["status"] == "healthy"
    assert peer["address"] == "127.0.0.1"
    assert peer["last_seen_via"] == ANNOUNCE


def test_a_probe_is_answered_with_a_pong(pair):
    """The healthcheck heartbeat: b learns of a, probes it, and a answers."""
    a, b = pair
    a.announce()
    assert wait_for(lambda: "id-a" in b.registry.peers)

    b.probe(b.registry.addresses_to_probe())
    assert wait_for(lambda: "id-b" in a.registry.peers)  # a saw the probe
    assert wait_for(lambda: b.registry.peers["id-a"]["last_seen_via"] == PONG)


def test_a_pong_counts_as_being_heard_from(pair):
    """Liveness is recency, with no separate health flag that could disagree with
    the timestamps.
    """
    a, b = pair
    a.announce()
    assert wait_for(lambda: "id-a" in b.registry.peers)
    before = b.registry.peers["id-a"]["last_seen"]

    time.sleep(0.01)
    b.probe(b.registry.addresses_to_probe())
    assert wait_for(lambda: b.registry.peers["id-a"]["last_seen"] > before)
    assert b.registry.peers["id-a"]["missed_healthchecks"] == 0


def test_an_instance_ignores_its_own_broadcast(pair):
    """Broadcasts loop back on the sending host. Without the id check every
    instance would list itself as a peer.
    """
    a, _ = pair
    a.send_port = a.bind_port  # talk to ourselves, as a real broadcast does
    a.announce()
    time.sleep(0.3)
    assert a.registry.peers == {}


def test_peer_status_is_carried_so_a_peer_knows_the_others_health(pair):
    a, b = pair
    b.announce()
    assert wait_for(lambda: "id-b" in a.registry.peers)
    assert a.registry.peers["id-b"]["status"] == "incident"


def test_on_change_fires_when_a_peer_is_heard_from():
    """This is what repaints the dashboard's peer list."""
    calls = []
    a = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=0,
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    b = PeerNetwork(
        registry=PeerRegistry(self_id="id-b"),
        host="mac-b",
        bind_port=0,
        broadcast_fn=lambda: ["127.0.0.1"],
        on_change=lambda: calls.append(1),
    )
    assert a.start() and b.start()
    connect(a, b)
    try:
        a.announce()
        assert wait_for(lambda: calls)
    finally:
        a.stop()
        b.stop()


def test_a_silent_peer_accumulates_missed_healthchecks(pair):
    """The sweep counts a miss when a probe went out and nothing came back before
    the next sweep -- which surfaces "was here, isn't answering" before the bucket
    itself changes.
    """
    _, b = pair
    b.registry.observe("ghost", host="switched-off", address="127.0.0.1")
    # Two sweeps with nothing answering for `ghost`; port 9 discards silently.
    b.send_port = 9
    b.probe(b.registry.addresses_to_probe())
    b.probe(b.registry.addresses_to_probe())
    assert b.registry.peers["ghost"]["missed_healthchecks"] >= 1


# --- robustness ------------------------------------------------------------


def test_start_reports_failure_instead_of_raising_when_the_socket_is_refused(monkeypatch):
    """A monitor that will not start because a UDP port was unavailable has its
    priorities backwards, so this must degrade rather than raise.

    The failure is forced rather than provoked with a privileged port: binding
    UDP port 1 unprivileged actually succeeds on this machine, so that would have
    been a test asserting the local port policy instead of this code.
    """

    def refuse(*args, **kwargs):
        raise OSError("Address already in use")

    monkeypatch.setattr(socket, "socket", refuse)
    net = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=0,
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    assert net.start() is False
    assert "Address already in use" in net.start_error
    assert net.started is False


@pytest.mark.parametrize("bad_port", [70000, "45737", -1])
def test_a_nonsense_configured_port_degrades_instead_of_crashing_the_app(bad_port):
    """`peer_port` comes from a hand-editable YAML file and goes straight to
    bind(), where an out-of-range int raises OverflowError and a string raises
    TypeError-or-ValueError -- none of them OSError.
    """
    net = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=bad_port,
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    assert net.start() is False
    assert net.started is False


def test_sending_before_start_is_a_no_op_not_a_crash():
    net = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"), host="mac-a", broadcast_fn=lambda: ["127.0.0.1"]
    )
    assert net.announce() == 0
    assert net.probe([("peer", "127.0.0.1")]) == 0


def test_an_unroutable_broadcast_address_does_not_stop_the_others(pair):
    """A down interface still lists a broadcast address, so a failed send is
    expected and must not abort the sweep.
    """
    a, b = pair
    a.broadcast_fn = lambda: ["203.0.113.255", "127.0.0.1"]
    a.announce()
    assert wait_for(lambda: "id-a" in b.registry.peers)


def test_garbage_on_the_port_does_not_kill_the_listener(pair):
    """One malformed packet must not end discovery for the life of the process."""
    a, b = pair
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as junk:
        junk.sendto(b"\x00\x01garbage not json", ("127.0.0.1", b.bind_port))
        junk.sendto(b"x" * (MAX_DATAGRAM * 2), ("127.0.0.1", b.bind_port))
    time.sleep(0.2)

    a.announce()
    assert wait_for(lambda: "id-a" in b.registry.peers)


def test_stop_is_idempotent(pair):
    a, _ = pair
    a.stop()
    a.stop()
    assert a.started is False


def test_broadcast_addresses_always_offer_a_fallback():
    """If ifconfig cannot be read, the limited broadcast address is still worth
    trying rather than giving up on discovery entirely.
    """

    def failing_run(*args, **kwargs):
        raise OSError("no ifconfig here")

    assert broadcast_addresses(run_fn=failing_run) == ["255.255.255.255"]


def test_broadcast_addresses_parses_real_ifconfig_output():
    class Result:
        returncode = 0
        stdout = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n"
            "\tinet 127.0.0.1 netmask 0xff000000\n"
        )
        stderr = ""

    addresses = broadcast_addresses(run_fn=lambda *a, **k: Result())
    assert addresses[0] == "192.168.1.255"
    assert "255.255.255.255" in addresses


def test_broadcast_addresses_are_deduplicated():
    class Result:
        returncode = 0
        stdout = (
            "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "\tinet 192.168.1.43 netmask 0xffffff00 broadcast 192.168.1.255\n"
        )
        stderr = ""

    assert broadcast_addresses(run_fn=lambda *a, **k: Result()).count("192.168.1.255") == 1


def test_a_truncated_ifconfig_line_does_not_raise():
    """`broadcast` as the final token with no address after it."""

    class Result:
        returncode = 0
        stdout = "\tinet 192.168.1.42 netmask 0xffffff00 broadcast\n"
        stderr = ""

    assert broadcast_addresses(run_fn=lambda *a, **k: Result()) == ["255.255.255.255"]


def test_probe_and_pong_use_the_declared_protocol_tag():
    """A version tag on every message is what lets a future format change ignore
    this one instead of misreading it.
    """
    for kind in (ANNOUNCE, PROBE, PONG):
        decoded = json.loads(build_message(kind, "id", "host", "status", 1).decode())
        assert decoded["proto"] == PROTOCOL


# --- the port --------------------------------------------------------------


def test_binding_port_zero_reads_the_assigned_port_back(pair):
    """The advertised port and the default send port must be the real one, not
    the 0 that was asked for.
    """
    a, b = pair
    assert a.bind_port > 0 and b.bind_port > 0
    assert a.bind_port != b.bind_port


# --- oversized datagrams ---------------------------------------------------


def test_an_oversized_datagram_that_starts_with_a_valid_message_is_dropped(pair):
    """recvfrom() with a buffer of exactly MAX_DATAGRAM truncated a larger
    datagram to fit, so the size check never saw anything too big. A valid
    announce padded past the cap was cut back to valid JSON and registered.
    """
    _, b = pair
    oversized = build_message(ANNOUNCE, "padded", "h", "healthy", 1) + b" " * 5000
    assert len(oversized) > MAX_DATAGRAM
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(oversized, ("127.0.0.1", b.bind_port))
        sender.sendto(
            build_message(ANNOUNCE, "marker", "h", "healthy", 1), ("127.0.0.1", b.bind_port)
        )
    assert wait_for(lambda: "marker" in b.registry.peers)
    assert "padded" not in b.registry.peers


def test_a_datagram_of_exactly_the_cap_is_still_accepted(pair):
    _, b = pair
    message = build_message(ANNOUNCE, "at-cap", "h", "healthy", 1)
    exact = message + b" " * (MAX_DATAGRAM - len(message))
    assert len(exact) == MAX_DATAGRAM
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(exact, ("127.0.0.1", b.bind_port))
    assert wait_for(lambda: "at-cap" in b.registry.peers)


# --- the listener's life ---------------------------------------------------


class ScriptedSocket:
    """Stands in for the UDP socket so the reader loop can be driven in order."""

    def __init__(self, script, on_exhausted):
        self.script = list(script)
        self.on_exhausted = on_exhausted
        self.sent = []
        self.closed = False
        self.buffer_sizes = []

    def recvfrom(self, size):
        self.buffer_sizes.append(size)
        if not self.script:
            self.on_exhausted()
            raise TimeoutError("timed out")
        step = self.script.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    def sendto(self, payload, address):
        self.sent.append((payload, address))
        return len(payload)

    def fileno(self):
        return -1 if self.closed else 7


def scripted_network(script, **kwargs):
    net = PeerNetwork(
        registry=PeerRegistry(self_id="me"),
        host="mac",
        bind_port=1,
        broadcast_fn=lambda: ["127.0.0.1"],
        **kwargs,
    )
    net.read_error_backoff_seconds = 0
    net.socket = ScriptedSocket(script, on_exhausted=net._stop.set)
    return net


def test_a_transient_socket_error_does_not_end_discovery():
    """An ENOBUFS from recvfrom() used to return from the reader thread for good,
    while `started` stayed True -- discovery was silently off for the rest of
    the session and nothing restarted it.
    """
    announce = build_message(ANNOUNCE, "peer-a", "mac-a", "healthy", 1)
    net = scripted_network(
        [OSError(errno.ENOBUFS, "No buffer space available"), (announce, ("127.0.0.1", 1))]
    )
    net._read_loop()
    assert "peer-a" in net.registry.peers


def test_the_reader_stops_when_its_socket_has_been_closed():
    """A closed socket will never deliver again, so retrying it once a second
    forever would only hide that the listener is dead.
    """
    net = scripted_network([OSError(errno.EBADF, "Bad file descriptor")] * 1000)
    net.socket.closed = True
    net._read_loop()
    assert len(net.socket.buffer_sizes) == 1


def test_alive_tracks_the_listener_thread_not_the_started_flag(pair):
    """The owner can only rebuild discovery if it can tell the listener has died,
    and `started` records only that start() once succeeded.
    """
    a, _ = pair
    assert a.alive() is True
    a.socket.close()
    assert wait_for(lambda: not a.alive(), timeout=5.0)


def test_alive_is_false_before_start_and_after_stop(pair):
    a, _ = pair
    a.stop()
    assert a.alive() is False
    never_started = PeerNetwork(registry=PeerRegistry(self_id="x"), host="h", bind_port=0)
    assert never_started.alive() is False


def test_the_reader_asks_for_one_byte_more_than_the_cap():
    net = scripted_network([])
    net._read_loop()
    assert net.socket.buffer_sizes == [MAX_DATAGRAM + 1]


# --- who may talk to us ----------------------------------------------------


LAN = [ipaddress.IPv4Network("192.168.1.0/24")]


def test_a_probe_from_off_the_local_subnet_is_neither_recorded_nor_answered():
    """The socket binds every interface. Without this check a host beyond the LAN
    that can reach the port could register itself, be probed on every sweep, and
    make this machine send pongs to any address it names.
    """
    net = scripted_network([], local_networks_fn=lambda: LAN)
    net._handle(build_message(PROBE, "outsider", "evil", "healthy", 1), "203.0.113.7")
    assert net.registry.peers == {}
    assert net.socket.sent == []


def test_a_probe_from_the_local_subnet_is_recorded_and_answered():
    net = scripted_network([], local_networks_fn=lambda: LAN)
    net._handle(build_message(PROBE, "neighbour", "mac-b", "healthy", 1), "192.168.1.20")
    assert "neighbour" in net.registry.peers
    assert [address for _, address in net.socket.sent] == [("192.168.1.20", 1)]


def test_loopback_is_always_accepted_without_reading_the_interfaces():
    calls = []
    net = scripted_network([], local_networks_fn=lambda: calls.append(1) or LAN)
    net._handle(build_message(ANNOUNCE, "same-host", "mac", "healthy", 1), "127.0.0.1")
    assert "same-host" in net.registry.peers
    assert calls == []


def test_a_malformed_sender_address_is_dropped():
    net = scripted_network([], local_networks_fn=lambda: LAN)
    net._handle(build_message(ANNOUNCE, "weird", "h", "healthy", 1), "not-an-address")
    assert net.registry.peers == {}


def test_unreadable_interfaces_leave_the_sender_check_open():
    """If ifconfig cannot be read the local subnets are unknown, not empty.
    Treating unknown as "nothing is local" would switch discovery off silently.
    """
    net = scripted_network([], local_networks_fn=lambda: None)
    net._handle(build_message(ANNOUNCE, "peer", "h", "healthy", 1), "10.0.0.5")
    assert "peer" in net.registry.peers


def test_interfaces_are_not_reread_for_every_datagram():
    """The listener is reachable by anything on the network; a flood of packets
    from outside must not become a flood of ifconfig subprocesses.
    """
    calls = []
    net = scripted_network([], local_networks_fn=lambda: calls.append(1) or LAN)
    for index in range(50):
        net._handle(build_message(ANNOUNCE, f"x{index}", "h", "healthy", 1), "203.0.113.7")
    assert len(calls) == 1


def test_local_networks_parses_ifconfig_inet_and_netmask():
    class Result:
        returncode = 0
        stdout = (
            "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
            "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n"
            "\tinet 192.168.1.42 netmask 0xffffff00 broadcast 192.168.1.255\n"
            "utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380\n"
            "\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffff00\n"
            "\tinet 172.16.0.9 netmask garbage\n"
            "\tinet 172.16.0.10\n"
        )
        stderr = ""

    networks = local_networks(run_fn=lambda *a, **k: Result())
    assert ipaddress.IPv4Network("192.168.1.0/24") in networks
    assert ipaddress.IPv4Network("10.8.0.0/24") in networks
    assert len(networks) == 2


def test_local_networks_is_none_when_ifconfig_cannot_be_read():
    def failing_run(*args, **kwargs):
        raise OSError("no ifconfig here")

    assert local_networks(run_fn=failing_run) is None
