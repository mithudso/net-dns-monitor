"""Peer discovery over the wire.

Two real PeerNetwork instances talk to each other over loopback with real UDP
sockets -- `broadcast_fn` is overridden to return `["127.0.0.1"]` so nothing is
ever sent onto a real network from the test suite, and the two use different
ports so they can coexist on one host.

Ports are picked from an ephemeral range per test to avoid collisions with the
installed app (which uses the default 45737) and with a parallel test run.
"""

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
    parse_message,
)
from netdnsmonitor.peers import PeerRegistry


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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
    port_a, port_b = free_port(), free_port()
    a = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=port_a,
        send_port=port_b,
        status_fn=lambda: "healthy",
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    b = PeerNetwork(
        registry=PeerRegistry(self_id="id-b"),
        host="mac-b",
        bind_port=port_b,
        send_port=port_a,
        status_fn=lambda: "incident",
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    assert a.start(), a.start_error
    assert b.start(), b.start_error
    yield a, b
    a.stop()
    b.stop()


# --- message encoding ------------------------------------------------------


def test_a_message_round_trips():
    parsed = parse_message(build_message(ANNOUNCE, "id-a", "mac-a", "healthy", 45737))
    assert parsed == {"t": ANNOUNCE, "id": "id-a", "host": "mac-a", "status": "healthy"}


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
    port_a, port_b = free_port(), free_port()
    calls = []
    a = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=port_a,
        send_port=port_b,
        broadcast_fn=lambda: ["127.0.0.1"],
    )
    b = PeerNetwork(
        registry=PeerRegistry(self_id="id-b"),
        host="mac-b",
        bind_port=port_b,
        send_port=port_a,
        broadcast_fn=lambda: ["127.0.0.1"],
        on_change=lambda: calls.append(1),
    )
    assert a.start() and b.start()
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

    # Taken before the patch: free_port() opens a socket of its own, so patching
    # first makes the helper raise and the test pass for the wrong reason.
    port = free_port()

    def refuse(*args, **kwargs):
        raise OSError("Address already in use")

    monkeypatch.setattr(socket, "socket", refuse)
    net = PeerNetwork(
        registry=PeerRegistry(self_id="id-a"),
        host="mac-a",
        bind_port=port,
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
