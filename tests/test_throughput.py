"""Offline. `default_measure` was verified by hand against real interfaces:
en0 measured 3.8 Mbps against Cloudflare's endpoint, and every inactive
interface returned None rather than 0.0.
"""

import errno
import socket
import threading
import time

import pytest

from netdnsmonitor.failover_policy import Candidate, best_candidate, rank_candidates
from netdnsmonitor.throughput import (
    default_measure,
    is_success_status,
    make_throughput_meter,
    mbps,
    measure_all,
    resolve_addresses,
)

V6 = "2606:4700::6810:84e5"
V4 = "104.16.132.229"


def no_lookup(host, timeout):
    """The meter resolves before it measures; a real lookup would leave the
    machine, so every meter here gets this instead.
    """
    return [V4]


# --- meter ------------------------------------------------------------------


def resolved(host, timeout):
    return "192.0.2.1"


def test_meter_returns_the_measurement():
    meter = make_throughput_meter(measure_fn=lambda dev, **kw: 94.2, resolve_fn=no_lookup)
    assert meter("en0") == 94.2


def test_meter_does_not_touch_the_resolver(monkeypatch):
    """The lookup enters through `resolve_fn`; with a fake injected, the suite
    must never reach the real resolver. Guarded at the socket boundary because
    that is the only place an accidental real lookup would show.
    """
    calls = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: calls.append(a) or [])
    meter = make_throughput_meter(measure_fn=lambda dev, **kw: 1.0, resolve_fn=resolved)
    assert meter("en0") == 1.0
    assert calls == []


def test_no_device_is_not_measured():
    meter = make_throughput_meter(measure_fn=lambda dev, **kw: 94.2, resolve_fn=no_lookup)
    assert meter(None) is None
    assert meter("") is None


def test_an_empty_host_disables_measurement_entirely():
    """Ranking then falls back to reachability rather than inventing numbers."""
    calls = []
    meter = make_throughput_meter(
        host="", measure_fn=lambda dev, **kw: calls.append(dev) or 1.0, resolve_fn=resolved
    )
    assert meter("en0") is None
    assert calls == []


def test_a_raising_measurement_is_not_measured_rather_than_an_error():
    def boom(dev, **kw):
        raise OSError("interface went away mid-benchmark")

    assert make_throughput_meter(measure_fn=boom, resolve_fn=no_lookup)("en0") is None


def test_measurement_parameters_reach_the_measure_function():
    seen = {}

    def capture(dev, **kw):
        seen.update(kw)
        seen["device"] = dev
        return 1.0

    meter = make_throughput_meter(
        host="h",
        path="/p",
        port=8443,
        timeout=9.0,
        max_bytes=5,
        measure_fn=capture,
        resolve_fn=no_lookup,
    )
    meter("en3")
    assert seen.pop("address") == [V4]
    # Whatever the lookup cost comes off the top, so the meter sees the rest.
    assert seen.pop("timeout") == pytest.approx(9.0, abs=0.5)
    assert seen == {
        "device": "en3",
        "host": "h",
        "path": "/p",
        "port": 8443,
        "max_bytes": 5,
    }


def test_meter_resolves_once_and_shares_every_family_across_interfaces():
    """The lookup is the same for every interface, so it is paid once. What is
    cached is one literal per family, not just the first answer: a v4-only
    backup handed only the v6 literal could never connect.
    """
    lookups = []
    seen = []

    def resolve(host, timeout):
        lookups.append((host, timeout))
        return [V6, V4]

    def capture(dev, **kw):
        seen.append(kw["address"])
        return 1.0

    meter = make_throughput_meter(
        host="h", timeout=4.0, measure_fn=capture, resolve_fn=resolve, clock=FakeClock()
    )
    meter("en0")
    meter("en12")
    assert lookups == [("h", 4.0)]
    assert seen == [[V6, V4], [V6, V4]]


def test_a_failed_lookup_lets_the_measurement_retry_inside_its_own_budget():
    """An empty lookup must not be handed on as "no addresses exist"; passing
    None lets the measurement resolve again within its own deadline.
    """
    seen = []
    meter = make_throughput_meter(
        measure_fn=lambda dev, **kw: seen.append(kw["address"]) or 1.0,
        resolve_fn=lambda host, timeout: [],
    )
    meter("en0")
    assert seen == [None]


def test_meter_deducts_resolution_time_from_measurement_budget():
    clock = FakeClock()
    seen = []

    def resolve(host, timeout):
        clock.now += 4.0
        return [V4]

    meter = make_throughput_meter(
        timeout=5.0,
        resolve_fn=resolve,
        measure_fn=lambda device, **kw: seen.append(kw["timeout"]) or 1.0,
        clock=clock,
    )
    assert meter("en0") == 1.0
    assert seen == [1.0]


def test_an_exhausted_lookup_budget_does_not_start_a_measurement():
    clock = FakeClock()
    measured = []

    def resolve(host, timeout):
        clock.now += timeout
        return []

    meter = make_throughput_meter(
        timeout=5.0,
        resolve_fn=resolve,
        measure_fn=lambda device, **kw: measured.append(device) or 1.0,
        clock=clock,
    )
    assert meter("en0") is None
    assert measured == []


def test_concurrent_meters_share_one_successful_lookup():
    entered = threading.Event()
    duplicate = threading.Event()
    release = threading.Event()
    lookups = []
    results = []

    def resolve(host, timeout):
        lookups.append(host)
        if len(lookups) > 1:
            duplicate.set()
        entered.set()
        assert release.wait(timeout=2)
        return [V4]

    meter = make_throughput_meter(resolve_fn=resolve, measure_fn=lambda device, **kw: 1.0)
    workers = [threading.Thread(target=lambda: results.append(meter("en0"))) for _ in range(2)]
    try:
        workers[0].start()
        assert entered.wait(timeout=2)
        workers[1].start()
        assert not duplicate.wait(timeout=0.1)
    finally:
        release.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join(timeout=2)
                assert not worker.is_alive()
    assert lookups == ["speed.cloudflare.com"]
    assert results == [1.0, 1.0]


def test_a_failed_shared_lookup_is_retried_on_the_next_measurement():
    answers = iter([[], [V4]])
    seen = []
    meter = make_throughput_meter(
        resolve_fn=lambda host, timeout: next(answers),
        measure_fn=lambda device, **kw: seen.append(kw["address"]) or 1.0,
    )
    assert meter("en0") == 1.0
    assert meter("en1") == 1.0
    assert seen == [None, [V4]]


def test_a_measurement_type_error_is_not_retried_or_raised():
    calls = []

    def broken(device, **kw):
        calls.append(device)
        raise TypeError("measurement failed internally")

    meter = make_throughput_meter(resolve_fn=no_lookup, measure_fn=broken)
    assert meter("en0") is None
    assert calls == ["en0"]


# --- resolution -------------------------------------------------------------


def test_resolution_keeps_one_literal_per_family_in_resolver_order():
    def fake_getaddrinfo(host, port, proto=0):
        return [
            (socket.AF_INET6, socket.SOCK_STREAM, proto, "", (V6, 0, 0, 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, proto, "", ("2606:4700::1", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, proto, "", (V4, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, proto, "", ("104.16.133.229", 0)),
        ]

    assert resolve_addresses("h", 1.0, getaddrinfo_fn=fake_getaddrinfo) == [V6, V4]


def test_a_failed_resolution_is_empty_not_an_error():
    def failing(host, port, proto=0):
        raise socket.gaierror(socket.EAI_NONAME, "nodename nor servname provided")

    assert resolve_addresses("h", 1.0, getaddrinfo_fn=failing) == []


# --- default_measure through its socket seams --------------------------------


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeSocket:
    def __init__(self, family, clock, connect_cost=0.0, refuse=False):
        self.family = family
        self.clock = clock
        self.connect_cost = connect_cost
        self.refuse = refuse
        self.timeouts = []
        self.connected_to = None
        self.closed = False

    def setsockopt(self, level, option, value):
        pass

    def settimeout(self, value):
        self.timeouts.append(value)

    def connect(self, address):
        self.clock.now += self.connect_cost
        if self.refuse:
            raise OSError(errno.EHOSTUNREACH, "No route to host")
        self.connected_to = address

    def close(self):
        self.closed = True


class FakeStream:
    """A TLS stream: a status line, then `chunk` forever (or `script` in order),
    each read costing `per_recv` seconds of the fake clock.
    """

    def __init__(self, clock, per_recv=0.0, chunk=b"x" * 1000, script=None):
        self.clock = clock
        self.per_recv = per_recv
        self.chunk = chunk
        self.script = list(script) if script is not None else None
        self.first = True
        self.timeouts = []
        self.recvs = 0
        self.sent = b""

    def sendall(self, data):
        self.sent += data

    def settimeout(self, value):
        self.timeouts.append((self.clock.now, value))

    def recv(self, size):
        self.recvs += 1
        self.clock.now += self.per_recv
        if self.first:
            self.first = False
            return b"HTTP/1.1 200 OK\r\n\r\n"
        if self.script is None:
            return self.chunk
        if not self.script:
            return b""
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self):
        pass


def seams(clock, stream, refuse_families=(), connect_cost=0.0):
    sockets = []
    wrapped = []

    def socket_factory(family, kind):
        sock = FakeSocket(
            family, clock, connect_cost=connect_cost, refuse=family in refuse_families
        )
        sockets.append(sock)
        return sock

    def tls_wrap(sock, server_hostname):
        wrapped.append((sock, server_hostname))
        return stream

    kwargs = {
        "device_index_fn": lambda device: 12,
        "socket_factory": socket_factory,
        "tls_wrap": tls_wrap,
        "clock": clock,
    }
    return kwargs, sockets, wrapped


def test_a_backup_without_an_ipv6_route_still_measures_over_ipv4():
    """The shared lookup put IPv6 first. A v4-only backup failed that connect,
    read as unmeasurable, and ranked behind a slower link on no evidence.
    """
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.1, script=[b"x" * 125_000])
    kwargs, sockets, wrapped = seams(clock, stream, refuse_families=(socket.AF_INET6,))

    result = default_measure("en12", host="speed.example", address=[V6, V4], **kwargs)

    assert result is not None
    assert [s.family for s in sockets] == [socket.AF_INET6, socket.AF_INET]
    assert sockets[0].closed, "the refused socket must not leak"
    assert sockets[1].connected_to == (V4, 443)
    # Connect to the literal, but present the hostname for SNI and validation.
    assert wrapped == [(sockets[1], "speed.example")]


def test_a_blackholing_ipv6_literal_leaves_budget_for_ipv4():
    """A v6 route that blackholes rather than refusing stalls connect for its
    whole armed timeout. Armed with the full budget, it spent all 5s, IPv4 was
    never tried, and a working backup read as unmeasurable -- ranked behind a
    slower link that happened to be measured.
    """
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.1, script=[b"x" * 125_000])
    kwargs, sockets, _ = seams(clock, stream)

    class BlackholeSocket(FakeSocket):
        def connect(self, address):
            self.clock.now += self.timeouts[-1]
            raise TimeoutError("timed out")

    def socket_factory(family, kind):
        cls = BlackholeSocket if family == socket.AF_INET6 else FakeSocket
        sock = cls(family, clock)
        sockets.append(sock)
        return sock

    kwargs["socket_factory"] = socket_factory
    result = default_measure("en12", address=[V6, V4], timeout=5.0, **kwargs)

    assert result is not None
    assert [s.family for s in sockets] == [socket.AF_INET6, socket.AF_INET]
    assert sockets[0].timeouts[0] <= 2.5
    assert sockets[1].connected_to == (V4, 443)


def test_no_literal_that_connects_is_unmeasured_not_zero():
    clock = FakeClock()
    kwargs, sockets, _ = seams(
        clock, FakeStream(clock), refuse_families=(socket.AF_INET6, socket.AF_INET)
    )
    assert default_measure("en12", address=[V6, V4], **kwargs) is None
    assert len(sockets) == 2
    assert all(s.closed for s in sockets)


def test_a_single_literal_is_still_accepted():
    """Callers that pass one pre-resolved string keep working."""
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.1, script=[b"x" * 1000])
    kwargs, sockets, _ = seams(clock, stream)
    assert default_measure("en12", address=V4, **kwargs) is not None
    assert sockets[0].connected_to == (V4, 443)


def test_connect_and_tls_are_charged_to_the_one_budget():
    """The transfer deadline used to start after connect and TLS, and a socket
    timeout applies per operation, so each phase could spend the whole budget
    in turn. Here connect burns 2s of a 3s budget, which leaves the transfer 1s.
    """
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.25)
    kwargs, sockets, _ = seams(clock, stream, connect_cost=2.0)

    result = default_measure("en12", address=[V4], timeout=3.0, max_bytes=10**12, **kwargs)

    assert result is not None
    assert clock.now <= 3.0 + 0.25, "no read may start after the budget is spent"
    assert stream.recvs <= 4
    # Every read is armed with what is left of the budget, never the full timeout.
    assert stream.timeouts
    for armed_at, value in stream.timeouts:
        assert value <= max(0.05, 3.0 - armed_at) + 1e-9
    assert sockets[0].timeouts == [3.0, 1.0]


def test_a_read_cut_off_by_the_budget_still_reports_what_arrived():
    """With each read armed to the remaining budget, a stall at the very end
    raises a timeout. Bytes already received are still a measurement of this
    link; discarding them would report a slow link as unmeasurable.
    """
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.5, script=[b"x" * 125_000, TimeoutError("timed out")])
    kwargs, _, _ = seams(clock, stream)
    assert default_measure("en12", address=[V4], timeout=3.0, **kwargs) is not None


def test_a_timeout_before_the_status_line_is_unmeasured():
    clock = FakeClock()

    class SilentStream(FakeStream):
        def recv(self, size):
            raise TimeoutError("timed out")

    kwargs, _, _ = seams(clock, SilentStream(clock))
    assert default_measure("en12", address=[V4], **kwargs) is None


def test_a_missing_interface_is_unmeasured_without_opening_a_socket():
    clock = FakeClock()
    kwargs, sockets, _ = seams(clock, FakeStream(clock))
    kwargs["device_index_fn"] = lambda device: None
    assert default_measure("en99", address=[V4], **kwargs) is None
    assert sockets == []


# --- ranking ----------------------------------------------------------------


def test_fastest_reachable_candidate_wins():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True, throughput_mbps=12.0),
            Candidate("iPhone USB", "en11", reachable=True, throughput_mbps=48.5),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["iPhone USB", "M3100", "Wi-Fi"]


def test_unreachable_candidates_are_never_eligible_however_fast():
    """Reachability is a gate, not a factor. A fast-looking but unverified path
    must never beat a slow proven one.
    """
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=False, throughput_mbps=999.0),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["Wi-Fi"]


def test_unprobed_candidates_are_never_eligible():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=None, throughput_mbps=999.0),
        ]
    )
    assert ranked == []


def test_unmeasured_but_reachable_ranks_after_measured_and_still_counts():
    """ "Unknown speed" is a better bet than no link at all."""
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True, throughput_mbps=None),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["Wi-Fi", "M3100"]


def test_ties_keep_configured_order():
    ranked = rank_candidates(
        [
            Candidate("first", "en1", reachable=True, throughput_mbps=10.0),
            Candidate("second", "en2", reachable=True, throughput_mbps=10.0),
        ]
    )
    assert [c.name for c in ranked] == ["first", "second"]


def test_all_unmeasured_keeps_configured_order():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True),
            Candidate("iPhone USB", "en11", reachable=True),
        ]
    )
    assert [c.name for c in ranked] == ["M3100", "iPhone USB"]


def test_zero_throughput_is_a_real_reading_not_a_missing_one():
    """0.0 means "carries nothing" and must rank below a measured link, but
    still above an unmeasured one -- it is evidence, not absence of it.
    """
    ranked = rank_candidates(
        [
            Candidate("dead", "en1", reachable=True, throughput_mbps=0.0),
            Candidate("unknown", "en2", reachable=True, throughput_mbps=None),
            Candidate("good", "en3", reachable=True, throughput_mbps=5.0),
        ]
    )
    assert [c.name for c in ranked] == ["good", "dead", "unknown"]


def test_best_candidate_is_none_when_nothing_is_eligible():
    assert best_candidate([]) is None
    assert best_candidate([Candidate("x", "en1", reachable=False)]) is None


# --- the pieces of default_measure that can be tested without a socket ------


def test_status_line_split_across_reads_is_still_2xx():
    """A first TCP/TLS segment shorter than the status line used to read as
    non-2xx, reporting a healthy link as unmeasurable.
    """
    assert is_success_status(b"HTTP/1.1 200 OK\r\n") is True
    assert is_success_status(b"HTTP/1.1 2") is True
    assert is_success_status(b"HTTP/1.1 204 No Content\r\n") is True


def test_non_2xx_is_rejected_so_a_broken_target_is_not_a_slow_interface():
    assert is_success_status(b"HTTP/1.1 301 Moved Permanently\r\n") is False
    assert is_success_status(b"HTTP/1.1 500 Server Error\r\n") is False
    assert is_success_status(b"garbage") is False
    assert is_success_status(b"") is False


def test_mbps_arithmetic():
    assert mbps(1_000_000, 1.0) == 8.0
    assert mbps(2_000_000, 2.0) == 8.0


def test_mbps_is_none_rather_than_zero_when_it_would_be_meaningless():
    assert mbps(0, 1.0) is None  # nothing transferred
    assert mbps(1000, 0.0) is None  # no elapsed time
    assert mbps(1000, -1.0) is None  # clock went backwards


def test_measure_all_shares_one_deadline_across_interfaces():
    """Serially this is one timeout each on the UI thread; the whole point is
    that the round costs roughly one.
    """

    def slow(device):
        time.sleep(0.3)
        return 1.0

    started = time.monotonic()
    results = measure_all(["a", "b", "c", "d"], slow, timeout=2.0, grace=0)
    elapsed = time.monotonic() - started
    assert set(results) == {"a", "b", "c", "d"}
    assert elapsed < 1.0, "measurements must run concurrently, not one after another"


def test_measure_all_reports_a_slow_interface_as_unmeasured_not_a_wait():
    release = threading.Event()
    workers = []

    def never(device):
        workers.append(threading.current_thread())
        assert release.wait(timeout=5)
        return 1.0

    try:
        started = time.monotonic()
        results = measure_all(["stuck"], never, timeout=0.2, grace=0)
        assert results == {"stuck": None}
        assert time.monotonic() - started < 1.0, "grace=0 must not add the default 1s"
    finally:
        release.set()
        for worker in workers:
            worker.join(timeout=5)
            assert not worker.is_alive()


def test_measure_all_with_no_devices_is_empty():
    assert measure_all([], lambda d: 1.0, timeout=1.0, grace=0) == {}
