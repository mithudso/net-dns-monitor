"""Offline: every socket call is injected. The real IP_BOUND_IF path was
confirmed by hand against this machine (active interface connects; a
present-but-down interface fails instantly with ENETUNREACH; an absent
interface raises from if_nametoindex) -- see docs/SCRIPTS.md.
"""

import errno
import socket
import time

import pytest

from netdnsmonitor.interface_probe import (
    default_bound_connect,
    default_device_index,
    make_interface_prober,
)

TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443)]


def test_returns_true_when_a_target_answers_through_the_interface():
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: True, index_fn=lambda d: 15
    )
    assert probe("en0") is True


def test_returns_false_when_no_target_answers():
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: False, index_fn=lambda d: 15
    )
    assert probe("en0") is False


def test_absent_device_is_none_not_false():
    """An unplugged adapter is 'not probed', which is a different thing to
    report to a human than 'the link is dead' -- even though both refuse the
    same switches today.
    """
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: True, index_fn=lambda d: None
    )
    assert probe("en6") is None


def test_no_device_configured_is_none():
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: True, index_fn=lambda d: 15
    )
    assert probe(None) is None
    assert probe("") is None


def test_no_targets_is_none_not_false():
    probe = make_interface_prober(
        [], timeout=2.0, connect_fn=lambda d, h, p, t: True, index_fn=lambda d: 15
    )
    assert probe("en0") is None


def test_non_positive_timeout_is_none_not_false():
    """`probe_timeout_seconds` is user-settable YAML. A budget of zero asks
    nothing, and False would say "dead" about a link nobody probed.
    """
    calls = []
    probe = make_interface_prober(
        TARGETS,
        timeout=0.0,
        connect_fn=lambda d, h, p, t: calls.append(h) or True,
        index_fn=lambda d: 15,
    )
    assert probe("en0") is None
    assert calls == []


def test_binds_to_the_requested_device():
    seen = []
    probe = make_interface_prober(
        TARGETS,
        timeout=2.0,
        connect_fn=lambda d, h, p, t: seen.append((d, h, p)) or False,
        index_fn=lambda d: 15,
    )
    probe("en0")
    assert [d for d, _, _ in seen] == ["en0", "en0"]


def test_stops_at_the_first_reachable_target():
    seen = []

    def connect(device, host, port, timeout):
        seen.append(host)
        return host == "1.1.1.1"

    probe = make_interface_prober(TARGETS, timeout=2.0, connect_fn=connect, index_fn=lambda d: 15)
    assert probe("en0") is True
    assert seen == ["1.1.1.1"]


def test_all_targets_share_one_deadline():
    """Two blackholing targets must not cost 2 x timeout: the second call gets
    only the remaining budget, and once it is gone no further target is tried.
    """
    budgets = []

    def slow_connect(device, host, port, timeout):
        budgets.append(timeout)
        # Simulate consuming the entire remaining budget.
        import time

        time.sleep(min(timeout, 0.05))
        return False

    probe = make_interface_prober(
        [("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)],
        timeout=0.1,
        connect_fn=slow_connect,
        index_fn=lambda d: 15,
    )
    assert probe("en0") is False
    assert budgets == sorted(budgets, reverse=True), "budget must shrink"
    assert all(b <= 0.1 for b in budgets)


def test_ipv6_targets_select_the_ipv6_bind_option():
    """The ordinary prober accepts an IPv6 external target, so this one must
    too -- forcing every probe through AF_INET would report a link that had
    recovered over IPv6 as unreachable, and it would never be failed back to.
    Both option numbers were confirmed against Darwin's headers and a live
    interface; here we only assert the family/option selection.
    """
    import socket

    from netdnsmonitor.interface_probe import IP_BOUND_IF, IPV6_BOUND_IF

    assert (IP_BOUND_IF, IPV6_BOUND_IF) == (25, 125)

    seen = []

    class FakeSocket:
        def __init__(self, family, type_):
            seen.append(family)

        def setsockopt(self, level, option, value):
            seen.append((level, option))

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def close(self):
            pass

    from netdnsmonitor import interface_probe

    real_socket = socket.socket
    socket.socket = lambda fam, typ: FakeSocket(fam, typ)
    try:
        interface_probe.default_bound_connect(
            "en0", "2606:4700:4700::1111", 443, 1.0, index_fn=lambda d: 15
        )
        interface_probe.default_bound_connect("en0", "1.1.1.1", 443, 1.0, index_fn=lambda d: 15)
    finally:
        socket.socket = real_socket

    assert seen[0] == socket.AF_INET6
    assert seen[1] == (socket.IPPROTO_IPV6, 125)
    assert seen[2] == socket.AF_INET
    assert seen[3] == (socket.IPPROTO_IP, 25)


def test_the_injected_index_fn_reaches_the_default_connect():
    """With the default connect, the index lookup on the connect side has to
    be the same injected one probe() used, or a test pretending an adapter is
    absent gets the real interface table underneath it. An absent index
    returns None (not asked) before any socket is opened, so this touches no network.
    """
    from netdnsmonitor.interface_probe import default_bound_connect

    seen = []

    def index_fn(device):
        seen.append(device)
        return None

    assert default_bound_connect("en9", "1.1.1.1", 443, 1.0, index_fn=index_fn) is None
    assert seen == ["en9"]


def test_device_index_is_checked_before_connecting():
    """No connect attempt at all for an absent interface."""
    calls = []
    probe = make_interface_prober(
        TARGETS,
        timeout=2.0,
        connect_fn=lambda d, h, p, t: calls.append(d) or True,
        index_fn=lambda d: None,
    )
    assert probe("en6") is None
    assert calls == []


def test_one_blackholing_target_does_not_starve_the_reachable_one():
    """Found on a live machine 2026-08-08.

    The shared deadline was handed to each connect *whole*, so a target that
    blackholes -- which is what an off-link gateway does, rather than refusing --
    consumed the entire budget and every later target was skipped. Raising the
    budget made it worse: the blackhole simply stalled for longer before the
    probe still reported unreachable.

    The interesting case is exactly the one this feature needs: per-link gateways,
    where every target but one is unreachable from any given interface.
    """
    attempted = []

    def connect_fn(device, host, port, timeout):
        attempted.append((host, timeout))
        if host == "10.0.0.1":  # the off-link gateway: blackholes for its whole slice
            time.sleep(timeout)
            return False
        return True

    probe = make_interface_prober(
        targets=[("10.0.0.1", 53), ("192.168.1.1", 53)],
        timeout=1.0,
        connect_fn=connect_fn,
        index_fn=lambda device: 1,
    )

    assert probe("en0") is True
    assert [host for host, _ in attempted] == ["10.0.0.1", "192.168.1.1"]


def test_the_total_deadline_is_still_bounded_by_the_timeout():
    """The property the shared deadline exists for, which the fix must not lose:
    N targets must not cost N x timeout.
    """

    def connect_fn(device, host, port, timeout):
        time.sleep(timeout)
        return False

    probe = make_interface_prober(
        targets=[("10.0.0.1", 53), ("10.0.0.2", 53), ("10.0.0.3", 53)],
        timeout=0.6,
        connect_fn=connect_fn,
        index_fn=lambda device: 1,
    )

    started = time.monotonic()
    assert probe("en0") is False
    assert time.monotonic() - started < 1.2  # not 3 x 0.6 plus slack


def test_time_a_fast_failure_leaves_behind_goes_to_the_next_target():
    """Each slice is the remaining budget over the targets still to try, not a
    fixed timeout / N. A target that fails instantly (ENETUNREACH) used to leave
    its unspent share stranded, so a slow-but-working second target was cut off
    at half the budget it could have had.
    """
    budgets = []

    def connect_fn(device, host, port, timeout):
        budgets.append(timeout)
        return False

    probe = make_interface_prober(
        [("10.0.0.1", 53), ("192.168.1.1", 53)],
        timeout=1.0,
        connect_fn=connect_fn,
        index_fn=lambda d: 1,
    )
    assert probe("en0") is False
    assert budgets[0] <= 0.5
    assert budgets[1] >= 0.9


def test_no_budget_at_all_is_none_not_false():
    """With nothing attempted there is no reading: False would tell the report
    and the failover policy that the link was probed and is dead.
    """
    calls = []
    probe = make_interface_prober(
        TARGETS,
        timeout=0,
        connect_fn=lambda d, h, p, t: calls.append(h) or True,
        index_fn=lambda d: 1,
    )
    assert probe("en0") is None
    assert calls == []


def test_a_numeric_ipv4_target_uses_the_family_returned_by_the_os(monkeypatch):
    import socket

    from netdnsmonitor.interface_probe import default_bound_connect

    seen = []

    def resolve(host, port, family, kind):
        assert host == "1.1.1.1" and family == socket.AF_UNSPEC
        return [(socket.AF_INET6, kind, 6, "", ("64:ff9b::101:101", port, 0, 0))]

    class Socket:
        def setsockopt(self, level, option, index):
            seen.append((level, option, index))

        def settimeout(self, timeout):
            assert 0 < timeout <= 1

        def connect(self, address):
            seen.append(address)

        def close(self):
            seen.append("closed")

    def open_socket(family, kind):
        seen.append(family)
        return Socket()

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", open_socket)
    assert default_bound_connect("en0", "1.1.1.1", 443, 1, index_fn=lambda d: 15) is True
    assert seen == [
        socket.AF_INET6,
        (socket.IPPROTO_IPV6, 125, 15),
        ("64:ff9b::101:101", 443, 0, 0),
        "closed",
    ]


def test_bound_candidate_fallback_closes_sockets_and_shares_one_budget(monkeypatch):
    import socket

    from netdnsmonitor import interface_probe

    now = [10.0]
    budgets = []
    closed = []
    addresses = [("2001:db8::1", 443, 0, 0), ("192.0.2.1", 443)]
    monkeypatch.setattr(interface_probe.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", addresses[0]),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", addresses[1]),
        ],
    )

    class Socket:
        def __init__(self, family, kind):
            self.family = family

        def setsockopt(self, *args):
            pass

        def settimeout(self, timeout):
            self.timeout = timeout
            budgets.append(timeout)

        def connect(self, address):
            if self.family == socket.AF_INET6:
                now[0] += self.timeout
                raise TimeoutError
            assert address == addresses[1]

        def close(self):
            closed.append(self.family)

    monkeypatch.setattr(socket, "socket", Socket)
    assert (
        interface_probe.default_bound_connect("en0", "192.0.2.1", 443, 2, index_fn=lambda d: 1)
        is True
    )
    assert budgets == [1.0, 1.0]
    assert closed == [socket.AF_INET6, socket.AF_INET]


def test_bound_probes_refuse_hostname_lookup_before_resolving(monkeypatch):
    import socket

    from netdnsmonitor.interface_probe import default_bound_connect

    def unexpected_lookup(*args):
        raise AssertionError("hostname resolution has no socket deadline")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected_lookup)
    assert default_bound_connect("en0", "example.com", 443, 1, index_fn=lambda d: 1) is False


def test_default_device_index_of_an_absent_interface_is_none():
    assert default_device_index("nonexist0") is None


def _fake_socket(monkeypatch, *, make=None, setsockopt=None, connect=None):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 53))],
    )

    class FakeSocket:
        def __init__(self, family, kind):
            if make:
                raise make

        def setsockopt(self, *a):
            if setsockopt:
                raise setsockopt

        def settimeout(self, t):
            pass

        def connect(self, address):
            if connect:
                raise connect

        def close(self):
            pass

    monkeypatch.setattr(socket, "socket", FakeSocket)


def test_interface_vanishing_before_the_bind_is_none_not_false(monkeypatch):
    _fake_socket(monkeypatch, setsockopt=OSError(errno.ENXIO, "Device not configured"))
    probe = make_interface_prober([("192.168.1.1", 53)], timeout=1.0, index_fn=lambda d: 7)
    assert probe("en6") is None


@pytest.mark.parametrize(
    "code",
    [errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EPERM, errno.EACCES],
)
def test_a_local_socket_failure_is_none_not_a_dead_link(monkeypatch, code):
    _fake_socket(monkeypatch, make=OSError(code, "local"))
    probe = make_interface_prober([("192.168.1.1", 53)], timeout=1.0, index_fn=lambda d: 7)
    assert probe("en0") is None


def test_a_connect_failure_through_the_interface_is_still_false(monkeypatch):
    _fake_socket(monkeypatch, connect=OSError(errno.ENETUNREACH, "unreachable"))
    probe = make_interface_prober([("192.168.1.1", 53)], timeout=1.0, index_fn=lambda d: 7)
    assert probe("en0") is False


def test_default_bound_connect_with_an_absent_index_is_none():
    assert default_bound_connect("en9", "1.1.1.1", 443, 1.0, index_fn=lambda d: None) is None


def test_none_from_connect_fn_is_not_an_attempt():
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: None, index_fn=lambda d: 15
    )
    assert probe("en0") is None


def test_one_none_does_not_hide_a_measured_failure():
    answers = iter([None, False])
    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=lambda d, h, p, t: next(answers), index_fn=lambda d: 15
    )
    assert probe("en0") is False
