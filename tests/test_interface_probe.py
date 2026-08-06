"""Offline: every socket call is injected. The real IP_BOUND_IF path was
confirmed by hand against this machine (active interface connects; a
present-but-down interface fails instantly with ENETUNREACH; an absent
interface raises from if_nametoindex) -- see docs/SCRIPTS.md.
"""

from netdnsmonitor.interface_probe import make_interface_prober

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
    """An unplugged adapter is 'not probed'. Reporting False would let the
    policy layer read a missing interface as a broken one.
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

    probe = make_interface_prober(
        TARGETS, timeout=2.0, connect_fn=connect, index_fn=lambda d: 15
    )
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

    real_socket = socket.socket
    socket.socket = lambda fam, typ: FakeSocket(fam, typ)
    try:
        from netdnsmonitor.interface_probe import default_bound_connect

        default_bound_connect.__globals__["default_device_index"] = lambda d: 15
        default_bound_connect("en0", "2606:4700:4700::1111", 443, 1.0)
        default_bound_connect("en0", "1.1.1.1", 443, 1.0)
    finally:
        socket.socket = real_socket

    assert seen[0] == socket.AF_INET6
    assert seen[1] == (socket.IPPROTO_IPV6, 125)
    assert seen[2] == socket.AF_INET
    assert seen[3] == (socket.IPPROTO_IP, 25)


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
