import time

import pytest

from netdnsmonitor.prober import make_prober


def test_external_reachable_true_if_any_external_target_connects():
    connect_fn = lambda host, port, timeout: host == "1.1.1.1"
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[("1.1.1.1", 443), ("8.8.8.8", 443)],
        internal_targets=[],
        domains=["example.com"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    result = prober()
    assert result["external_reachable"] is True


def test_external_reachable_false_if_no_external_target_connects():
    connect_fn = lambda host, port, timeout: False
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[("1.1.1.1", 443), ("8.8.8.8", 443)],
        internal_targets=[],
        domains=["example.com"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    assert prober()["external_reachable"] is False


def test_dns_ok_false_if_any_domain_fails_to_resolve():
    connect_fn = lambda host, port, timeout: True
    resolve_fn = lambda domain, timeout: domain != "broken.example"
    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[],
        domains=["good.example", "broken.example"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    assert prober()["dns_ok"] is False


def test_dns_ok_none_when_no_domains_configured():
    connect_fn = lambda host, port, timeout: True
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[],
        domains=[],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    assert prober()["dns_ok"] is None


def test_internal_reachable_tracked_separately_from_external():
    connect_fn = lambda host, port, timeout: host == "10.0.0.1"
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[("10.0.0.1", 22)],
        domains=["example.com"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    result = prober()
    assert result["internal_reachable"] is True
    assert result["external_reachable"] is False


def test_internal_reachable_none_when_no_internal_targets_configured():
    """`[]` means "not configured", which has to stay distinguishable from
    "all down". DEFAULT_CONFIG ships `internal_targets: []`, so this is the
    default install's path -- reporting False here puts a LAN outage nobody
    measured into every incident report and every LLM escalation bundle.
    """
    connect_fn = lambda host, port, timeout: False
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[],
        domains=["example.com"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    assert prober()["internal_reachable"] is None


def test_external_reachable_none_when_no_external_targets_configured():
    """Same tri-state rule on the external side, where it also gates
    classification: classify() returns UNCLASSIFIED on None but NETWORK on
    False, so collapsing the two invents a network incident outright.
    """
    connect_fn = lambda host, port, timeout: True
    resolve_fn = lambda domain, timeout: True
    prober = make_prober(
        external_targets=[],
        internal_targets=[("10.0.0.1", 22)],
        domains=["example.com"],
        connect_fn=connect_fn,
        resolve_fn=resolve_fn,
    )
    assert prober()["external_reachable"] is None


def test_domain_lookups_share_one_deadline_instead_of_one_each():
    """Regression guard: sequential lookups made the UI-thread block additive
    (N x timeout). With the learned-domain list capped at 20 plus a control
    domain, a resolver outage froze the menu bar for ~42s.
    """
    import time

    def slow_resolve(domain, timeout):
        time.sleep(timeout * 3)  # never answers before the deadline
        return True

    prober = make_prober(
        external_targets=[],
        internal_targets=[],
        domains=["a.example.com", "b.example.com", "c.example.com", "d.example.com"],
        timeout=0.2,
        connect_fn=lambda *a: True,
        resolve_fn=slow_resolve,
    )
    started = time.monotonic()
    result = prober()
    elapsed = time.monotonic() - started

    assert elapsed < 0.2 * 4  # nowhere near 4 x timeout
    assert result["domain_results"] == {
        "a.example.com": False,
        "b.example.com": False,
        "c.example.com": False,
        "d.example.com": False,
    }


def test_a_slow_domain_does_not_hide_the_fast_ones():
    import time

    def resolve_fn(domain, timeout):
        if domain == "slow.example.com":
            time.sleep(timeout * 3)
        return True

    prober = make_prober(
        external_targets=[],
        internal_targets=[],
        domains=["fast.example.com", "slow.example.com"],
        timeout=0.2,
        connect_fn=lambda *a: True,
        resolve_fn=resolve_fn,
    )
    results = prober()["domain_results"]
    assert results == {"fast.example.com": True, "slow.example.com": False}


def test_non_positive_timeout_is_refused_at_construction():
    """A 0 timeout makes every connect fail instantly, so every tick would
    classify as a NETWORK incident about a link nobody measured; a negative one
    raises ValueError out of socket code that only catches OSError. Neither is a
    reading, so the prober refuses to be built rather than report one.
    """
    for timeout in (0, -1.0, float("nan")):
        with pytest.raises(ValueError):
            make_prober(
                external_targets=[("1.1.1.1", 443)],
                internal_targets=[],
                domains=["example.com"],
                timeout=timeout,
                connect_fn=lambda *a: True,
                resolve_fn=lambda d, t: True,
            )


def test_connects_and_lookups_share_one_deadline_instead_of_adding_up():
    """Regression guard: connects ran one after another at the full timeout
    each, then DNS got its own timeout on top -- 2 external targets at 2s plus
    DNS was a 6s menu-bar freeze on every failing tick. Every probe now runs
    against one deadline, so blackholing everything costs about one timeout.
    """

    def blackhole_connect(host, port, timeout):
        time.sleep(timeout * 3)
        return True  # too late to count

    def blackhole_resolve(domain, timeout):
        time.sleep(timeout * 3)
        return True

    prober = make_prober(
        external_targets=[("1.1.1.1", 443), ("8.8.8.8", 443), ("9.9.9.9", 443)],
        internal_targets=[("10.0.0.1", 22), ("10.0.0.2", 22)],
        domains=["a.example.com", "b.example.com"],
        timeout=0.2,
        connect_fn=blackhole_connect,
        resolve_fn=blackhole_resolve,
    )
    started = time.monotonic()
    result = prober()
    elapsed = time.monotonic() - started

    assert elapsed < 0.2 * 2
    assert result["external_reachable"] is False
    assert result["internal_reachable"] is False
    assert result["dns_ok"] is False


def test_one_answering_target_ends_the_wait_without_the_blackholes():
    """The first True settles "reachable"; waiting out the targets that are
    going to time out anyway would put their whole timeout on the UI thread.
    """

    def connect_fn(host, port, timeout):
        if host == "1.1.1.1":
            return True
        time.sleep(timeout)
        return False

    prober = make_prober(
        external_targets=[("10.0.0.1", 443), ("10.0.0.2", 443), ("1.1.1.1", 443)],
        internal_targets=[],
        domains=[],
        timeout=1.0,
        connect_fn=connect_fn,
        resolve_fn=lambda d, t: True,
    )
    started = time.monotonic()
    result = prober()
    elapsed = time.monotonic() - started

    assert result["external_reachable"] is True
    assert elapsed < 0.5


def test_a_connect_fn_that_raises_is_not_reported_as_unreachable():
    """Moving connects onto worker threads must not turn a bug into a reading:
    a swallowed exception would surface as external_reachable False, which
    classify() turns into a confident NETWORK diagnosis. It still reaches the
    caller, where the tick guard records it.
    """

    def broken(host, port, timeout):
        raise RuntimeError("bug in connect_fn")

    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[],
        domains=[],
        timeout=0.5,
        connect_fn=broken,
        resolve_fn=lambda d, t: True,
    )
    with pytest.raises(RuntimeError):
        prober()


def test_resolution_worker_error_is_not_a_dns_failure():
    from netdnsmonitor.prober import resolve_all

    def bad_lookup(domain, timeout):
        raise UnicodeError("invalid DNS label")

    with pytest.raises(UnicodeError, match="invalid DNS label"):
        resolve_all(["bad.example"], 0.1, bad_lookup)


def test_a_domains_callable_is_re_read_on_every_probe():
    """The learner grows the list between ticks; a snapshot taken at build time
    would never probe a learned domain.
    """
    seen = []
    current = ["a.example"]

    def resolve_fn(domain, timeout):
        seen.append(domain)
        return True

    prober = make_prober(
        external_targets=[("1.1.1.1", 443)],
        internal_targets=[],
        domains=lambda: list(current),
        connect_fn=lambda host, port, timeout: True,
        resolve_fn=resolve_fn,
    )
    prober()
    current.append("b.example")
    prober()
    assert seen == ["a.example", "a.example", "b.example"]


def test_a_refused_connection_counts_as_the_target_answering(monkeypatch):
    # The same rule as interface_probe: an RST came back from the target, so the
    # path to it works even though nothing listens on that port.
    import socket

    from netdnsmonitor import prober

    def refuse(address, timeout=None):
        raise ConnectionRefusedError(61, "Connection refused")

    monkeypatch.setattr(socket, "create_connection", refuse)
    assert prober.default_connect("192.168.1.1", 53, 1.0) is True


def test_a_timed_out_connection_is_still_unreachable(monkeypatch):
    import socket

    from netdnsmonitor import prober

    def timeout(address, timeout=None):
        raise TimeoutError()

    monkeypatch.setattr(socket, "create_connection", timeout)
    assert prober.default_connect("192.168.1.1", 53, 1.0) is False
