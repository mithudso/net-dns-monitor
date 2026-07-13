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
