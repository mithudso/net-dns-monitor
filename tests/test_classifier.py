from netdnsmonitor.classifier import Classification, classify


def test_reachable_and_dns_ok_is_healthy():
    assert classify(external_reachable=True, dns_ok=True) == Classification.HEALTHY


def test_reachable_but_dns_fails_is_dns_layer():
    assert classify(external_reachable=True, dns_ok=False) == Classification.DNS


def test_unreachable_is_network_layer_even_if_dns_ok():
    assert classify(external_reachable=False, dns_ok=True) == Classification.NETWORK


def test_unreachable_and_dns_fails_is_network_layer():
    assert classify(external_reachable=False, dns_ok=False) == Classification.NETWORK


def test_missing_probe_result_is_unclassified():
    assert classify(external_reachable=None, dns_ok=True) == Classification.UNCLASSIFIED
    assert classify(external_reachable=True, dns_ok=None) == Classification.UNCLASSIFIED


def test_incomplete_probe_data_is_unclassified_even_when_the_network_is_down():
    """Completes the 3x3 truth table; these three cells were untested.

    (False, None) is not hypothetical: with the shipped default `domains: []`
    the prober returns dns_ok=None on every probe, so it is exactly the cell a
    default install lands in the moment its network drops. The None check
    deliberately wins over the network check -- reordering the two keeps every
    other test in this file green while silently turning UNCLASSIFIED into
    NETWORK.
    """
    assert classify(external_reachable=False, dns_ok=None) == Classification.UNCLASSIFIED
    assert classify(external_reachable=None, dns_ok=False) == Classification.UNCLASSIFIED
    assert classify(external_reachable=None, dns_ok=None) == Classification.UNCLASSIFIED
