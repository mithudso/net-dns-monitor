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
