from netdnsmonitor.classifier import Classification
from netdnsmonitor.ladder import ladder_for


def test_network_layer_ladder_checks_interface_and_route_before_repairs():
    steps = ladder_for(Classification.NETWORK)
    names = [s.name for s in steps]
    assert names.index("check_interface_state") < names.index("renew_dhcp_lease")
    assert names.index("check_default_route") < names.index("toggle_network_service")


def test_network_layer_repairs_need_privilege():
    steps = ladder_for(Classification.NETWORK)
    repairs = [s for s in steps if s.name in ("renew_dhcp_lease", "toggle_network_service")]
    assert repairs and all(s.needs_privilege for s in repairs)


def test_dns_layer_ladder_flushes_cache_without_privilege():
    steps = ladder_for(Classification.DNS)
    flush = next(s for s in steps if s.name == "flush_dns_cache")
    assert flush.needs_privilege is False


def test_dns_layer_ladder_checks_resolver_config_before_flushing():
    steps = ladder_for(Classification.DNS)
    names = [s.name for s in steps]
    assert names.index("check_configured_dns_servers") < names.index("flush_dns_cache")


def test_unclassified_and_healthy_have_no_ladder_steps():
    assert ladder_for(Classification.UNCLASSIFIED) == []
    assert ladder_for(Classification.HEALTHY) == []
