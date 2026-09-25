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


def test_no_check_step_claims_to_need_privilege():
    """`kind` and `needs_privilege` are independent fields, and only three of
    the eight steps had their flag asserted. A check is read-only with no side
    effect, so flagging one privileged makes repair_executor stub out a step it
    could always have run.
    """
    for classification in (Classification.NETWORK, Classification.DNS):
        for step in ladder_for(classification):
            if step.kind == "check":
                assert step.needs_privilege is False, step.name


def test_every_step_is_either_a_check_or_a_repair():
    for classification in (Classification.NETWORK, Classification.DNS):
        for step in ladder_for(classification):
            assert step.kind in ("check", "repair"), step.name


def test_every_step_records_why_it_runs():
    """state_machine carries `reason` into ladder_results and the report prints it.
    A step with an empty reason -- the failover step shipped that way -- renders as
    a command with no explanation, in the one document meant to explain.
    """
    for classification in (Classification.NETWORK, Classification.DNS):
        for step in ladder_for(classification, frozenset({"network", "dns"})):
            assert step.reason, step.name


def test_ladder_for_returns_a_fresh_list_the_caller_cannot_corrupt():
    """state_machine iterates the returned list once per incident. Returning
    the module-level list itself would let one caller's mutation change every
    later incident's ladder, and the defensive `list(...)` copy was unpinned.
    """
    first = ladder_for(Classification.NETWORK)
    original_length = len(first)
    first.clear()
    steps = ladder_for(Classification.NETWORK)
    assert len(steps) == original_length
    assert steps[0].name == "check_interface_state"
