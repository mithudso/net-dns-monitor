"""The parser is tested against the literal `networksetup
-listnetworkserviceorder` output captured from the machine this feature was
built for, disabled `(*)` entries and all, because the failure this module
guards against -- dropping a service name -- is invisible in a synthetic
two-service fixture.
"""

from netdnsmonitor.service_order import (
    NetworkService,
    find_service,
    is_order_intact,
    order_argv,
    parse_service_order,
    promote,
)

# Verbatim output, including the two disabled services and the adapter pair
# whose names differ only in the middle ("10/100/1000" vs "10/100/1G/2.5G").
REAL_LISTING = """An asterisk (*) denotes that a network service is disabled.
(1) AX88179B
(Hardware Port: AX88179B, Device: en6)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)

(*) USB 10/100/1G/2.5G LAN
(Hardware Port: USB 10/100/1G/2.5G LAN, Device: en9)

(*) M3100
(Hardware Port: M3100, Device: en12)

(3) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(4) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(5) iPhone USB
(Hardware Port: iPhone USB, Device: en11)
"""


def test_parses_every_service_including_disabled():
    services = parse_service_order(REAL_LISTING)
    assert [s.name for s in services] == [
        "AX88179B",
        "USB 10/100/1000 LAN",
        "USB 10/100/1G/2.5G LAN",
        "M3100",
        "Thunderbolt Bridge",
        "Wi-Fi",
        "iPhone USB",
    ]


def test_header_line_is_not_parsed_as_a_service():
    services = parse_service_order(REAL_LISTING)
    assert all("asterisk" not in s.name for s in services)
    assert len(services) == 7


def test_disabled_services_are_marked_but_kept():
    services = parse_service_order(REAL_LISTING)
    disabled = [s.name for s in services if not s.enabled]
    assert disabled == ["USB 10/100/1G/2.5G LAN", "M3100"]


def test_devices_are_extracted():
    services = parse_service_order(REAL_LISTING)
    devices = {s.name: s.device for s in services}
    assert devices["Wi-Fi"] == "en0"
    assert devices["AX88179B"] == "en6"
    assert devices["Thunderbolt Bridge"] == "bridge0"


def test_names_with_slashes_and_spaces_survive_verbatim():
    services = parse_service_order(REAL_LISTING)
    assert find_service(services, "USB 10/100/1G/2.5G LAN") is not None
    assert find_service(services, "USB 10/100/1000 LAN") is not None


def test_find_service_is_exact_not_prefix():
    """The two USB adapters share a prefix; a prefix match would reorder the
    wrong physical link.
    """
    services = parse_service_order(REAL_LISTING)
    assert find_service(services, "USB 10/100") is None
    assert find_service(services, "wi-fi") is None  # case-sensitive


def test_promote_moves_target_to_front_and_keeps_everything_else():
    services = parse_service_order(REAL_LISTING)
    order = promote(services, "Wi-Fi")
    assert order[0] == "Wi-Fi"
    assert len(order) == 7
    assert set(order) == {s.name for s in services}
    # Relative order of the untouched services is preserved.
    assert order[1:] == [
        "AX88179B",
        "USB 10/100/1000 LAN",
        "USB 10/100/1G/2.5G LAN",
        "M3100",
        "Thunderbolt Bridge",
        "iPhone USB",
    ]


def test_promote_keeps_disabled_services_in_the_order():
    services = parse_service_order(REAL_LISTING)
    order = promote(services, "Wi-Fi")
    assert "USB 10/100/1G/2.5G LAN" in order
    assert "M3100" in order


def test_promote_returns_none_for_unknown_service():
    services = parse_service_order(REAL_LISTING)
    assert promote(services, "Ethernet") is None


def test_promote_of_already_first_service_is_a_no_op_permutation():
    services = parse_service_order(REAL_LISTING)
    order = promote(services, "AX88179B")
    assert order == [s.name for s in services]


def test_empty_input_parses_to_empty_not_a_crash():
    assert parse_service_order("") == []
    assert parse_service_order("command not found") == []


def test_service_without_hardware_port_line_has_no_device():
    services = parse_service_order("(1) Weird Service\n")
    assert services == [NetworkService(name="Weird Service", device=None, enabled=True)]


def test_is_order_intact_accepts_a_true_permutation():
    services = parse_service_order(REAL_LISTING)
    assert is_order_intact(services, promote(services, "Wi-Fi")) is True


def test_is_order_intact_rejects_a_dropped_service():
    """The exact accident this guard exists for."""
    services = parse_service_order(REAL_LISTING)
    truncated = [s.name for s in services if s.name != "M3100"]
    assert is_order_intact(services, truncated) is False


def test_is_order_intact_rejects_duplicates_and_extras():
    services = parse_service_order(REAL_LISTING)
    names = [s.name for s in services]
    assert is_order_intact(services, names[:-1] + ["Wi-Fi"]) is False
    assert is_order_intact(services, names + ["Ethernet"]) is False


def test_is_order_intact_rejects_a_flag_shaped_service_name():
    """Each name becomes its own argv token for networksetup; a name starting
    with '-' would be read as a flag.
    """
    services = parse_service_order("(1) -v\n(2) Wi-Fi\n")
    assert is_order_intact(services, ["-v", "Wi-Fi"]) is False


def test_is_order_intact_rejects_empty_current_list():
    """An unparseable listing must never authorize a reorder."""
    assert is_order_intact([], []) is False
    assert is_order_intact([], ["Wi-Fi"]) is False


def test_is_order_intact_refuses_a_listing_with_duplicate_names():
    """macOS keys services by id, so two services can share a name. A name
    list cannot express which is which, so no reorder built from it is safe.
    """
    services = parse_service_order("(1) Wi-Fi\n(2) Wi-Fi\n(3) Ethernet\n")
    assert is_order_intact(services, ["Wi-Fi", "Wi-Fi", "Ethernet"]) is False
    assert is_order_intact(services, ["Ethernet", "Wi-Fi", "Wi-Fi"]) is False


def test_service_name_whitespace_survives_the_parse():
    """The name has to reach networksetup exactly as the listing printed it.
    Trimming it makes the guard's before/after comparison pass while the argv
    names a service that does not exist.
    """
    services = parse_service_order("(1) Wi-Fi \n")
    assert services[0].name == "Wi-Fi "


def test_order_argv_is_built_only_from_an_intact_order():
    services = parse_service_order(REAL_LISTING)
    order = promote(services, "Wi-Fi")
    assert order_argv(services, order) == ["networksetup", "-ordernetworkservices", *order]
    assert order_argv(services, order[:-1]) is None
    assert order_argv([], ["Wi-Fi"]) is None
