"""Interface-counter parsing and throughput derivation.

The sample output below is real `/usr/sbin/netstat -ibn` output from this
machine, trimmed to the interesting interfaces. The variable field count in it
is the whole reason this module parses right-anchored -- see net_stats.py.
"""

import subprocess
from types import SimpleNamespace

from netdnsmonitor.net_stats import (
    NETSTAT_BIN,
    ThroughputMeter,
    parse_interface_counters,
    read_interface_counters,
)

# Note the two row shapes: lo0/utun0 have an empty Address column (10 fields),
# en0/en9/awdl0 carry a MAC (11 fields).
NETSTAT_OUTPUT = """Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
lo0        16384 <Link#1>                        546703     0  121334000   546703     0  121334000     0
lo0        16384 127           127.0.0.1         546703     -  121334000   546703     -  121334000     -
gif0*      1280  <Link#2>                             0     0          0        0     0          0     0
en0        1500  <Link#15>   4a:63:a4:bf:16:ed 45800660     0 41636061650 21753714     0 19752595011     0
en0        1500  192.168.1     192.168.1.42     45800660     -  41636061650 21753714     -  19752595011  -
awdl0      1500  <Link#17>   e2:86:5a:a5:ea:ab     5009     0    2499600     5357     0    1250355     0
utun8      1300  <Link#34>                       193060     0   67107906   104358     0   67872775     0
en9        1500  <Link#37>   00:e0:4c:ff:bd:bf  2092359     0 1103462569  1505923     0 1110772437     0
"""

EN0_IN, EN0_OUT = 41636061650, 19752595011
EN9_IN, EN9_OUT = 1103462569, 1110772437


def test_sums_only_the_ethernet_and_wifi_interfaces():
    assert parse_interface_counters(NETSTAT_OUTPUT) == (EN0_IN + EN9_IN, EN0_OUT + EN9_OUT)


def test_parses_rows_whose_address_column_is_empty():
    """The discriminating case. Link rows are 11 fields when the interface has
    a MAC and 10 when it doesn't, so a left-anchored `fields[6]`/`fields[9]`
    reads Ibytes off one shape and Opkts off the other -- and still returns
    plausible-looking numbers, so nothing downstream would look wrong.
    """
    only_empty_address = """Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en7        1500  <Link#9>                          1000     0      50000      900     0      40000     0
"""
    assert parse_interface_counters(only_empty_address) == (50000, 40000)


def test_excludes_loopback_because_it_is_not_network_traffic():
    assert parse_interface_counters(NETSTAT_OUTPUT)[0] < 121334000 + EN0_IN + EN9_IN


def test_excludes_vpn_tunnels_to_avoid_double_counting():
    """utun traffic is carried over en0 as well, so it is already inside the
    en* totals. Counting both reports roughly double the real rate whenever a
    VPN is up -- which on this machine is most of the time.
    """
    assert 67107906 not in parse_interface_counters(NETSTAT_OUTPUT)
    assert parse_interface_counters(NETSTAT_OUTPUT)[0] == EN0_IN + EN9_IN


def test_excludes_airdrop_peer_links():
    assert parse_interface_counters(NETSTAT_OUTPUT)[0] == EN0_IN + EN9_IN


def test_counts_each_interface_once_not_once_per_address():
    """Only `<Link#N>` rows carry the interface totals; the per-address rows
    below each one repeat the same numbers. Summing every row multiplies the
    total by however many addresses the interface happens to have.
    """
    doubled = NETSTAT_OUTPUT + (
        "en0        1500  fe80::1%en0 fe80:f::1     45800660     -  41636061650 21753714"
        "     -  19752595011  -\n"
    )
    assert parse_interface_counters(doubled) == parse_interface_counters(NETSTAT_OUTPUT)


def test_counts_an_interface_that_is_currently_down():
    """netstat marks a down interface with a trailing `*` on the name. Its
    accumulated bytes still belong in the total -- and more importantly, a
    Wi-Fi interface that just dropped must not silently change which
    interfaces are summed, which would look like a huge negative delta.
    """
    down = """Name       Mtu   Network       Address            Ipkts Ierrs     Ibytes    Opkts Oerrs     Obytes  Coll
en0*       1500  <Link#15>   4a:63:a4:bf:16:ed     1000     0      50000      900     0      40000     0
"""
    assert parse_interface_counters(down) == (50000, 40000)


def test_malformed_rows_are_skipped_rather_than_raising():
    """This runs every 5 seconds forever; one unexpected line must not take
    the heartbeat down.
    """
    junk = NETSTAT_OUTPUT + "en0        1500  <Link#15>   4a:63:a4:bf:16:ed  -  -  -  -\n"
    assert parse_interface_counters(junk) == (EN0_IN + EN9_IN, EN0_OUT + EN9_OUT)


def test_empty_output_is_zero_not_an_error():
    assert parse_interface_counters("") == (0, 0)


def test_read_interface_counters_uses_the_absolute_netstat_path():
    """launchd's minimal PATH again: a bare `netstat` resolves in a shell and
    not in the installed bundle.
    """
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=NETSTAT_OUTPUT, stderr="")

    read_interface_counters(run_fn=fake_run)
    assert calls[0][0] == [NETSTAT_BIN, "-ibn"]
    assert NETSTAT_BIN.startswith("/")


def test_read_interface_counters_requests_explicit_utf8_decoding():
    calls = []

    def fake_run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=NETSTAT_OUTPUT, stderr="")

    read_interface_counters(run_fn=fake_run)
    assert calls[0][1]["encoding"] == "utf-8"
    assert calls[0][1]["errors"] == "replace"


def test_read_interface_counters_returns_none_when_netstat_fails():
    def fake_run(args, **kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")

    assert read_interface_counters(run_fn=fake_run) is None


def test_read_interface_counters_returns_none_instead_of_raising():
    def missing(args, **kwargs):
        raise FileNotFoundError("no such file: /usr/sbin/netstat")

    assert read_interface_counters(run_fn=missing) is None


def test_read_interface_counters_survives_a_subprocess_timeout():
    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=5)

    assert read_interface_counters(run_fn=timing_out) is None


# --- ThroughputMeter -------------------------------------------------------


def test_first_sample_has_no_rate_yet():
    """A rate needs two readings. Reporting the raw cumulative total as a rate
    would show tens of gigabits per second on the first tick.
    """
    meter = ThroughputMeter()
    assert meter.sample((1000, 500), now=100.0) == (None, None)


def test_second_sample_reports_bits_per_second():
    meter = ThroughputMeter()
    meter.sample((1000, 500), now=100.0)
    down, up = meter.sample((1000 + 6250, 500 + 1250), now=105.0)
    # 6250 bytes over 5s = 1250 B/s = 10_000 bits/s.
    assert down == 10_000
    assert up == 2_000


def test_counter_reset_reports_no_rate_rather_than_a_negative_one():
    """Totals can go down: a reboot, a sleep/wake that re-creates interfaces,
    or an unplugged dock Ethernet whose row disappears from netstat entirely.
    A negative delta rendered as a rate shows a nonsense figure like -4.2M.
    """
    meter = ThroughputMeter()
    meter.sample((10_000_000, 10_000_000), now=100.0)
    assert meter.sample((5_000, 5_000), now=105.0) == (None, None)


def test_recovers_on_the_sample_after_a_counter_reset():
    """The reset must re-baseline, not wedge the meter. Returning None forever
    after one dock unplug would leave the throughput half of the stats blank
    for the rest of the process's life.
    """
    meter = ThroughputMeter()
    meter.sample((10_000_000, 10_000_000), now=100.0)
    meter.sample((5_000, 5_000), now=105.0)
    down, up = meter.sample((5_000 + 6250, 5_000 + 1250), now=110.0)
    assert down == 10_000
    assert up == 2_000


def test_zero_elapsed_time_reports_no_rate_instead_of_dividing_by_zero():
    meter = ThroughputMeter()
    meter.sample((1000, 500), now=100.0)
    assert meter.sample((2000, 1500), now=100.0) == (None, None)


def test_time_going_backwards_reports_no_rate():
    """`now` defaults to time.monotonic(), which cannot go backwards -- but the
    parameter is injectable and a wall-clock caller would be a plausible
    mistake, so fail closed rather than emit a negative rate.
    """
    meter = ThroughputMeter()
    meter.sample((1000, 500), now=100.0)
    assert meter.sample((2000, 1500), now=95.0) == (None, None)


def test_an_idle_interval_reports_zero_not_none():
    """Zero is a real reading and must be distinguishable from "not measured
    yet" -- the title renders them differently.
    """
    meter = ThroughputMeter()
    meter.sample((1000, 500), now=100.0)
    assert meter.sample((1000, 500), now=105.0) == (0.0, 0.0)
