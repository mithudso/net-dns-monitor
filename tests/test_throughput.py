"""Offline. `default_measure` was verified by hand against real interfaces:
en0 measured 3.8 Mbps against Cloudflare's endpoint, and every inactive
interface returned None rather than 0.0.
"""

import time

from netdnsmonitor.failover_policy import Candidate, best_candidate, rank_candidates
from netdnsmonitor.throughput import (
    is_success_status,
    make_throughput_meter,
    mbps,
    measure_all,
)

# --- meter ------------------------------------------------------------------


def test_meter_returns_the_measurement():
    meter = make_throughput_meter(measure_fn=lambda dev, **kw: 94.2)
    assert meter("en0") == 94.2


def test_no_device_is_not_measured():
    meter = make_throughput_meter(measure_fn=lambda dev, **kw: 94.2)
    assert meter(None) is None
    assert meter("") is None


def test_an_empty_host_disables_measurement_entirely():
    """Ranking then falls back to reachability rather than inventing numbers."""
    calls = []
    meter = make_throughput_meter(host="", measure_fn=lambda dev, **kw: calls.append(dev) or 1.0)
    assert meter("en0") is None
    assert calls == []


def test_a_raising_measurement_is_not_measured_rather_than_an_error():
    def boom(dev, **kw):
        raise OSError("interface went away mid-benchmark")

    assert make_throughput_meter(measure_fn=boom)("en0") is None


def test_measurement_parameters_reach_the_measure_function():
    seen = {}

    def capture(dev, **kw):
        seen.update(kw)
        seen["device"] = dev
        return 1.0

    meter = make_throughput_meter(
        host="h", path="/p", port=8443, timeout=9.0, max_bytes=5, measure_fn=capture
    )
    meter("en3")
    seen.pop("address", None)  # resolved once by the meter, not a caller concern
    assert seen == {
        "device": "en3",
        "host": "h",
        "path": "/p",
        "port": 8443,
        "timeout": 9.0,
        "max_bytes": 5,
    }


# --- ranking ----------------------------------------------------------------


def test_fastest_reachable_candidate_wins():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True, throughput_mbps=12.0),
            Candidate("iPhone USB", "en11", reachable=True, throughput_mbps=48.5),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["iPhone USB", "M3100", "Wi-Fi"]


def test_unreachable_candidates_are_never_eligible_however_fast():
    """Reachability is a gate, not a factor. A fast-looking but unverified path
    must never beat a slow proven one.
    """
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=False, throughput_mbps=999.0),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["Wi-Fi"]


def test_unprobed_candidates_are_never_eligible():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=None, throughput_mbps=999.0),
        ]
    )
    assert ranked == []


def test_unmeasured_but_reachable_ranks_after_measured_and_still_counts():
    """ "Unknown speed" is a better bet than no link at all."""
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True, throughput_mbps=None),
            Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
        ]
    )
    assert [c.name for c in ranked] == ["Wi-Fi", "M3100"]


def test_ties_keep_configured_order():
    ranked = rank_candidates(
        [
            Candidate("first", "en1", reachable=True, throughput_mbps=10.0),
            Candidate("second", "en2", reachable=True, throughput_mbps=10.0),
        ]
    )
    assert [c.name for c in ranked] == ["first", "second"]


def test_all_unmeasured_keeps_configured_order():
    ranked = rank_candidates(
        [
            Candidate("M3100", "en12", reachable=True),
            Candidate("iPhone USB", "en11", reachable=True),
        ]
    )
    assert [c.name for c in ranked] == ["M3100", "iPhone USB"]


def test_zero_throughput_is_a_real_reading_not_a_missing_one():
    """0.0 means "carries nothing" and must rank below a measured link, but
    still above an unmeasured one -- it is evidence, not absence of it.
    """
    ranked = rank_candidates(
        [
            Candidate("dead", "en1", reachable=True, throughput_mbps=0.0),
            Candidate("unknown", "en2", reachable=True, throughput_mbps=None),
            Candidate("good", "en3", reachable=True, throughput_mbps=5.0),
        ]
    )
    assert [c.name for c in ranked] == ["good", "dead", "unknown"]


def test_best_candidate_is_none_when_nothing_is_eligible():
    assert best_candidate([]) is None
    assert best_candidate([Candidate("x", "en1", reachable=False)]) is None


# --- the pieces of default_measure that can be tested without a socket ------


def test_status_line_split_across_reads_is_still_2xx():
    """A first TCP/TLS segment shorter than the status line used to read as
    non-2xx, reporting a healthy link as unmeasurable.
    """
    assert is_success_status(b"HTTP/1.1 200 OK\r\n") is True
    assert is_success_status(b"HTTP/1.1 2") is True
    assert is_success_status(b"HTTP/1.1 204 No Content\r\n") is True


def test_non_2xx_is_rejected_so_a_broken_target_is_not_a_slow_interface():
    assert is_success_status(b"HTTP/1.1 301 Moved Permanently\r\n") is False
    assert is_success_status(b"HTTP/1.1 500 Server Error\r\n") is False
    assert is_success_status(b"garbage") is False
    assert is_success_status(b"") is False


def test_mbps_arithmetic():
    assert mbps(1_000_000, 1.0) == 8.0
    assert mbps(2_000_000, 2.0) == 8.0


def test_mbps_is_none_rather_than_zero_when_it_would_be_meaningless():
    assert mbps(0, 1.0) is None  # nothing transferred
    assert mbps(1000, 0.0) is None  # no elapsed time
    assert mbps(1000, -1.0) is None  # clock went backwards


def test_measure_all_shares_one_deadline_across_interfaces():
    """Serially this is one timeout each on the UI thread; the whole point is
    that the round costs roughly one.
    """

    def slow(device):
        time.sleep(0.3)
        return 1.0

    started = time.monotonic()
    results = measure_all(["a", "b", "c", "d"], slow, timeout=2.0)
    elapsed = time.monotonic() - started
    assert set(results) == {"a", "b", "c", "d"}
    assert elapsed < 1.0, "measurements must run concurrently, not one after another"


def test_measure_all_reports_a_slow_interface_as_unmeasured_not_a_wait():
    def never(device):
        time.sleep(30)
        return 1.0

    results = measure_all(["stuck"], never, timeout=0.2)
    assert results == {"stuck": None}


def test_measure_all_with_no_devices_is_empty():
    assert measure_all([], lambda d: 1.0, timeout=1.0) == {}
