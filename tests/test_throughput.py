"""Offline. `default_measure` was verified by hand against real interfaces:
en0 measured 3.8 Mbps against Cloudflare's endpoint, and every inactive
interface returned None rather than 0.0.
"""

from netdnsmonitor.failover_policy import Candidate, best_candidate, rank_candidates
from netdnsmonitor.throughput import make_throughput_meter


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
    meter = make_throughput_meter(
        host="", measure_fn=lambda dev, **kw: calls.append(dev) or 1.0
    )
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
    assert seen == {
        "device": "en3", "host": "h", "path": "/p",
        "port": 8443, "timeout": 9.0, "max_bytes": 5,
    }


# --- ranking ----------------------------------------------------------------


def test_fastest_reachable_candidate_wins():
    ranked = rank_candidates([
        Candidate("M3100", "en12", reachable=True, throughput_mbps=12.0),
        Candidate("iPhone USB", "en11", reachable=True, throughput_mbps=48.5),
        Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
    ])
    assert [c.name for c in ranked] == ["iPhone USB", "M3100", "Wi-Fi"]


def test_unreachable_candidates_are_never_eligible_however_fast():
    """Reachability is a gate, not a factor. A fast-looking but unverified path
    must never beat a slow proven one.
    """
    ranked = rank_candidates([
        Candidate("M3100", "en12", reachable=False, throughput_mbps=999.0),
        Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
    ])
    assert [c.name for c in ranked] == ["Wi-Fi"]


def test_unprobed_candidates_are_never_eligible():
    ranked = rank_candidates([
        Candidate("M3100", "en12", reachable=None, throughput_mbps=999.0),
    ])
    assert ranked == []


def test_unmeasured_but_reachable_ranks_after_measured_and_still_counts():
    """"Unknown speed" is a better bet than no link at all."""
    ranked = rank_candidates([
        Candidate("M3100", "en12", reachable=True, throughput_mbps=None),
        Candidate("Wi-Fi", "en0", reachable=True, throughput_mbps=3.8),
    ])
    assert [c.name for c in ranked] == ["Wi-Fi", "M3100"]


def test_ties_keep_configured_order():
    ranked = rank_candidates([
        Candidate("first", "en1", reachable=True, throughput_mbps=10.0),
        Candidate("second", "en2", reachable=True, throughput_mbps=10.0),
    ])
    assert [c.name for c in ranked] == ["first", "second"]


def test_all_unmeasured_keeps_configured_order():
    ranked = rank_candidates([
        Candidate("M3100", "en12", reachable=True),
        Candidate("iPhone USB", "en11", reachable=True),
    ])
    assert [c.name for c in ranked] == ["M3100", "iPhone USB"]


def test_zero_throughput_is_a_real_reading_not_a_missing_one():
    """0.0 means "carries nothing" and must rank below a measured link, but
    still above an unmeasured one -- it is evidence, not absence of it.
    """
    ranked = rank_candidates([
        Candidate("dead", "en1", reachable=True, throughput_mbps=0.0),
        Candidate("unknown", "en2", reachable=True, throughput_mbps=None),
        Candidate("good", "en3", reachable=True, throughput_mbps=5.0),
    ])
    assert [c.name for c in ranked] == ["good", "dead", "unknown"]


def test_best_candidate_is_none_when_nothing_is_eligible():
    assert best_candidate([]) is None
    assert best_candidate([Candidate("x", "en1", reachable=False)]) is None
