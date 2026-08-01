from types import SimpleNamespace

from netdnsmonitor.query_log import (
    extract_top_domains,
    make_query_log_reader,
)

SAMPLE_LOG = "\n".join(
    [
        "2026-07-20 09:00:01 mDNSResponder: Q for example.com. A",
        "2026-07-20 09:00:02 mDNSResponder: Q for example.com. AAAA",
        "2026-07-20 09:00:03 mDNSResponder: Q for api.example.com. A",
        "2026-07-20 09:00:04 mDNSResponder: Q for example.com. A",
        "2026-07-20 09:00:05 networkd: interface en0 came up",
        "2026-07-20 09:00:06 mDNSResponder: Q for corp.local. A",
        "2026-07-20 09:00:07 mDNSResponder: reply from 10.0.0.1 for corp.local.",
    ]
)


def test_extract_top_domains_orders_by_frequency():
    lines = SAMPLE_LOG.splitlines()
    top = extract_top_domains(lines, limit=50)
    assert top[0] == "example.com"
    assert "api.example.com" in top
    assert "corp.local" in top


def test_extract_top_domains_respects_limit():
    lines = SAMPLE_LOG.splitlines()
    top = extract_top_domains(lines, limit=2)
    assert len(top) == 2
    assert top[0] == "example.com"


def test_extract_top_domains_ignores_ip_addresses():
    # The final label must be all-alphabetic; that is what keeps an IPv4
    # address out of the counts. Exercising it needs a final octet of two or
    # more digits: with a single-digit octet ("10.0.0.1") the {2,63} length
    # floor rejects the address on its own, so the character class could be
    # loosened to [a-zA-Z0-9] -- deleting exactly the rule the module docstring
    # advertises -- and this test could not fail. Real mDNSResponder lines
    # carry resolver addresses, and a leaked IP enters the ever-growing stall
    # set permanently.
    lines = [
        "reply from 10.0.0.1 for example.com.",
        "reply from 192.168.1.10 for example.com.",
        "reply from 172.16.254.100 for example.com.",
    ]
    top = extract_top_domains(lines, limit=50)
    assert "10.0.0.1" not in top
    assert "192.168.1.10" not in top
    assert "172.16.254.100" not in top
    assert "example.com" in top


def test_extract_top_domains_returns_empty_for_no_matches():
    assert extract_top_domains(["networkd: interface en0 came up"], limit=50) == []


def test_query_log_reader_invokes_log_show_with_lookback_window():
    captured = {}

    def run_fn(args, **kwargs):
        captured["args"] = args
        return SimpleNamespace(returncode=0, stdout=SAMPLE_LOG, stderr="")

    reader = make_query_log_reader(run_fn=run_fn, lookback="1h")
    lines = reader()
    args = captured["args"]
    assert args[:2] == ["log", "show"]
    # Flag/value pair, not bare membership -- see test_log_watcher.py for why.
    assert args[args.index("--last") + 1] == "1h"
    assert any("example.com" in line for line in lines)


def test_query_log_reader_returns_empty_list_when_command_fails():
    run_fn = lambda args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="denied")
    reader = make_query_log_reader(run_fn=run_fn)
    assert reader() == []


def test_query_log_reader_returns_empty_list_on_subprocess_timeout():
    import subprocess

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    reader = make_query_log_reader(run_fn=timing_out)
    assert reader() == []


def test_requests_explicit_utf8_decoding_instead_of_relying_on_locale():
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_query_log_reader(run_fn=run_fn)()
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"


def test_returns_empty_list_on_unicode_decode_error_instead_of_raising():
    def bad_decode(args, **kwargs):
        raise UnicodeDecodeError("ascii", b"\xe2", 0, 1, "ordinal not in range(128)")

    reader = make_query_log_reader(run_fn=bad_decode)
    assert reader() == []


def test_returns_empty_list_when_the_log_binary_is_missing_instead_of_raising():
    """The OSError arm of the except clause. See the matching test in
    test_log_watcher.py.
    """

    def missing_binary(args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "log")

    reader = make_query_log_reader(run_fn=missing_binary)
    assert reader() == []


def test_bounds_the_log_show_call_and_captures_its_output():
    """timeout= and capture_output= are supplied for free by every fake here,
    so nothing else pins them. See test_log_watcher.py for what each prevents.
    """
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_query_log_reader(run_fn=run_fn)()
    assert captured.get("timeout") == 10
    assert captured.get("capture_output") is True
    assert captured.get("text") is True
