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
    lines = ["reply from 10.0.0.1 for example.com."]
    top = extract_top_domains(lines, limit=50)
    assert "10.0.0.1" not in top
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
    assert captured["args"][:2] == ["log", "show"]
    assert "1h" in captured["args"]
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
