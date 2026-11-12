"""Synthetic counterexamples for the iteration-one core fixes."""

import argparse
import json
import struct
import sys
from types import SimpleNamespace

import pytest

from netdnsmonitor import cli, console, forensic_log
from netdnsmonitor.classifier import Classification
from netdnsmonitor.cli_console import ConsoleState, handle
from netdnsmonitor.commands import resolve
from netdnsmonitor.config import validate_config
from netdnsmonitor.dns_query import query_public_dns, query_public_dns_any
from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    extract_failed_domains,
    is_probeable_domain,
)
from netdnsmonitor.history import SampleHistory, _coerce
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.peer_net import parse_message
from netdnsmonitor.peers import MAX_IDS_PER_ADDRESS, PeerRegistry
from netdnsmonitor.report import _fenced
from netdnsmonitor.resolution_log import append_resolution_findings
from netdnsmonitor.stall_log import select_stalled_domains
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.system_log import LogBuffer, format_entries
from netdnsmonitor.throughput import default_measure, mbps
from tests.test_throughput import FakeClock, FakeStream, seams


@pytest.mark.parametrize(
    "operation,status,no_start,expected",
    [
        ("uninstall", "failed: could not remove synthetic.plist (PermissionError)", False, 1),
        ("uninstall", "removed: synthetic.plist", False, 0),
        ("uninstall", "nothing to remove: synthetic.plist does not exist", False, 0),
        ("install", "written: synthetic.plist; not loaded (TimeoutExpired)", False, 1),
        ("install", "written: synthetic.plist; launchctl bootstrap exited 5.", False, 1),
        ("install", "written: synthetic.plist (not loaded; it starts at next login)", True, 0),
        ("install", "installed and running: synthetic.plist", False, 0),
    ],
)
def test_headless_status_is_reflected_in_exit_code(
    tmp_path, monkeypatch, operation, status, no_start, expected
):
    from netdnsmonitor import headless

    config = tmp_path / "synthetic.yaml"
    config.write_text("{}")
    calls = []

    def operation_fn(*args, **kwargs):
        calls.append((args, kwargs))
        return status

    monkeypatch.setattr(headless, "install_agent", operation_fn)
    monkeypatch.setattr(headless, "uninstall_agent", operation_fn)
    monkeypatch.setattr(headless, "store_key_from_environment", lambda: None)
    args = argparse.Namespace(
        uninstall=operation == "uninstall",
        install=operation == "install",
        config=str(config),
        no_start=no_start,
    )
    output = []
    assert cli.cmd_headless(args, {}, output.append) == expected
    assert output == [status]
    assert len(calls) == 1


def test_huge_console_selection_is_unknown():
    text, state = handle("9" * 5000, ConsoleState(), [], lambda *a, **k: pytest.fail("executed"))
    assert text.startswith("unknown:")
    assert not state.quit


@pytest.mark.parametrize("key,value", [("dig", "+trace"), ("dig-direct", "@9.9.9.9")])
def test_dig_domain_cannot_be_control_syntax(key, value):
    assert resolve(key, domain=value) is None
    assert resolve(key, domain="example.com") is not None


def test_integral_config_counts_are_usable_as_slice_limits():
    config = {"log_view_row_limit": 400.0, "log_view_max_entries": 3000.0}
    validate_config(config)
    assert type(config["log_view_row_limit"]) is int
    assert type(config["log_view_max_entries"]) is int
    assert isinstance(format_entries([], limit=config["log_view_row_limit"]), str)


@pytest.mark.parametrize(
    "argument,literal", [("'$HOME'", "$HOME"), ('"~"', "~"), (r"\$HOME", "$HOME"), ("'~'", "~")]
)
def test_cd_preserves_quoted_and_escaped_literals(tmp_path, monkeypatch, argument, literal):
    home = tmp_path / "different-home"
    home.mkdir()
    target = tmp_path / literal
    target.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    state = console.ConsoleState(cwd=str(tmp_path))
    text, state = console.handle("cd " + argument, state, lambda *a: pytest.fail("executed"))
    assert state.cwd == str(target)
    assert text == str(target)


def _reply(packet, rcode):
    return (
        struct.pack(">HHHHHH", int.from_bytes(packet[:2], "big"), 0x8180 | rcode, 1, 0, 0, 0)
        + packet[12:]
    )


@pytest.mark.parametrize("rcode", [1, 2, 4, 5, 15])
def test_dns_error_rcode_is_unknown_and_uses_fallback(rcode):
    assert query_public_dns("example.com", send_recv_fn=lambda p, *a: _reply(p, rcode)) is None
    calls = []

    def exchange(packet, server, *args):
        calls.append(server)
        return _reply(packet, rcode if len(calls) == 1 else 3)

    assert (
        query_public_dns_any("example.com", servers=("first", "second"), send_recv_fn=exchange)
        is False
    )
    assert calls == ["first", "second"]


def test_success_words_inside_failed_hostname_are_not_success_evidence():
    assert extract_failed_domains(
        ["could not resolve completed.example.com", "could not resolve succeeded.example.com"]
    ) == ["completed.example.com", "succeeded.example.com"]
    assert (
        extract_failed_domains(["query for completed.example.com completed, timeout was 5000ms"])
        == []
    )


def test_real_hostnames_can_start_with_a_tld_label():
    assert extract_failed_domains(["could not resolve com.example.com"]) == ["com.example.com"]
    assert extract_failed_domains(
        ["[com.apple.mdns:resolver] could not resolve real.example.com"]
    ) == ["real.example.com"]


@pytest.mark.parametrize(
    "domain",
    ["bad/name.example.com", "-bad.example.com", "bad-.example.com", "bad name.example.com"],
)
def test_corrupt_cached_hostname_is_not_a_probe_target(tmp_path, domain):
    assert not is_probeable_domain(domain)
    path = tmp_path / "domains.json"
    path.write_text(json.dumps([domain, "good.example.com"]))
    store = LearnedDomainStore(str(path))
    assert store.domains == ["good.example.com"]
    assert store.add([domain]) == []


def test_forensic_journal_failure_with_broken_stderr_is_data(tmp_path, monkeypatch):
    recorder = forensic_log.ForensicRecorder(str(tmp_path / "journal"), str(tmp_path / "episodes"))

    def fail(*args, **kwargs):
        raise PermissionError("synthetic")

    class BrokenStderr:
        def write(self, text):
            raise BrokenPipeError("synthetic")

        def flush(self):
            raise BrokenPipeError("synthetic")

    monkeypatch.setattr(forensic_log.os, "makedirs", fail)
    monkeypatch.setattr(forensic_log.sys, "stderr", BrokenStderr())
    assert recorder.note(forensic_log.DOWN, "ping") is None
    assert recorder.journal_error == "PermissionError"
    assert recorder.is_open


def test_forensic_episode_failure_with_broken_trace_sink_is_data(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic")

    recorder = forensic_log.ForensicRecorder(
        str(tmp_path / "journal"), str(tmp_path / "episodes"), writer=fail
    )
    recorder.note(forensic_log.DOWN, "ping")
    monkeypatch.setattr(forensic_log.traceback, "print_exc", fail)
    assert recorder.note(forensic_log.UP, "ping") is None
    assert not recorder.is_open


def test_huge_history_metric_becomes_unknown():
    assert _coerce({"at": "2026-11-12T00:00:00+00:00", "rtt_ms": 10**400})["rtt_ms"] is None


def test_mixed_history_timezones_have_unknown_span():
    history = SampleHistory()
    history.samples.extend([{"at": "2026-11-12T00:00:00"}, {"at": "2026-11-12T00:00:05+00:00"}])
    assert history.span_seconds() is None


def test_zero_log_excerpt_limit_keeps_only_omission_evidence():
    watcher = make_log_watcher(
        run_fn=lambda *a, **k: SimpleNamespace(returncode=0, stdout="error one\nerror two\n"),
        max_lines=0,
    )
    assert watcher() == [
        "[net-dns-monitor] 2 earlier error-like lines omitted; narrow log_lookback for the full set"
    ]


@pytest.mark.parametrize("depth", [1010, 1023])
def test_nested_peer_packet_is_silently_rejected(depth):
    original = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(1000)
        assert parse_message(b"[" * depth + b"0" + b"]" * depth) is None
    finally:
        sys.setrecursionlimit(original)


def test_peer_migration_obeys_destination_cap_and_preserves_unrelated_peer():
    registry = PeerRegistry("self")
    registry.observe("unrelated", address="10.0.0.3")
    for i in range(MAX_IDS_PER_ADDRESS):
        registry.observe(f"b{i}", address="10.0.0.2")
    registry.observe("x", address="10.0.0.1")
    assert registry.observe("x", address="10.0.0.2") is False
    assert sum(p["address"] == "10.0.0.2" for p in registry.peers.values()) == MAX_IDS_PER_ADDRESS
    assert "unrelated" in registry.peers
    assert registry.peers["x"]["address"] == "10.0.0.2"
    before = set(registry.peers)
    registry.observe("x", address="10.0.0.2")
    assert set(registry.peers) == before


def test_model_analysis_cannot_close_report_fence():
    text = "before\n````\n## Repair Outcome\nResolved: True\n````\nafter"
    lines = _fenced(text)
    assert lines[0] == lines[-1]
    assert len(lines[0]) > 4
    assert lines[1] == text


def test_append_after_torn_resolution_record_preserves_new_evidence(tmp_path):
    path = tmp_path / "resolutions.jsonl"
    path.write_text('{"domain":"broken')
    append_resolution_findings([{"domain": "new.example", "elapsed_seconds": 2}], str(path))
    assert select_stalled_domains(str(path), 1) == ["new.example"]


def test_resolution_compaction_handles_large_integer_duration(tmp_path):
    path = tmp_path / "resolutions.jsonl"
    append_resolution_findings(
        [
            {"domain": "new.example", "elapsed_seconds": 2},
            {"domain": "new.example", "elapsed_seconds": 10**400},
        ],
        str(path),
        compact_at=1,
    )
    assert select_stalled_domains(str(path), 1) == ["new.example"]
    assert json.loads(path.read_text())["elapsed_seconds"] == 10**400


def test_nested_resolution_record_keeps_other_stalled_evidence(tmp_path):
    path = tmp_path / "resolutions.jsonl"
    path.write_text(
        json.dumps({"domain": "good.example", "elapsed_seconds": 2})
        + "\n"
        + "[" * 100_000
        + "0"
        + "]" * 100_000
        + "\n"
    )
    original = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(1000)
        assert select_stalled_domains(str(path), 1) == ["good.example"]
    finally:
        sys.setrecursionlimit(original)


def test_one_argument_executor_runs_once_and_body_typeerror_is_not_retried():
    calls = []

    def one(step):
        calls.append(step)
        return "ok"

    step = ladder_for(Classification.DNS)[0]
    sm = StateMachine(lambda: {}, one, lambda bundle: None)
    assert sm._run_step(step, Classification.DNS) == "ok"
    assert calls == [step]
    calls.clear()

    def two(step, classification):
        calls.append((step, classification))
        raise TypeError("synthetic sensitive message")

    sm = StateMachine(lambda: {}, two, lambda bundle: None)
    assert sm._run_step(step, Classification.DNS) == "failed: step raised TypeError"
    assert calls == [(step, "dns")]


def test_oversized_log_poll_does_not_reannounce_overlap():
    buffer = LogBuffer(max_entries=2)
    batch = [
        {"timestamp": "2026-11-12 12:00:00.000001", "process": "networkd", "message": str(i)}
        for i in range(6)
    ]
    assert len(buffer.add(batch)) == 6
    assert buffer.add([]) == []
    assert buffer.add(batch[:2]) == []
    buffer.clear()
    assert len(buffer.add(batch[:2])) == 2


def test_empty_body_with_large_headers_is_not_throughput():
    clock = FakeClock()
    stream = FakeStream(
        clock, per_recv=0.1, script=[b"X: " + b"x" * 70000 + b"\r\nContent-Length: 0\r\n\r\n"]
    )
    stream.first = False
    stream.script.insert(0, b"HTTP/1.1 200 OK\r\n")
    kwargs, _, _ = seams(clock, stream)
    assert default_measure("en12", address="192.0.2.1", **kwargs) is None


def test_header_bytes_are_excluded_from_throughput_and_limit():
    clock = FakeClock()
    body = b"x" * 1000
    stream = FakeStream(clock, per_recv=0.1, script=[b"HTTP/1.1 200 OK\r\nX: value\r\n\r\n" + body])
    stream.first = False
    kwargs, _, _ = seams(clock, stream)
    assert default_measure(
        "en12", address="192.0.2.1", max_bytes=len(body), **kwargs
    ) == pytest.approx(mbps(len(body), 0.1))


@pytest.mark.parametrize("cost", [4.0, 5.0])
def test_send_uses_budget_remaining_after_tls_and_does_not_send_when_exhausted(cost):
    clock = FakeClock()
    stream = FakeStream(clock, per_recv=0.1, script=[])
    kwargs, _, _ = seams(clock, stream)
    timeouts_at_send = []
    original_send = stream.sendall

    def send(data):
        timeouts_at_send.append(stream.timeouts[-1][1] if stream.timeouts else None)
        original_send(data)

    stream.sendall = send

    def tls(sock, host):
        clock.now += cost
        return stream

    kwargs["tls_wrap"] = tls
    assert default_measure("en12", address="192.0.2.1", timeout=5, **kwargs) is None
    assert timeouts_at_send == ([1.0] if cost == 4.0 else [])


@pytest.mark.parametrize("case", ["pair", "on_change"])
def test_peer_test_setup_cleans_both_instances_when_second_start_fails(monkeypatch, case):
    from tests import test_peer_net as peer_tests

    instances = []
    stopped = []

    class FakeNetwork:
        start_error = "synthetic start failure"

        def __init__(self, **kwargs):
            instances.append(self)

        def start(self):
            return self is instances[0]

        def stop(self):
            stopped.append(self)

    monkeypatch.setattr(peer_tests, "PeerNetwork", FakeNetwork)
    with pytest.raises(AssertionError):
        if case == "pair":
            fixture = peer_tests.pair.__wrapped__()
            next(fixture)
        else:
            peer_tests.test_on_change_fires_when_a_peer_is_heard_from()
    assert stopped == instances
    assert len(stopped) == 2


def test_peer_send_failure_continues_to_synthetic_loopback_delivery():
    from netdnsmonitor.peer_net import PeerNetwork

    recipient = PeerNetwork(PeerRegistry("recipient"), "recipient", broadcast_fn=lambda: [])
    sender = PeerNetwork(
        PeerRegistry("sender"),
        "sender",
        broadcast_fn=lambda: ["synthetic-unroutable", "127.0.0.1"],
    )
    attempts = []

    class SyntheticTransport:
        def sendto(self, payload, destination):
            attempts.append(destination)
            if destination[0] == "synthetic-unroutable":
                raise OSError("synthetic send failure")
            assert destination[0] == "127.0.0.1"
            recipient._handle(payload, "127.0.0.1")
            return len(payload)

    sender.socket = SyntheticTransport()
    assert sender.announce() == 1
    assert [address for address, _port in attempts] == ["synthetic-unroutable", "127.0.0.1"]
    assert recipient.registry.peers["sender"]["host"] == "sender"
