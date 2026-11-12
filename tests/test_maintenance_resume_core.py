"""Synthetic regressions for the bounded core repair batch."""

import queue
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from netdnsmonitor import (
    app,
    cli,
    config,
    console,
    credentials,
    distribution,
    dns_query,
    domain_learner,
    forensic_log,
    headless,
    privileges,
    router_window,
    settings_window,
    system_log,
    user_notify,
)


@pytest.mark.parametrize(
    "name", ["bad name.example", "bad\tname.example", "bad\x00name.example", "bad\x7fname.example"]
)
def test_domain_controls(name):
    assert config.domain_problem(name) is not None


def test_duplicate_heartbeat_name():
    calls = []

    def ping(host, **kwargs):
        calls.append(host)
        return {"ok": host == "1.1.1.1", "rtt_ms": 1, "error": None}

    cfg = {
        **config.DEFAULT_CONFIG,
        "ping_host_v6": "2001:db8::1",
        "ping_host_name": "2001:db8::1",
        "ping_host": "8.8.8.8",
        "ping_fallback_host": "1.1.1.1",
    }
    assert app.ping_heartbeat(cfg, ping_fn=ping, clock=lambda: 0)["ok"]
    assert calls[-1] == "1.1.1.1"


@pytest.mark.parametrize("argument", ['"a&b"', r"a\&b", "'a&b'"])
def test_cd_quoted_metacharacters(tmp_path, argument):
    (tmp_path / "a&b").mkdir()
    state = console.ConsoleState(cwd=str(tmp_path))
    console.handle("cd " + argument, state)
    assert state.cwd == str(tmp_path / "a&b")


def test_bare_ipconfig():
    assert privileges.covers([privileges.IPCONFIG], [privileges.IPCONFIG, "set", "en0", "DHCP"])
    assert privileges.granted_interfaces_from([privileges.IPCONFIG]) == list(
        privileges.ALL_INTERFACES_SENTINEL
    )


@pytest.mark.parametrize("severities", [("info", "error"), ("error", "info"), ("fault", "error")])
def test_coalesced_severity(severities):
    rows = system_log.coalesce(
        [{"process": "p", "message": "m", "severity": severity} for severity in severities]
    )
    assert rows[0]["severity"] == ("fault" if "fault" in severities else "error")


def test_bootpd_unknown():
    assert "not checked" in router_window.bootpd_status(
        lambda *a, **k: SimpleNamespace(returncode=1, stderr="Permission denied")
    )


@pytest.mark.parametrize(
    "token",
    ["api.example.123", "api.example.bad123", "api.example_", "api.example-", "api.example.."],
)
def test_learner_complete_token(token):
    assert domain_learner.extract_failed_domains(["lookup failed for " + token]) == []


def test_learner_root_dot():
    assert domain_learner.extract_failed_domains(["lookup failed for api.example."]) == [
        "api.example"
    ]


@pytest.mark.parametrize("separator", ["\u3002", "\uff0e", "\uff61"])
def test_idna_wire_question(separator, monkeypatch):
    packets = []

    class Socket:
        def settimeout(self, value):
            pass

        def connect(self, address):
            pass

        def send(self, packet):
            packets.append(packet)

        def recv(self, size):
            raise OSError("synthetic no answer")

        def close(self):
            pass

    monkeypatch.setattr(
        dns_query.socket, "getaddrinfo", lambda *a, **k: [(2, 2, 0, "", ("127.0.0.1", 53))]
    )
    monkeypatch.setattr(dns_query.socket, "socket", lambda *a, **k: Socket())
    assert dns_query.query_public_dns("example" + separator + "com" + separator) is None
    assert packets[0][12:-4] == b"\x07example\x03com\x00"


def test_notify_callback_with_broken_stderr(monkeypatch):
    # conftest replaces post; call the real implementation through its original
    # binding retained by the test module's import below.
    callbacks = []

    class Broken:
        def write(self, text):
            raise BrokenPipeError()

        def flush(self):
            raise BrokenPipeError()

    user_notify._reset_for_tests()
    monkeypatch.setattr(user_notify.sys, "stderr", Broken())
    assert (
        REAL_POST(
            "title",
            "",
            "body",
            backend_fn=lambda: SimpleNamespace(request_authorization=callbacks.append),
            bundle_fn=lambda: ("example.app", "/Applications/Example.app"),
        )
        == "queued"
    )
    callbacks[0](False, None)
    assert "denied" in user_notify.last_outcome()
    user_notify._reset_for_tests()


REAL_POST = user_notify.post


def test_completion_age(monkeypatch):
    snapshot = {"rtt_ms": 1, "loss_pct": 0, "down": False, "alert": False}
    owner = SimpleNamespace(
        _ping_results=queue.Queue(),
        ping_stats={"down": False},
        ping_monitor=SimpleNamespace(record=lambda *a, **k: snapshot),
        throughput=SimpleNamespace(sample=lambda *a, **k: (0, 0)),
        history=SimpleNamespace(record=lambda **k: None),
        config=config.DEFAULT_CONFIG,
        _refresh_title=lambda: None,
    )
    owner._ping_results.put(({}, (0, 0), 10))
    monkeypatch.setattr(app.time, "monotonic", lambda: 130)
    monkeypatch.setattr(app.time, "time", lambda: 1000)
    app.NetDnsMonitorApp._drain_ping_results(owner)
    assert owner.ping_stats["at"] == 880


def test_forensic_same_timestamp(tmp_path):
    recorder = forensic_log.ForensicRecorder(
        str(tmp_path / "journal"),
        str(tmp_path / "episodes"),
        clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    recorder.note(forensic_log.DOWN, "ping")
    first = recorder.note(forensic_log.UP, "ping")
    first_body = Path(first["json_path"]).read_text()
    recorder.note(forensic_log.DOWN, "dns")
    second = recorder.note(forensic_log.UP, "dns")
    assert first != second
    assert Path(first["json_path"]).read_text() == first_body


def test_forensic_clock_failure(tmp_path):
    def broken():
        raise RuntimeError("synthetic clock failure")

    recorder = forensic_log.ForensicRecorder(
        str(tmp_path / "journal"), str(tmp_path / "episodes"), clock=broken
    )
    assert recorder.note(forensic_log.DOWN, "ping") is None
    assert not recorder.is_open


def test_settings_yaml_disclosure(capsys):
    def reload_config(_):
        return yaml.safe_load('sensitive_strings: ["PRIVATE_TOKEN" unexpected]')

    messages = []
    owner = SimpleNamespace(app_controls={}, on_save=reload_config, set_status=messages.append)
    settings_window.SettingsWindow._handle(owner, SimpleNamespace(identifier=lambda: "reload"))
    assert messages and "Not reloaded" in messages[0]
    assert "PRIVATE_TOKEN" not in str(messages) + capsys.readouterr().err


@pytest.mark.parametrize("command", [cli.cmd_interfaces, cli.cmd_bench])
def test_cli_discovery_failure(monkeypatch, command):
    def no_probe(*a):
        pytest.fail("discovery failed; no probe expected")

    monkeypatch.setattr(
        cli,
        "build_context",
        lambda config: (
            no_probe,
            no_probe,
            None,
            lambda *a: SimpleNamespace(returncode=1, stdout="", stderr="synthetic failure"),
        ),
    )
    messages = []
    assert command(SimpleNamespace(bench=False, json=False), {}, messages.append) != 0
    assert "failed" in messages[0]


@pytest.mark.parametrize("server_failure", [False, True])
def test_headless_injected_parts_and_cleanup(monkeypatch, server_failure):
    # Replace every construction dependency before invoking the entry point.
    # The guard also prohibits real OS and outbound operations.
    import threading

    events = []
    cfg = {**config.DEFAULT_CONFIG, "fleet_reporting_enabled": True, "fleet_server_enabled": True}
    caps = SimpleNamespace(network_order_write=False)
    store = SimpleNamespace(get=lambda name: "synthetic", as_env=lambda: {})
    state = SimpleNamespace(
        flap_gate=SimpleNamespace(state="healthy", consecutive_failures=0), tick=lambda: None
    )
    parts = {
        "credential_store": store,
        "state_machine": state,
        "notifier": lambda text: None,
        "failover": None,
    }
    monkeypatch.setattr(config, "load_config", lambda *a: cfg)
    monkeypatch.setattr(distribution, "detect", lambda: caps)
    monkeypatch.setattr(distribution, "default_overrides", lambda caps: {})
    monkeypatch.setattr(app, "default_credential_store", lambda: store)
    monkeypatch.setattr(app, "build_failover", lambda *a, **k: None)
    monkeypatch.setattr(app, "build_remediation_store", lambda *a, **k: None)
    monkeypatch.setattr(app, "build_state_machine", lambda *a, **k: state)
    monkeypatch.setattr(app, "build_notifier", lambda *a, **k: parts["notifier"])
    reporter = SimpleNamespace(
        start=lambda: events.append("start"), stop=lambda: events.append("stop")
    )
    monkeypatch.setattr(headless, "build_reporter", lambda *a: reporter)

    def start_server(config):
        if server_failure:
            raise OSError("synthetic startup failure")
        return SimpleNamespace(stop=lambda: events.append("server stop"))

    monkeypatch.setattr(headless, "start_server", start_server)
    monkeypatch.setattr(headless.signal, "signal", lambda *a: None)
    called = []

    def factory(config, capabilities):
        called.append((config, capabilities))
        return parts

    stop = threading.Event()
    stop.set()
    if server_failure:
        with pytest.raises(OSError, match="synthetic startup failure"):
            headless.run_headless("synthetic.yaml", stop=stop, build_app_parts=factory)
    else:
        assert headless.run_headless("synthetic.yaml", stop=stop, build_app_parts=factory) == 0
    assert called == [(cfg, caps)]
    assert events.count("stop") == 1


def test_all_credential_names_are_scrubbed(monkeypatch):
    import os

    from tests.conftest import no_real_keychain_or_distribution

    for name in credentials.NAMES:
        monkeypatch.setenv(name, "synthetic-credential")
    no_real_keychain_or_distribution.__wrapped__(monkeypatch)
    assert all(name not in os.environ for name in credentials.NAMES)
    store = credentials.CredentialStore(backend_factory=credentials.make_keychain_backend)
    assert all(store.get(name) is None for name in credentials.NAMES)


def test_idna_total_wire_limit():
    assert config.domain_problem(".".join(["é" * 57] * 4)) is not None
    assert config.domain_problem(".".join(["a" * 63] * 3 + ["b" * 61]) + ".") is None


def test_mixed_runas_restriction_supersedes_grant():
    listing = (
        "    (root) NOPASSWD: /usr/bin/killall -HUP mDNSResponder\n"
        "    (_postgres) /bin/ls, (root) PASSWD: /usr/bin/killall -HUP mDNSResponder\n"
    )
    assert not privileges.covers(privileges.parse_granted_commands(listing), privileges.MDNS_HUP)


def test_all_log_levels_are_requested():
    command = system_log.log_show_command("1m", errors_only=False)
    assert "--info" in command and "--debug" in command


def test_log_overlap_keeps_latest_timestamp():
    buffer = system_log.LogBuffer()
    newer = dict(
        timestamp="2026-11-12 12:00:20.000",
        time="12:00:20",
        process="configd",
        message="connection changed",
        severity="error",
    )
    older = {**newer, "timestamp": "2026-11-12 12:00:10.000", "time": "12:00:10"}
    buffer.add([newer])
    buffer.add([older, newer])
    assert buffer.view(noise_patterns=())["rows"][0]["time"] == "12:00:20"


def test_cache_normalization_stops_at_capacity(tmp_path, monkeypatch):
    import json

    path = tmp_path / "learned.json"
    path.write_text(json.dumps([f"host{i}.example.com" for i in range(1000)]))
    calls = []
    original = domain_learner.is_probeable_domain

    def valid(name):
        calls.append(name)
        return original(name)

    monkeypatch.setattr(domain_learner, "is_probeable_domain", valid)
    store = domain_learner.LearnedDomainStore(str(path), max_domains=2)
    assert store.load() == ["host0.example.com", "host1.example.com"]
    assert len(calls) == 4


@pytest.mark.parametrize("kind", [2, 5])
def test_referral_or_incomplete_alias_is_unknown(kind):
    import struct

    packet = dns_query._encode_query("example.com", 42)
    target = b"\x02ns\x07example\x03com\x00"
    record = b"\xc0\x0c" + struct.pack(">HHIH", kind, 1, 30, len(target)) + target
    response = (
        struct.pack(">HHHHHH", 42, 0x8000, 1, int(kind == 5), int(kind == 2), 0)
        + packet[12:]
        + record
    )
    assert dns_query._answer_result(response, packet) is None


def test_check_failure_title_survives_refresh():
    owner = SimpleNamespace(
        _tick_failures=3,
        config={"failure_threshold": 3},
        _display_snapshot=lambda: pytest.fail("failure title must precede snapshot"),
    )
    app.NetDnsMonitorApp._refresh_title(owner)
    assert owner.title == "⚪ Net/DNS: check failing"


def test_stale_privilege_probe_is_discarded():
    owner = SimpleNamespace(
        _privilege_results=queue.Queue(),
        _privilege_generation=1,
        privileges_granted=False,
        dhcp_interfaces=[],
        primary_dhcp_interface=None,
        granted_interfaces=[],
        privileges_file_rule_listed=False,
        privileges_probed=True,
    )
    owner._privilege_results.put({"granted": True, "interfaces": ["en0"], "generation": 0})
    app.NetDnsMonitorApp._drain_privilege_results(owner)
    assert owner.privileges_granted is False


@pytest.mark.parametrize("state", ["loaded", "absent", "unknown", "timeout", "removed"])
def test_unload_requires_confirmed_outcome(state):
    import subprocess

    calls = []

    def run(argv, **kwargs):
        calls.append(argv[1])
        if state == "timeout":
            raise subprocess.TimeoutExpired("synthetic", 20)
        if argv[1] == "bootout":
            return SimpleNamespace(returncode=0 if state == "removed" else 1)
        return SimpleNamespace(
            returncode=0 if state == "loaded" else 1,
            stderr="Could not find service" if state == "absent" else "synthetic error",
        )

    result = headless._unload_agent("gui/123/synthetic", run)
    assert (result is None) == (state in {"absent", "removed"})
    if result:
        assert result.startswith("failed:")


def test_probe_generation_is_captured_before_providers_finish():
    owner = SimpleNamespace(_privilege_results=queue.Queue(), _privilege_generation=0)

    def interfaces():
        owner._privilege_generation = 1
        return ["en0"]

    app.NetDnsMonitorApp._run_privilege_status(owner, lambda: ["ALL"], interfaces, lambda: "en0")
    assert owner._privilege_results.get_nowait()["generation"] == 0


def test_clean_tick_clears_detection_failure_title():
    owner = SimpleNamespace(_tick_failures=3, title="⚪ Net/DNS: check failing", _tick=lambda: None)
    owner._refresh_title = lambda: setattr(owner, "title", "healthy")
    app.NetDnsMonitorApp.tick(owner)
    assert owner._tick_failures == 0
    assert owner.title == "healthy"


def test_referral_allows_next_resolver():
    import struct

    calls = []

    def response(packet, server, *args):
        calls.append(server)
        if server == "first":
            target = b"\x02ns\x07example\x03com\x00"
            record = b"\xc0\x0c" + struct.pack(">HHIH", 2, 1, 30, len(target)) + target
            counts = (0, 1, 0)
        else:
            record = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + b"\xc0\x00\x02\x01"
            counts = (1, 0, 0)
        return (
            struct.pack(">HHHHHH", int.from_bytes(packet[:2], "big"), 0x8180, 1, *counts)
            + packet[12:]
            + record
        )

    assert (
        dns_query.query_public_dns_any(
            "example.com", servers=("first", "second"), send_recv_fn=response
        )
        is True
    )
    assert calls == ["first", "second"]


def test_failed_fleet_key_persistence_prevents_install(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("{}")
    installed = []
    monkeypatch.setattr(
        headless, "store_key_from_environment", lambda: "failed: synthetic key write"
    )
    monkeypatch.setattr(
        headless,
        "install_agent",
        lambda *args, **kwargs: installed.append(True) or "installed and running: synthetic",
    )
    args = SimpleNamespace(install=True, uninstall=False, config=str(path), no_start=False)
    output = []
    assert cli.cmd_headless(args, {}, output.append) == 1
    assert installed == []
    assert output == ["failed: synthetic key write"]
