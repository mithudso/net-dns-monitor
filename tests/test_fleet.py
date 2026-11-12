"""Fleet reporting: the wire format, the client's outbox, the server's log and
state, the headless loop and its LaunchAgent. Everything offline; the one test
that opens sockets uses loopback only.
"""

import ast
import json
import os
import pathlib
import plistlib
import sys
import threading
import types

import pytest

from netdnsmonitor import fleet_protocol as proto
from netdnsmonitor import headless
from netdnsmonitor.fleet_client import MAX_OUTBOX, FleetReporter, default_transport
from netdnsmonitor.fleet_keys import EnrollmentError, KeyRegistry
from netdnsmonitor.fleet_server import FleetServer
from netdnsmonitor.fleet_store import (
    RATE_LIMIT_EVENTS,
    FleetStore,
    machine_status,
    read_events,
    read_state,
    render_events,
    render_fleet,
)

SECRET = "correct horse battery staple"
NOW = 1_800_000_000.0


def message(kind=proto.INCIDENT, machine="mac-1", eid="e1", data=None, secret=SECRET, now=NOW):  # noqa: E501
    return proto.build_message(kind, machine, machine, eid, now, data or {}, secret)


def accepted(payload, secret=SECRET, now=NOW):
    parsed, reason = proto.parse_message(payload, now, secret)
    assert reason is None, reason
    return parsed


# --- protocol ---------------------------------------------------------------


def test_signed_message_round_trips():
    parsed = accepted(message(data={"classification": "dns", "recheck_ok": False}))
    assert parsed["t"] == proto.INCIDENT
    assert parsed["id"] == "mac-1"
    assert parsed["signed"] is True
    assert parsed["data"] == {"classification": "dns", "recheck_ok": False}


def test_tampered_message_is_refused():
    payload = message(data={"classification": "dns"}).replace(b"dns", b"lan")
    parsed, reason = proto.parse_message(payload, NOW, SECRET)
    assert parsed is None
    assert reason == proto.REFUSED_BAD_SIGNATURE


def test_wrong_secret_is_refused():
    parsed, reason = proto.parse_message(message(secret="other"), NOW, SECRET)
    assert (parsed, reason) == (None, proto.REFUSED_BAD_SIGNATURE)


def test_unsigned_message_is_refused_unless_allowed():
    payload = message(secret=None)
    assert proto.parse_message(payload, NOW, SECRET)[1] == proto.REFUSED_UNSIGNED
    assert proto.parse_message(payload, NOW, SECRET, allow_unsigned=True)[1] is None


def test_no_secret_and_no_allowance_trusts_nothing():
    parsed, reason = proto.parse_message(message(secret=None), NOW, None)
    assert (parsed, reason) == (None, proto.REFUSED_UNSIGNED)


def test_a_signed_message_is_still_verified_in_unsigned_mode():
    bad = message(secret="other")
    assert proto.parse_message(bad, NOW, SECRET, allow_unsigned=True)[1] == (
        proto.REFUSED_BAD_SIGNATURE
    )


def test_clock_skew_beyond_the_window_is_refused():
    late = message(now=NOW - proto.MAX_SKEW_SECONDS - 1)
    assert proto.parse_message(late, NOW, SECRET)[1] == proto.REFUSED_STALE
    ok = message(now=NOW - proto.MAX_SKEW_SECONDS + 5)
    assert proto.parse_message(ok, NOW, SECRET)[1] is None


def test_malformed_input_is_refused_not_raised():
    for payload in (b"", b"not json", b"[]", b'{"proto":"x"}', b"\xff\xfe", b"x" * 5000):
        assert proto.parse_message(payload, NOW, SECRET)[1] == proto.REFUSED_MALFORMED


def test_non_numeric_timestamp_is_malformed():
    raw = json.loads(message())
    raw["ts"] = "soon"
    assert proto.parse_message(json.dumps(raw).encode(), NOW, None, True)[1] == (
        proto.REFUSED_MALFORMED
    )


def test_strings_are_cleaned_and_unknown_fields_dropped():
    raw = {
        "proto": proto.PROTOCOL,
        "t": proto.HELLO,
        "id": "a\nb\x1b[31m",
        "host": "h" * 500,
        "eid": "1",
        "ts": NOW,
        "data": {"status": "ok\x00", "evil": "rm -rf /", "steps": "not a list"},
    }
    parsed, _ = proto.parse_message(json.dumps(raw).encode(), NOW, None, True)
    assert "\n" not in parsed["id"] and "\x1b" not in parsed["id"]
    assert len(parsed["host"]) <= 100
    assert parsed["data"] == {"status": "ok"}


def test_steps_are_bounded():
    steps = [{"name": f"s{i}", "outcome": "x" * 1000} for i in range(40)]
    parsed = accepted(message(data={"steps": steps}, secret=SECRET))
    assert len(parsed["data"]["steps"]) <= proto.MAX_STEPS
    assert all(len(s["outcome"]) <= proto.MAX_STEP_TEXT for s in parsed["data"]["steps"])


def test_oversize_steps_are_dropped_with_a_note_not_silently_cut():
    steps = [{"name": "n" * 60, "outcome": "o" * proto.MAX_STEP_TEXT}] * proto.MAX_STEPS
    # Passed straight to build_message, which does not bound steps itself.
    payload = proto.build_message("incident", "m", "m", "e", NOW, {"steps": steps}, SECRET)
    assert len(payload) <= proto.MAX_SEND_BYTES
    data = accepted(payload)["data"]
    assert data.get("steps_omitted")


def test_step_summaries_redact_before_truncating():
    secret = "internal-db.acme.com"
    out = proto.step_summaries(
        [{"name": "n", "outcome": "x" * 130 + secret}], lambda t: t.replace(secret, "[REDACTED]")
    )
    assert secret not in out[0]["outcome"]
    assert "internal-db" not in out[0]["outcome"]


def test_protocol_and_store_import_no_network_modules():
    root = os.path.join(os.path.dirname(__file__), "..", "netdnsmonitor")
    for name in ("fleet_protocol.py", "fleet_store.py"):
        tree = ast.parse(pathlib.Path(root, name).read_text())
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module
        }
        assert not imported & {"socket", "subprocess"}, name


# --- store ------------------------------------------------------------------


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def make_store(tmp_path, clock=None, stale=900.0):
    return FleetStore(
        str(tmp_path / "events.jsonl"),
        str(tmp_path / "state.json"),
        stale_seconds=stale,
        now_fn=clock or Clock(),
    )


STEPS = [
    {"name": "flush_dns_cache", "outcome": "partial: HUP refused"},
    {"name": "renew_dhcp_lease", "outcome": "NEEDS_PRIVILEGE: no grant"},
]


def feed(store, kind, eid="e1", machine="mac-1", data=None, address="10.0.0.5"):
    parsed = accepted(message(kind, machine, eid, data))
    return store.record(parsed, address)


def test_incident_then_resolved_is_logged_with_steps_and_duration(tmp_path):
    clock = Clock()
    store = make_store(tmp_path, clock)
    assert feed(store, proto.INCIDENT, "e1", data={"classification": "dns", "steps": STEPS}) == (
        "logged"
    )
    state = store.machines["mac-1"]
    assert state["open_incident"]["classification"] == "dns"
    clock.now += 90
    assert feed(store, proto.RESOLVED, "e2", data={"classification": "dns"}) == "logged"
    assert state["open_incident"] is None
    last = state["last_incident"]
    assert last["duration_seconds"] == 90.0
    assert last["steps"] == STEPS  # the incident's steps are carried to the resolution
    kinds = [e["kind"] for e in read_events(store.log_path)]
    assert kinds == ["incident", "resolved"]


def test_resolved_event_does_not_credit_a_step(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns", "steps": STEPS})
    feed(
        store,
        proto.RESOLVED,
        "e2",
        data={"classification": "dns", "recovery": "network recovered; no step is credited"},
    )
    text = render_events(read_events(store.log_path))
    assert "fixed" not in text.lower() and "repaired" not in text.lower()
    assert "no step is credited" in json.dumps(read_events(store.log_path))


def test_duplicate_event_id_is_acknowledged_but_not_logged_twice(tmp_path):
    store = make_store(tmp_path)
    assert feed(store, proto.INCIDENT, "e1", data={"classification": "dns"}) == "logged"
    assert feed(store, proto.INCIDENT, "e1", data={"classification": "dns"}) == "duplicate"
    incidents = [e for e in read_events(store.log_path) if e["kind"] == "incident"]
    assert len(incidents) == 1
    assert store.machines["mac-1"]["incidents_total"] == 1


def test_healthy_heartbeat_closes_an_open_incident_and_says_it_was_inferred(tmp_path):
    clock = Clock()
    store = make_store(tmp_path, clock)
    feed(store, proto.INCIDENT, "e1", data={"classification": "network", "steps": STEPS})
    clock.now += 300
    feed(store, proto.HELLO, "e2", data={"status": "healthy"})
    assert store.machines["mac-1"]["open_incident"] is None
    assert store.machines["mac-1"]["last_incident"]["inferred"] is True
    resolved = [e for e in read_events(store.log_path) if e["kind"] == "resolved"][0]
    assert resolved["inferred"] is True
    assert "inferred" in render_events([resolved])
    assert "not reported" in render_fleet(read_state(store.state_path), clock.now)


def test_incident_heartbeat_does_not_close_it(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns"})
    feed(store, proto.HELLO, "e2", data={"status": "incident"})
    assert store.machines["mac-1"]["open_incident"] is not None


def test_heartbeats_are_not_logged_each_time(tmp_path):
    store = make_store(tmp_path)
    for i in range(5):
        feed(store, proto.HELLO, f"h{i}", data={"status": "healthy"})
    events = read_events(store.log_path)
    assert [e["kind"] for e in events] == ["online"]


def test_silent_machine_is_logged_once_and_keeps_its_last_status(tmp_path):
    clock = Clock()
    store = make_store(tmp_path, clock, stale=600)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns"})
    clock.now += 601
    assert store.sweep() == ["mac-1"]
    assert store.sweep() == []
    silent = [e for e in read_events(store.log_path) if e["kind"] == "silent"]
    assert len(silent) == 1 and silent[0]["open_incident"] is True
    assert machine_status(store.machines["mac-1"], clock.now, 600) == "incident (silent)"


def test_machine_back_from_silence_is_logged_online(tmp_path):
    clock = Clock()
    store = make_store(tmp_path, clock, stale=600)
    feed(store, proto.HELLO, "h1", data={"status": "healthy"})
    clock.now += 700
    store.sweep()
    clock.now += 10
    feed(store, proto.HELLO, "h2", data={"status": "healthy"})
    assert [e["kind"] for e in read_events(store.log_path)] == ["online", "silent", "online"]


def test_silent_healthy_machine_is_not_shown_as_healthy(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.HELLO, "h1", data={"status": "healthy"})
    machine = store.machines["mac-1"]
    assert machine_status(machine, NOW + 5000, 900) == "silent"
    assert machine_status(machine, NOW + 10, 900) == "healthy"


def test_rate_limit_refuses_a_flood_and_counts_it(tmp_path):
    store = make_store(tmp_path)
    verdicts = [
        feed(store, proto.INCIDENT, f"e{i}", data={"classification": "dns"})
        for i in range(RATE_LIMIT_EVENTS + 5)
    ]
    assert verdicts.count("rate_limited") == 5
    assert store.refused["rate_limited"] == 5
    assert len(read_events(store.log_path, limit=1000)) == RATE_LIMIT_EVENTS


def test_state_survives_a_restart(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns", "steps": STEPS})
    again = make_store(tmp_path)
    assert again.machines["mac-1"]["open_incident"]["classification"] == "dns"


def test_a_damaged_log_line_is_skipped(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns"})
    with open(store.log_path, "a") as handle:
        handle.write("{broken\n")
    assert [e["kind"] for e in read_events(store.log_path)][-1] == "incident"


def test_log_rotates_when_large(tmp_path, monkeypatch):
    import netdnsmonitor.fleet_store as fs

    monkeypatch.setattr(fs, "LOG_ROTATE_BYTES", 10)
    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns"})
    feed(store, proto.RESOLVED, "e2", data={})
    assert os.path.exists(store.log_path + ".1")


def test_report_names_the_problem_machine_the_cause_and_the_steps(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.HELLO, "h0", machine="mac-ok", data={"status": "healthy"})
    feed(
        store,
        proto.INCIDENT,
        "e1",
        machine="mac-bad",
        data={"classification": "dns", "steps": STEPS, "recheck_ok": False},
    )
    text = render_fleet(read_state(store.state_path), NOW + 5)
    assert "2 machine(s) known; 1 not healthy" in text
    assert "mac-bad" in text and "PROBLEM since" in text
    assert "flush_dns_cache: partial: HUP refused" in text
    assert "the recheck after those steps still failed" in text


def test_report_with_no_machines():
    assert render_fleet({"machines": {}}, NOW) == "No machines have reported yet."


# --- client -----------------------------------------------------------------


class Transport:
    """Plays the server: acks what it is told to, records what it was sent."""

    def __init__(self, secret=SECRET, up=True, clock=lambda: NOW):
        self.secret, self.up, self.clock = secret, up, clock
        self.sent = []

    def __call__(self, payload, targets, port, timeout):
        parsed, reason = proto.parse_message(payload, self.clock(), self.secret)
        assert reason is None, reason
        self.sent.append((parsed, targets, port))
        if not self.up:
            return []
        return [
            proto.build_message(
                proto.ACK, "server", "", parsed["eid"], self.clock(), {}, self.secret
            )
        ]


def reporter(transport, **kwargs):
    defaults = dict(
        machine_id="mac-1",
        host="mac-1.local",
        server_address="10.0.0.9",
        secret=SECRET,
        now_fn=lambda: NOW,
        transport=transport,
        broadcast_fn=lambda: ["10.0.0.255", "255.255.255.255"],
    )
    defaults.update(kwargs)
    return FleetReporter(**defaults)


REPORT = {
    "classification": "dns",
    "started_at": "2026-10-17T10:00:00+00:00",
    "recheck_ok": False,
    "ladder_results": [{"name": "flush_dns_cache", "outcome": "partial: HUP refused"}],
    "probe_results": {"external_reachable": True, "dns_ok": False, "secret": "do-not-send"},
    "escalation": {"analysis": "..."},
}


def test_incident_is_delivered_and_acked():
    transport = Transport()
    r = reporter(transport)
    r.incident(REPORT)
    assert r.pending() == 1
    assert r.flush() == 1
    assert r.pending() == 0
    sent, targets, port = transport.sent[0]
    assert targets == ["10.0.0.9"] and port == 45738
    assert sent["data"]["classification"] == "dns"
    assert sent["data"]["external_reachable"] is True and sent["data"]["dns_ok"] is False
    assert sent["data"]["steps"] == [{"name": "flush_dns_cache", "outcome": "partial: HUP refused"}]
    assert "do-not-send" not in json.dumps(sent)


def test_unreachable_server_keeps_the_event_and_retries_in_order():
    transport = Transport(up=False)
    r = reporter(transport)
    r.incident(REPORT)
    r.resolved("dns", 42.0, REPORT["ladder_results"])
    assert r.flush() == 0
    assert r.pending() == 2
    assert r.last_error == "no acknowledgement from the server"
    transport.up = True
    transport.sent.clear()
    assert r.flush() == 2
    assert [m["t"] for m, _, _ in transport.sent] == [proto.INCIDENT, proto.RESOLVED]


def test_a_failed_head_stops_the_pass():
    transport = Transport(up=False)
    r = reporter(transport)
    r.incident(REPORT)
    r.resolved("dns", 1.0)
    r.flush()
    # Only the head was attempted (SEND_ATTEMPTS times), not the event behind it.
    assert {m["t"] for m, _, _ in transport.sent} == {proto.INCIDENT}


def test_retry_is_re_signed_with_the_current_time():
    clock = [NOW]
    transport = Transport(up=False, clock=lambda: clock[0])
    r = reporter(transport, now_fn=lambda: clock[0])
    r.incident(REPORT)
    r.flush()
    clock[0] += 3600  # an hour-long outage later
    transport.up = True
    assert r.flush() == 1
    assert transport.sent[-1][0]["ts"] == clock[0]


def test_ack_for_another_event_or_with_a_bad_signature_does_not_count():
    r = reporter(lambda *a: [proto.build_message(proto.ACK, "s", "", "other-eid", NOW, {}, SECRET)])
    r.incident(REPORT)
    assert r.flush() == 0
    forged = reporter(
        lambda p, *a: [
            proto.build_message(
                proto.ACK, "s", "", proto.parse_message(p, NOW, SECRET)[0]["eid"], NOW, {}, "wrong"
            )
        ]
    )
    forged.incident(REPORT)
    assert forged.flush() == 0


def test_outbox_is_bounded_and_counts_what_it_dropped():
    r = reporter(Transport(up=False))
    for _ in range(MAX_OUTBOX + 7):
        r.incident(REPORT)
    assert r.pending() == MAX_OUTBOX
    assert r.dropped == 7


def test_outbound_text_is_redacted():
    r = reporter(Transport(), redact_fn=lambda t: t.replace("acme", "[REDACTED]"))
    report = dict(REPORT, classification="acme-vpn")
    report["ladder_results"] = [{"name": "n", "outcome": "failed: acme-gw unreachable"}]
    r.incident(report)
    r.flush()
    sent = json.dumps(r.transport.sent[0][0])
    assert "acme" not in sent and "[REDACTED]" in sent


def test_resolved_wording_credits_no_step():
    transport = Transport()
    r = reporter(transport)
    r.resolved("dns", 30.0, REPORT["ladder_results"], occurred_at="t0")
    r.flush()
    data = transport.sent[0][0]["data"]
    assert data["recovery"] == "network recovered; no step is credited"
    assert data["duration_seconds"] == 30.0


def test_heartbeat_reports_unknown_as_unknown():
    transport = Transport()
    r = reporter(transport, version="1.2")
    assert r.heartbeat() is True
    assert transport.sent[0][0]["data"]["status"] == "unknown"
    assert transport.sent[0][0]["data"]["version"] == "1.2"


def test_no_server_address_broadcasts_and_no_address_at_all_is_an_error():
    transport = Transport()
    r = reporter(transport, server_address="")
    r.heartbeat()
    assert transport.sent[0][1] == ["10.0.0.255", "255.255.255.255"]
    empty = reporter(Transport(), server_address="", broadcast_fn=lambda: [])
    assert empty.heartbeat() is False
    assert "no server address" in empty.last_error


def test_a_transport_that_raises_is_data_not_an_exception():
    def broken(*args):
        raise OSError("boom")

    r = reporter(broken)
    r.incident(REPORT)
    assert r.flush() == 0
    assert r.last_error == "OSError"
    assert r.pending() == 1


# --- loopback: the real client against the real server ----------------------


def quick(port, name, key):
    """A reporter that waits only briefly for an ack."""
    return FleetReporter(
        machine_id=name,
        host=name,
        server_address="127.0.0.1",
        port=port,
        secret=key,
        transport=lambda p, t, prt, timeout: default_transport(p, t, prt, 0.3),
    )


def test_real_udp_round_trip_over_loopback(tmp_path):
    store = FleetStore(str(tmp_path / "e.jsonl"), str(tmp_path / "s.json"))
    registry = KeyRegistry(str(tmp_path / "keys.json"))
    key_1 = registry.enroll("mac-1")
    key_2 = registry.enroll("mac-2")
    server = FleetServer(store, port=0, key_for=registry.key_for, bind_host="127.0.0.1")
    assert server.start()
    try:
        r = FleetReporter(
            machine_id="mac-1",
            host="mac-1.local",
            server_address="127.0.0.1",
            port=server.port,
            secret=key_1,
            transport=default_transport,
        )
        r.incident(REPORT)
        assert r.flush() == 1
        assert store.machines["mac-1"]["open_incident"]["classification"] == "dns"

        # A name that was never enrolled is refused, whatever key it signs with.
        stranger = quick(server.port, "evil", key_1)
        stranger.incident(REPORT)
        assert stranger.flush() == 0
        assert "evil" not in store.machines
        assert store.refused[proto.REFUSED_UNKNOWN_MACHINE] >= 1

        # mac-2's own key cannot speak for mac-1.
        impostor = quick(server.port, "mac-1", key_2)
        impostor.resolved("dns", 1.0)
        assert impostor.flush() == 0
        assert store.machines["mac-1"]["open_incident"] is not None
        assert store.refused[proto.REFUSED_BAD_SIGNATURE] >= 1

        # Revoking takes effect without restarting the server.
        registry.revoke("mac-1")
        late = quick(server.port, "mac-1", key_1)
        late.heartbeat()
        assert late.last_error == "no acknowledgement from the server"
    finally:
        server.stop()


def test_server_start_failure_is_reported_not_raised(tmp_path, monkeypatch):
    import netdnsmonitor.fleet_server as server_module

    bound = set()

    class Socket:
        def __init__(self, *_):
            self.closed = threading.Event()
            self.port = None

        def setsockopt(self, *_):
            pass

        def bind(self, address):
            port = address[1] or 45738
            if port in bound:
                raise OSError("synthetic address already in use")
            self.port = port
            bound.add(port)

        def getsockname(self):
            return "127.0.0.1", self.port

        def settimeout(self, *_):
            pass

        def recvfrom(self, *_):
            assert self.closed.wait(2)
            raise OSError("closed")

        def close(self):
            self.closed.set()
            bound.discard(self.port)

    monkeypatch.setattr(server_module.socket, "socket", Socket)
    first = FleetServer(
        FleetStore(str(tmp_path / "a"), str(tmp_path / "b")),
        port=0,
        bind_host="127.0.0.1",
    )
    assert first.start()
    try:
        second = FleetServer(
            FleetStore(str(tmp_path / "c"), str(tmp_path / "d")),
            port=first.port,
            bind_host="127.0.0.1",
        )
        assert second.start() is False
        assert second.start_error
    finally:
        first.stop()
        first.thread.join(2)


# --- headless ---------------------------------------------------------------


class Gate:
    def __init__(self):
        self.state = "healthy"
        self.consecutive_failures = 0


class FakeMachine:
    def __init__(self):
        self.flap_gate = Gate()
        self.reports = []
        self.raises = False

    def tick(self):
        if self.raises:
            raise RuntimeError("probe blew up")
        return self.reports.pop(0) if self.reports else None


class RecordingReporter:
    def __init__(self):
        self.calls = []

    def incident(self, report):
        self.calls.append(("incident", report["classification"]))

    def resolved(self, classification, duration, steps, occurred_at=""):
        self.calls.append(("resolved", classification, round(duration), len(steps)))


def monitor(machine, rep=None, notifier=None, saved=None, clock=None):
    return headless.HeadlessMonitor(
        {"reports_dir": "/nowhere", "sensitive_strings": ["acme"], "poll_interval_seconds": 1},
        machine,
        reporter=rep,
        notifier=notifier,
        save_report_fn=lambda report, directory: (
            (saved.append(report) if saved is not None else None)
            or {"markdown_path": "/nowhere/r.md"}
        ),
        now_fn=clock or (lambda: 0.0),
        log=lambda text: None,
    )


def test_status_is_unknown_until_a_poll_finishes():
    m = monitor(FakeMachine())
    assert m.status() == "unknown"
    m.step()
    assert m.status() == "healthy"


def test_incident_is_saved_reported_and_recovery_follows():
    machine = FakeMachine()
    machine.reports = [REPORT]
    rep, saved = RecordingReporter(), []
    clock = [100.0]
    m = monitor(machine, rep, saved=saved, clock=lambda: clock[0])
    machine.flap_gate.state = "incident"
    m.step()
    assert rep.calls == [("incident", "dns")]
    assert saved == [REPORT]
    clock[0] = 160.0
    machine.flap_gate.state = "healthy"
    m.step()
    assert rep.calls[-1] == ("resolved", "dns", 60, 1)


def test_recovery_is_reported_once():
    machine = FakeMachine()
    machine.reports = [REPORT]
    rep = RecordingReporter()
    m = monitor(machine, rep)
    machine.flap_gate.state = "incident"
    m.step()
    machine.flap_gate.state = "healthy"
    m.step()
    m.step()
    assert [c[0] for c in rep.calls] == ["incident", "resolved"]


def test_a_raising_poll_is_contained_and_recovery_still_runs():
    machine = FakeMachine()
    machine.reports = [REPORT]
    rep = RecordingReporter()
    m = monitor(machine, rep)
    machine.flap_gate.state = "incident"
    m.step()
    machine.raises = True
    machine.flap_gate.state = "healthy"
    m.step()
    assert m.last_error == "RuntimeError"
    assert rep.calls[-1][0] == "resolved"


def test_notification_text_is_redacted():
    machine = FakeMachine()
    machine.reports = [dict(REPORT, classification="acme-vpn")]
    delivered, done = [], threading.Event()

    def notifier(text):
        delivered.append(text)
        done.set()

    m = monitor(machine, notifier=notifier)
    machine.flap_gate.state = "incident"
    m.step()
    assert done.wait(2)
    assert "acme" not in delivered[0]


def test_unsaved_report_does_not_cost_the_fleet_event():
    machine = FakeMachine()
    machine.reports = [REPORT]
    rep = RecordingReporter()
    m = monitor(machine, rep)

    def explode(report, directory):
        raise OSError("disk full")

    m.save_report_fn = explode
    machine.flap_gate.state = "incident"
    m.step()
    assert rep.calls == [("incident", "dns")]
    assert m.last_error == "report not saved: OSError"


def test_run_loops_until_stopped():
    machine = FakeMachine()
    m = monitor(machine)
    m.config["poll_interval_seconds"] = 0.01
    stop = threading.Event()
    calls = []

    def tick():
        calls.append(True)
        if len(calls) == 2:
            stop.set()

    machine.tick = tick
    watchdog = threading.Timer(2, stop.set)
    watchdog.start()
    try:
        m.run(stop)
    finally:
        watchdog.cancel()
    assert m.polls == len(calls) == 2


def test_machine_identity_is_stable_and_prefers_the_configured_name():
    assert headless.machine_identity({"fleet_machine_name": "desk-7"}) == "desk-7"
    assert headless.machine_identity({}) == headless.machine_identity({"fleet_machine_name": ""})


def test_agent_plist_keeps_it_alive_and_names_the_config(tmp_path):
    plist = headless.agent_plist("/py", "/src", "/etc/c.yaml", "/log")
    assert plist["KeepAlive"] is True and plist["RunAtLoad"] is True
    assert plist["ProgramArguments"][-3:] == ["--config", "/etc/c.yaml", "headless"]


def test_install_agent_writes_the_plist_and_loads_it(tmp_path):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return types.SimpleNamespace(returncode=0)

    line = headless.install_agent(
        str(tmp_path / "c.yaml"),
        "/py",
        "/src",
        agents_dir=str(tmp_path / "agents"),
        log_path=str(tmp_path / "logs" / "h.log"),
        run_fn=run,
        uid=501,
    )
    assert line.startswith("installed and running")
    with open(headless.agent_path(str(tmp_path / "agents")), "rb") as handle:
        assert plistlib.load(handle)["Label"] == headless.AGENT_LABEL
    assert calls[-1][:3] == ["/bin/launchctl", "bootstrap", "gui/501"]


def test_install_agent_reports_a_launchctl_failure_instead_of_claiming_success(tmp_path):
    line = headless.install_agent(
        str(tmp_path / "c.yaml"),
        "/py",
        "/src",
        agents_dir=str(tmp_path),
        log_path=str(tmp_path / "h.log"),
        run_fn=lambda argv, **kw: types.SimpleNamespace(returncode=5),
        uid=501,
    )
    assert "exited 5" in line and "installed and running" not in line


def test_install_without_start_does_not_call_launchctl(tmp_path):
    def run(*args, **kwargs):
        raise AssertionError("launchctl must not be called")

    line = headless.install_agent(
        str(tmp_path / "c.yaml"),
        "/py",
        "/src",
        agents_dir=str(tmp_path),
        log_path=str(tmp_path / "h.log"),
        start=False,
        run_fn=run,
    )
    assert "not loaded" in line


def test_uninstall_removes_the_plist(tmp_path):
    headless.install_agent(
        "/c", "/py", "/src", agents_dir=str(tmp_path), log_path=str(tmp_path / "h.log"), start=False
    )
    line = headless.uninstall_agent(
        str(tmp_path), run_fn=lambda *a, **k: types.SimpleNamespace(returncode=0), uid=501
    )
    assert line.startswith("removed")
    assert "nothing to remove" in headless.uninstall_agent(
        str(tmp_path), run_fn=lambda *a, **k: types.SimpleNamespace(returncode=0), uid=501
    )


def test_key_moves_from_the_environment_to_the_keychain_and_is_never_echoed():
    saved = {}

    class Store:
        def set(self, name, value):
            saved[name] = value
            return "saved to the Keychain"

    line = headless.store_key_from_environment({"FLEET_MACHINE_KEY": SECRET}, Store())
    assert saved == {"FLEET_MACHINE_KEY": SECRET}
    assert SECRET not in line
    assert headless.store_key_from_environment({}, Store()) is None


# --- command line -----------------------------------------------------------


def test_fleet_command_prints_the_picture_and_events(tmp_path):
    from netdnsmonitor import cli

    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns", "steps": STEPS})
    config = {
        "fleet_server_state_path": store.state_path,
        "fleet_server_log_path": store.log_path,
        "fleet_keys_path": str(tmp_path / "keys.json"),
        "fleet_stale_seconds": 900,
    }
    lines = []
    args = cli.build_parser().parse_args(["fleet", "--events", "5"])
    assert cli.cmd_fleet(args, config, lines.append) == 0
    text = "\n".join(lines)
    assert "mac-1" in text and "PROBLEM since" in text and "flush_dns_cache" in text


def test_fleet_command_json(tmp_path):
    from netdnsmonitor import cli

    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "e1", data={"classification": "dns"})
    lines = []
    args = cli.build_parser().parse_args(["fleet", "--json"])
    cli.cmd_fleet(
        args,
        {
            "fleet_server_state_path": store.state_path,
            "fleet_server_log_path": store.log_path,
            "fleet_keys_path": str(tmp_path / "keys.json"),
            "fleet_stale_seconds": 900,
        },
        lines.append,
    )
    assert json.loads(lines[0])["events"][-1]["kind"] == "incident"


def test_parser_knows_the_new_commands():
    from netdnsmonitor import cli

    parser = cli.build_parser()
    assert parser.parse_args(["headless", "--install", "--no-start"]).install is True
    assert parser.parse_args(["server"]).func is cli.cmd_server


# --- per-machine keys ---------------------------------------------------------


def test_each_machine_gets_its_own_key_and_only_that_name_verifies(tmp_path):
    registry = KeyRegistry(str(tmp_path / "keys.json"))
    key_a, key_b = registry.enroll("desk-a"), registry.enroll("desk-b")
    assert key_a != key_b and len(key_a) == 64
    a_message = proto.build_message(proto.HELLO, "desk-a", "h", "e1", NOW, {}, key_a)
    _, reason = proto.parse_message(a_message, NOW, key_for=registry.key_for)
    assert reason is None
    # desk-b's key signing a message that claims to be desk-a.
    forged = proto.build_message(proto.HELLO, "desk-a", "h", "e2", NOW, {}, key_b)
    assert proto.parse_message(forged, NOW, key_for=registry.key_for)[1] == (
        proto.REFUSED_BAD_SIGNATURE
    )


def test_unenrolled_name_is_refused_even_with_a_valid_looking_signature(tmp_path):
    registry = KeyRegistry(str(tmp_path / "keys.json"))
    payload = proto.build_message(proto.HELLO, "ghost", "h", "e1", NOW, {}, "any-key")
    assert proto.parse_message(payload, NOW, key_for=registry.key_for)[1] == (
        proto.REFUSED_UNKNOWN_MACHINE
    )


def test_unsigned_is_refused_for_an_enrolled_name_unless_allowed(tmp_path):
    registry = KeyRegistry(str(tmp_path / "keys.json"))
    registry.enroll("desk-a")
    payload = proto.build_message(proto.HELLO, "desk-a", "h", "e1", NOW, {}, None)
    assert proto.parse_message(payload, NOW, key_for=registry.key_for)[1] == (
        proto.REFUSED_UNSIGNED
    )
    assert proto.parse_message(payload, NOW, None, True, key_for=registry.key_for)[1] is None


def test_key_file_is_private_and_holds_no_key_in_listings(tmp_path):
    path = tmp_path / "fleet" / "keys.json"
    registry = KeyRegistry(str(path))
    key = registry.enroll("desk-a")
    assert (path.stat().st_mode & 0o777) == 0o600
    assert registry.names() == ["desk-a"]
    assert key not in " ".join(registry.names())


def test_enrolling_twice_is_refused_and_revoke_then_enroll_rotates(tmp_path):
    registry = KeyRegistry(str(tmp_path / "keys.json"))
    first = registry.enroll("desk-a")
    with pytest.raises(EnrollmentError):
        registry.enroll("desk-a")
    assert registry.revoke("desk-a") is True
    assert registry.key_for("desk-a") is None
    assert registry.revoke("desk-a") is False
    assert registry.enroll("desk-a") != first


@pytest.mark.parametrize("name", ["", "   ", "a\nb", "x" * 65])
def test_bad_machine_names_are_refused(tmp_path, name):
    with pytest.raises(EnrollmentError):
        KeyRegistry(str(tmp_path / "keys.json")).enroll(name)


def test_a_second_process_sees_an_enrollment_without_a_restart(tmp_path):
    clock = Clock(0.0)
    server_side = KeyRegistry(str(tmp_path / "keys.json"), now_fn=clock)
    assert server_side.key_for("desk-a") is None
    key = KeyRegistry(str(tmp_path / "keys.json")).enroll("desk-a")
    clock.now += 2
    assert server_side.key_for("desk-a") == key


def test_a_damaged_key_file_keeps_the_keys_already_loaded(tmp_path):
    clock = Clock(0.0)
    path = tmp_path / "keys.json"
    registry = KeyRegistry(str(path), now_fn=clock)
    key = registry.enroll("desk-a")
    path.write_text("{broken")
    os.utime(path, (1, 1))
    clock.now += 2
    assert registry.key_for("desk-a") == key


def test_report_lists_enrolled_machines_that_never_reported(tmp_path):
    store = make_store(tmp_path)
    feed(store, proto.HELLO, "h1", machine="mac-ok", data={"status": "healthy"})
    text = render_fleet(read_state(store.state_path), NOW + 5, 900.0, ["mac-ok", "mac-new"])
    assert "Enrolled but never heard from: mac-new" in text
    assert "mac-ok" in text.split("Enrolled but never heard from")[0]
    assert "Enrolled but never heard from: mac-new" in render_fleet(
        {"machines": {}}, NOW, 900.0, ["mac-new"]
    )


def test_enroll_command_prints_the_key_once_and_keys_never_does(tmp_path):
    from netdnsmonitor import cli

    config = {"fleet_keys_path": str(tmp_path / "keys.json")}
    lines = []
    parser = cli.build_parser()
    assert (
        cli.cmd_fleet(parser.parse_args(["fleet", "enroll", "desk-a"]), config, lines.append) == 0
    )
    key = KeyRegistry(config["fleet_keys_path"]).key_for("desk-a")
    assert key in "\n".join(lines)
    listing = []
    assert cli.cmd_fleet(parser.parse_args(["fleet", "keys"]), config, listing.append) == 0
    assert listing == ["desk-a"]
    again = []
    assert (
        cli.cmd_fleet(parser.parse_args(["fleet", "enroll", "desk-a"]), config, again.append) == 1
    )
    assert key not in "\n".join(again)


def test_revoke_command_and_missing_name(tmp_path):
    from netdnsmonitor import cli

    config = {"fleet_keys_path": str(tmp_path / "keys.json")}
    parser = cli.build_parser()
    out = []
    cli.cmd_fleet(parser.parse_args(["fleet", "enroll", "desk-a"]), config, out.append)
    out.clear()
    assert cli.cmd_fleet(parser.parse_args(["fleet", "revoke", "desk-a"]), config, out.append) == 0
    assert cli.cmd_fleet(parser.parse_args(["fleet", "revoke", "desk-a"]), config, out.append) == 1
    assert cli.cmd_fleet(parser.parse_args(["fleet", "revoke"]), config, out.append) == 2


def test_fleet_keys_module_imports_no_network_modules():
    tree = ast.parse(
        pathlib.Path(__file__).parent.joinpath("..", "netdnsmonitor", "fleet_keys.py").read_text()
    )
    imported = {
        a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    imported |= {
        n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module
    }
    assert not imported & {"socket", "subprocess"}


# --- maintenance regressions: entirely synthetic effects ---------------------


@pytest.mark.parametrize("signature", ["é", "z" * 64, "a" * 63, "a" * 65])
def test_invalid_signature_text_is_refused_as_data(signature):
    raw = json.loads(message())
    raw["sig"] = signature
    assert proto.parse_message(json.dumps(raw).encode(), NOW, SECRET) == (
        None,
        proto.REFUSED_BAD_SIGNATURE,
    )


def test_nested_fleet_packet_is_refused_at_the_production_recursion_limit():
    original = sys.getrecursionlimit()
    try:
        sys.setrecursionlimit(1000)
        assert proto.parse_message(b"[" * 2000 + b"0" + b"]" * 2000, NOW) == (
            None,
            proto.REFUSED_MALFORMED,
        )
    finally:
        sys.setrecursionlimit(original)


@pytest.mark.parametrize("timestamp", [float("nan"), float("inf"), -float("inf"), 10**400])
@pytest.mark.parametrize("signed", [False, True])
def test_invalid_numeric_timestamp_is_refused(timestamp, signed):
    raw = json.loads(message(secret=None))
    raw["ts"] = timestamp
    if signed:
        raw["sig"] = proto.sign(raw, SECRET)
    assert proto.parse_message(json.dumps(raw).encode(), NOW, SECRET, True) == (
        None,
        proto.REFUSED_MALFORMED,
    )


@pytest.mark.parametrize("duration", [10**400, float("inf"), float("nan"), -1, True])
def test_invalid_duration_is_omitted_without_losing_the_event(duration):
    parsed = accepted(message(data={"duration_seconds": duration, "classification": "dns"}))
    assert parsed["data"] == {"classification": "dns"}


@pytest.mark.parametrize("method", ["incident", "resolved"])
def test_report_preparation_failure_is_counted_without_leaking(method):
    def broken(_text):
        raise ValueError("SECRET_MARKER")

    rep = reporter(Transport(), redact_fn=broken)
    if method == "incident":
        rep.incident(REPORT)
    else:
        rep.resolved("dns", 5)
    assert rep.last_error == "ValueError"
    assert rep.dropped == 1 and rep.pending() == 0


def test_report_preparation_failure_does_not_cost_the_local_report():
    def broken(_text):
        raise ValueError("SECRET_MARKER")

    machine, saved = FakeMachine(), []
    machine.reports = [REPORT]
    rep = reporter(Transport(), redact_fn=broken)
    mon = monitor(machine, rep, saved=saved)
    mon.step()
    assert saved == [REPORT]
    assert rep.last_error == "ValueError" and rep.dropped == 1


def test_default_transport_ignores_invalid_packets_before_a_valid_ack(monkeypatch):
    import netdnsmonitor.fleet_client as client

    clocks = [0.0]
    sockets = []

    class Socket:
        def __init__(self, *_):
            sockets.append(self)
            self.timeouts, self.replies, self.closed = [], [], False

        def setsockopt(self, *_):
            pass

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

        def sendto(self, payload, target):
            event = accepted(payload)
            self.replies = [
                b"garbage",
                message(proto.ACK, eid="other"),
                message(proto.ACK, eid=event["eid"], secret="wrong"),
                message(proto.ACK, eid=event["eid"]),
            ]

        def recvfrom(self, _limit):
            clocks[0] += 0.1
            return self.replies.pop(0), ("127.0.0.1", 45738)

        def close(self):
            self.closed = True

    monkeypatch.setattr(client.socket, "socket", Socket)
    monkeypatch.setattr(client.time, "monotonic", lambda: clocks[0])
    rep = reporter(default_transport)
    rep.incident(REPORT)
    assert rep.flush() == 1 and rep.pending() == 0
    assert len(sockets) == 1 and sockets[0].closed
    assert sockets[0].timeouts == pytest.approx([2.0, 2.0, 1.9, 1.8, 1.7])


def test_invalid_ack_flood_uses_one_deadline_and_closes_each_socket(monkeypatch):
    import netdnsmonitor.fleet_client as client

    clocks, sockets = [0.0], []

    class Socket:
        def __init__(self, *_):
            self.closed, self.reads = False, 0
            sockets.append(self)

        def setsockopt(self, *_):
            pass

        def settimeout(self, timeout):
            assert 0 < timeout <= 2

        def sendto(self, *_):
            pass

        def recvfrom(self, _limit):
            self.reads += 1
            clocks[0] += 0.5
            return b"garbage", ("127.0.0.1", 1)

        def close(self):
            self.closed = True

    monkeypatch.setattr(client.socket, "socket", Socket)
    monkeypatch.setattr(client.time, "monotonic", lambda: clocks[0])
    rep = reporter(default_transport)
    rep.incident(REPORT)
    assert rep.flush() == 0 and rep.pending() == 1
    assert [sock.reads for sock in sockets] == [4, 4]
    assert all(sock.closed for sock in sockets)
    assert clocks[0] == 4


def test_timestamp_preserving_registry_rewrite_revokes_cached_key(tmp_path):
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({"machines": {"a": "key-a", "b": "key-b"}}))
    clock = Clock(0)
    registry = KeyRegistry(str(path), now_fn=clock)
    assert registry.key_for("a") == "key-a"
    before = path.stat()
    # Same size and mtime, with an in-place update rather than an inode change.
    path.write_text(json.dumps({"machines": {"b": "key-b", "c": "key-c"}}))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    clock.now += 2
    assert registry.key_for("a") is None
    assert registry.key_for("c") == "key-c"


@pytest.mark.parametrize("symlink", [False, True])
def test_key_writer_never_reuses_a_preexisting_temporary_path(tmp_path, symlink):
    path, old_tmp, victim = (tmp_path / name for name in ("keys.json", "keys.json.tmp", "victim"))
    victim.write_text("preserve me")
    if symlink:
        old_tmp.symlink_to(victim)
    else:
        old_tmp.write_text("stale scratch")
        old_tmp.chmod(0o644)
    KeyRegistry(str(path)).enroll("desk-a")
    assert path.stat().st_mode & 0o777 == 0o600
    assert victim.read_text() == "preserve me"
    assert old_tmp.is_symlink() if symlink else old_tmp.read_text() == "stale scratch"


def test_key_writer_preserves_old_registry_and_cleans_up_on_replace_failure(tmp_path, monkeypatch):
    import netdnsmonitor.fleet_keys as keys

    path = tmp_path / "keys.json"
    registry = KeyRegistry(str(path))
    first = registry.enroll("a")
    before = path.read_bytes()
    before_paths = set(tmp_path.iterdir())

    def broken(*_):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(keys.os, "replace", broken)
    with pytest.raises(OSError):
        registry.enroll("b")
    assert path.read_bytes() == before and registry.key_for("a") == first
    assert registry.names() == ["a"]
    assert set(tmp_path.iterdir()) == before_paths


def test_separate_registry_writers_serialize_refresh_and_write(tmp_path, monkeypatch):
    path = str(tmp_path / "keys.json")
    first, second = KeyRegistry(path), KeyRegistry(path)
    entered, release, second_started, second_done = (threading.Event() for _ in range(4))
    errors, returned = [], {}
    write = first._write

    def paused(keys):
        entered.set()
        assert release.wait(2)
        write(keys)

    monkeypatch.setattr(first, "_write", paused)

    def enroll(registry, name):
        try:
            if name == "b":
                second_started.set()
            returned[name] = registry.enroll(name)
        except Exception as exc:  # noqa: BLE001 - surface failures from both test threads
            errors.append(exc)
        finally:
            if name == "b":
                second_done.set()

    a = threading.Thread(target=enroll, args=(first, "a"))
    b = threading.Thread(target=enroll, args=(second, "b"))
    a.start()
    try:
        assert entered.wait(2)
        b.start()
        assert second_started.wait(2)
        assert not second_done.wait(0.1)
    finally:
        release.set()
        a.join(2)
        if b.ident is not None:
            b.join(2)
    assert not a.is_alive() and not b.is_alive() and errors == []
    registry = KeyRegistry(path)
    assert registry.names() == ["a", "b"]
    assert {name: registry.key_for(name) for name in registry.names()} == returned


def test_failed_incident_append_remains_retryable(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    append = store._append

    def fail(_event):
        raise OSError("synthetic disk full")

    monkeypatch.setattr(store, "_append", fail)
    with pytest.raises(OSError):
        feed(store, proto.INCIDENT, "a")
    assert "mac-1" not in store.machines
    monkeypatch.setattr(store, "_append", append)
    assert feed(store, proto.INCIDENT, "a") == "logged"
    assert store.machines["mac-1"]["incidents_total"] == 1
    assert [event["kind"] for event in read_events(store.log_path)] == ["incident"]
    assert feed(store, proto.INCIDENT, "a") == "duplicate"


def test_failed_recovery_append_preserves_existing_incident(tmp_path, monkeypatch):
    import copy

    store = make_store(tmp_path)
    feed(store, proto.INCIDENT, "a")
    original = copy.deepcopy(store.machines)
    append = store._append

    def fail(_event):
        raise OSError("synthetic disk full")

    monkeypatch.setattr(store, "_append", fail)
    with pytest.raises(OSError):
        feed(store, proto.RESOLVED, "b")
    assert store.machines == original
    monkeypatch.setattr(store, "_append", append)
    assert feed(store, proto.RESOLVED, "b") == "logged"
    assert [event["kind"] for event in read_events(store.log_path)] == ["incident", "resolved"]


def test_duplicate_delivery_does_not_evict_distinct_event_ids(tmp_path):
    clock = Clock()
    store = make_store(tmp_path, clock)
    feed(store, proto.INCIDENT, "a")
    feed(store, proto.HELLO, "b", data={"status": "incident"})
    for _ in range(35):
        clock.now += 3
        assert feed(store, proto.HELLO, "b", data={"status": "incident"}) == "duplicate"
    assert store.machines["mac-1"]["recent_event_ids"] == ["a", "b"]
    assert feed(store, proto.INCIDENT, "a") == "duplicate"
    assert store.machines["mac-1"]["incidents_total"] == 1
    assert [event["kind"] for event in read_events(store.log_path)] == ["incident"]


def test_server_restarts_only_after_the_previous_reader_exits(tmp_path, monkeypatch):
    import netdnsmonitor.fleet_server as server_module

    entered, release = threading.Event(), threading.Event()
    sockets = []

    class Socket:
        def __init__(self, *_):
            self.closed, self.sent = threading.Event(), []
            sockets.append(self)

        def setsockopt(self, *_):
            pass

        def bind(self, *_):
            pass

        def getsockname(self):
            return "127.0.0.1", 45738

        def settimeout(self, *_):
            pass

        def recvfrom(self, *_):
            entered.set()
            assert release.wait(2)
            return message(), ("127.0.0.1", 123)

        def fileno(self):
            return -1 if self.closed.is_set() else 1

        def sendto(self, payload, target):
            self.sent.append((payload, target))

        def close(self):
            self.closed.set()

    monkeypatch.setattr(server_module.socket, "socket", Socket)
    store = make_store(tmp_path)
    server = FleetServer(store, now_fn=lambda: NOW, key_for=lambda _: SECRET)
    assert server.start()
    old = server.thread
    try:
        assert entered.wait(2)
        assert server.start() is True  # already running is idempotent
        assert len(sockets) == 1
        server.stop()
        assert server.start() is False
        release.set()
        old.join(2)
        assert not old.is_alive()
        assert store.machines == {} and sockets[0].sent == []
        release.clear()
        entered.clear()
        assert server.start()
        assert entered.wait(2)
        assert len(sockets) == 2
    finally:
        server.stop()
        release.set()
        old.join(2)
        server.thread.join(2)
    assert store.machines == {} and all(not sock.sent for sock in sockets)


def test_recovery_uses_wall_time_and_monotonic_duration():
    machine, rep = FakeMachine(), RecordingReporter()
    machine.reports = [REPORT]
    received = []
    rep.resolved = lambda *args, **kwargs: received.append((args, kwargs))
    monotonic, wall = Clock(10), Clock(NOW)
    mon = headless.HeadlessMonitor(
        {"reports_dir": "/unused"},
        machine,
        reporter=rep,
        save_report_fn=lambda *_: {"markdown_path": "unused"},
        now_fn=monotonic,
        wall_now_fn=wall,
    )
    machine.flap_gate.state = "incident"
    mon.step()
    monotonic.now += 60
    wall.now += 90  # A wall-clock adjustment must not change duration.
    machine.flap_gate.state = "healthy"
    mon.step()
    assert received[0][0][1] == 60
    assert received[0][1]["occurred_at"] == "2027-01-15T08:01:30+00:00"
    assert received[0][1]["occurred_at"] != REPORT["started_at"]


@pytest.mark.parametrize("phase", ["poll", "recovery"])
def test_headless_diagnostics_include_only_exception_classes(phase, capsys):
    machine, logs = FakeMachine(), []
    mon = headless.HeadlessMonitor({}, machine, log=logs.append)

    def broken():
        raise RuntimeError("SECRET_MARKER")

    if phase == "poll":
        machine.tick = broken
    else:
        mon._note_recovery = broken
    mon.step()
    assert mon.last_error == "RuntimeError"
    assert logs == [f"[{phase}] failed: RuntimeError"]
    captured = capsys.readouterr()
    assert "SECRET_MARKER" not in captured.out + captured.err + " ".join(logs)


def test_a_failing_diagnostic_sink_cannot_raise_out_of_a_poll():
    machine = FakeMachine()
    machine.raises = True

    def broken(_text):
        raise OSError("SECRET_MARKER")

    mon = headless.HeadlessMonitor({}, machine, log=broken)
    mon.step()
    assert mon.last_error == "RuntimeError"


@pytest.mark.parametrize("symlink", [False, True])
def test_store_save_never_reuses_an_existing_temporary_path(tmp_path, symlink):
    store = make_store(tmp_path)
    path = pathlib.Path(store.state_path)
    old_tmp = pathlib.Path(store.state_path + ".tmp")
    victim = tmp_path / "victim"
    victim.write_text("preserve me")
    if symlink:
        old_tmp.symlink_to(victim)
    else:
        old_tmp.write_text("stale scratch")
    store.save()
    assert json.loads(path.read_text())["machines"] == {}
    assert victim.read_text() == "preserve me"
    assert old_tmp.is_symlink() if symlink else old_tmp.read_text() == "stale scratch"


def test_failed_state_replace_keeps_old_file_and_retries_only_state_save(tmp_path, monkeypatch):
    import netdnsmonitor.fleet_store as store_module

    store = make_store(tmp_path)
    store.save()
    before = pathlib.Path(store.state_path).read_bytes()
    before_paths = set(tmp_path.iterdir())
    replace = store_module.os.replace

    def fail(*_):
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(store_module.os, "replace", fail)
    with pytest.raises(OSError):
        feed(store, proto.INCIDENT, "a")
    assert pathlib.Path(store.state_path).read_bytes() == before
    assert set(tmp_path.iterdir()) == before_paths | {pathlib.Path(store.log_path)}
    monkeypatch.setattr(store_module.os, "replace", replace)
    assert feed(store, proto.INCIDENT, "a") == "duplicate"
    assert len(read_events(store.log_path)) == 1
    assert read_state(store.state_path)["machines"]["mac-1"]["incidents_total"] == 1


@pytest.mark.parametrize("method", ["incident", "resolved"])
def test_enqueue_failure_is_counted_as_class_only_data(monkeypatch, method):
    rep = reporter(Transport())

    def fail(*_):
        raise OSError("SECRET_MARKER")

    monkeypatch.setattr(rep, "_enqueue", fail)
    if method == "incident":
        rep.incident(REPORT)
    else:
        rep.resolved("dns", 10)
    assert rep.last_error == "OSError" and rep.dropped == 1 and rep.pending() == 0
