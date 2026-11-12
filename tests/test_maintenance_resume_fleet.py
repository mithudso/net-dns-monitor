"""Synthetic fleet maintenance regressions; all effects are local or injected."""

import builtins
import json
import threading
import time

import pytest

from netdnsmonitor import fleet_client, fleet_keys, fleet_server, fleet_store, router


@pytest.mark.parametrize("operation", ["enroll", "revoke"])
@pytest.mark.parametrize("damage", ["unreadable", "malformed", "shape"])
def test_registry_mutation_preserves_failed_read(tmp_path, monkeypatch, operation, damage):
    path = tmp_path / "keys.json"
    path.write_text(
        "{oops"
        if damage == "malformed"
        else json.dumps([] if damage == "shape" else {"machines": {"A": "synthetic-key"}})
    )
    before = path.read_bytes()
    real_open = builtins.open

    def denied(file, *args, **kwargs):
        if str(file) == str(path) and damage == "unreadable":
            raise PermissionError("synthetic")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", denied)
    with pytest.raises((OSError, ValueError)):
        getattr(fleet_keys.KeyRegistry(str(path)), operation)("B")
    assert path.read_bytes() == before


def test_silence_retries_append_failure(tmp_path, monkeypatch):
    store = fleet_store.FleetStore(
        str(tmp_path / "events"), str(tmp_path / "state"), stale_seconds=1, now_fn=lambda: 100
    )
    store.machines["A"] = {"id": "A", "last_seen_epoch": 0, "silent": False}
    real = store._append
    calls = []

    def append(event):
        calls.append(event)
        if len(calls) == 1:
            raise OSError("synthetic full")
        real(event)

    monkeypatch.setattr(store, "_append", append)
    with pytest.raises(OSError):
        store.sweep()
    assert store.sweep() == ["A"]


def test_private_subnet_rejects_public_space():
    with pytest.raises(ValueError):
        router.validate("en3", "en0", "192.168.10.1", "255.0.0.0", "192.1.1.100", "192.1.1.200")


def test_oversized_event_does_not_block_later_delivery():
    r = fleet_client.FleetReporter(
        "machine",
        "host",
        server_address="127.0.0.1",
        transport=lambda *args: [],
        broadcast_fn=lambda: [],
    )
    r.resolved("😀" * 200, 1)
    r.resolved("dns", 1)
    assert r.dropped == 1
    assert r.pending() == 1
    assert r.outbox[0][2]["classification"] == "dns"


def test_refusal_flood_has_bounded_persistence(tmp_path, monkeypatch):
    store = fleet_store.FleetStore(
        str(tmp_path / "events"), str(tmp_path / "state"), now_fn=lambda: 100
    )
    saves = []
    monkeypatch.setattr(store, "save", lambda: saves.append(True))
    server = fleet_server.FleetServer(store)
    for _ in range(100):
        server.handle(b"", "192.0.2.1")
    assert sum(store.refused.values()) == 100
    assert len(saves) <= 1


def test_hostname_resolution_spends_shared_deadline(monkeypatch):
    release = threading.Event()
    entered = threading.Event()

    class Socket:
        def setsockopt(self, *args):
            pass

        def settimeout(self, *args):
            pass

        def sendto(self, payload, target):
            assert target[0] == "192.0.2.1"

        def recvfrom(self, *args):
            raise OSError("synthetic")

        def close(self):
            pass

    def resolve(*args, **kwargs):
        entered.set()
        release.wait(1)
        return [(2, 2, 17, "", ("192.0.2.1", 1))]

    monkeypatch.setattr(fleet_client.socket, "socket", lambda *args: Socket())
    monkeypatch.setattr(fleet_client.socket, "getaddrinfo", resolve)
    started = time.monotonic()
    try:
        assert fleet_client.default_transport(b"x", ["synthetic.invalid"], 1, 0.02) == []
        assert time.monotonic() - started < 0.5
        assert entered.is_set()
        assert not release.is_set()
    finally:
        release.set()


def test_refusal_save_failures_are_also_throttled(tmp_path, monkeypatch):
    store = fleet_store.FleetStore(
        str(tmp_path / "events"), str(tmp_path / "state"), now_fn=lambda: 100
    )
    calls = []

    def fail():
        calls.append(True)
        raise OSError("synthetic")

    monkeypatch.setattr(store, "save", fail)
    with pytest.raises(OSError):
        store.note_refused("malformed")
    for _ in range(100):
        store.note_refused("malformed")
    assert len(calls) == 1
    assert store.refused["malformed"] == 101


def test_server_shutdown_flushes_pending_refusals(tmp_path, monkeypatch):
    store = fleet_store.FleetStore(
        str(tmp_path / "events"), str(tmp_path / "state"), now_fn=lambda: 100
    )
    server = fleet_server.FleetServer(store)
    for _ in range(3):
        server.handle(b"", "192.0.2.1")
    monkeypatch.setattr(server, "_receive_loop", lambda: None)
    server._read_loop()
    assert sum(json.loads((tmp_path / "state").read_text())["refused"].values()) == 3


def test_silence_state_save_is_retried_without_duplicate_log(tmp_path, monkeypatch):
    store = fleet_store.FleetStore(
        str(tmp_path / "events"), str(tmp_path / "state"), stale_seconds=1, now_fn=lambda: 100
    )
    store.machines["A"] = {"id": "A", "last_seen_epoch": 0, "silent": False, "status": "healthy"}
    store.save()
    save = store.save
    calls = []

    def flaky():
        calls.append(True)
        if len(calls) == 1:
            raise OSError("synthetic full")
        save()

    monkeypatch.setattr(store, "save", flaky)
    with pytest.raises(OSError):
        store.sweep()
    assert store.sweep() == []
    assert json.loads((tmp_path / "state").read_text())["machines"]["A"]["silent"] is True
    assert len((tmp_path / "events").read_text().splitlines()) == 1


def test_flush_bounds_replenishing_producer(monkeypatch):
    reporter = fleet_client.FleetReporter(
        "machine", "host", transport=lambda *args: [], broadcast_fn=lambda: []
    )
    reporter.resolved("dns", 1)
    calls = []

    def deliver(*args):
        calls.append(True)
        reporter.resolved("dns", 1)
        if len(calls) > 3:
            pytest.fail("flush did not yield after its initial batch")
        return True

    monkeypatch.setattr(reporter, "_deliver", deliver)
    assert reporter.flush() == 1
    assert reporter.pending() == 1


def _fleet_message(kind, eid, status=None):
    return {
        "id": "A",
        "host": "synthetic",
        "eid": eid,
        "signed": True,
        "t": kind,
        "data": {"status": status} if status else {},
    }


def test_duplicate_retry_logs_return_once(tmp_path):
    proto = fleet_store.proto
    clock = [100]
    store = fleet_store.FleetStore(
        str(tmp_path / "events"),
        str(tmp_path / "state"),
        stale_seconds=1,
        now_fn=lambda: clock[0],
    )
    message = _fleet_message(proto.INCIDENT, "e1")
    store.record(message, "192.0.2.1")
    clock[0] = 102
    store.sweep()
    assert store.record(message, "192.0.2.1") == "duplicate"
    assert store.record(message, "192.0.2.1") == "duplicate"
    kinds = [json.loads(line)["kind"] for line in (tmp_path / "events").read_text().splitlines()]
    assert kinds == [fleet_store.INCIDENT, fleet_store.SILENT, fleet_store.ONLINE]


def test_healthy_return_retry_preserves_online_append_progress(tmp_path, monkeypatch):
    proto = fleet_store.proto
    clock = [100]
    store = fleet_store.FleetStore(
        str(tmp_path / "events"),
        str(tmp_path / "state"),
        stale_seconds=1,
        now_fn=lambda: clock[0],
    )
    store.record(_fleet_message(proto.INCIDENT, "e1"), "192.0.2.1")
    clock[0] = 102
    store.sweep()
    append = store._append
    failed = []

    def flaky(event):
        if event["kind"] == fleet_store.RESOLVED and not failed:
            failed.append(True)
            raise OSError("synthetic full")
        append(event)

    monkeypatch.setattr(store, "_append", flaky)
    message = _fleet_message(proto.HELLO, "e2", proto.STATUS_HEALTHY)
    with pytest.raises(OSError):
        store.record(message, "192.0.2.1")
    assert store.record(message, "192.0.2.1") == "logged"
    kinds = [json.loads(line)["kind"] for line in (tmp_path / "events").read_text().splitlines()]
    assert kinds == [
        fleet_store.INCIDENT,
        fleet_store.SILENT,
        fleet_store.ONLINE,
        fleet_store.RESOLVED,
    ]
    assert store.machines["A"]["open_incident"] is None


def test_restart_retains_hourly_switch_history_above_32(tmp_path):
    from netdnsmonitor.failover import FailoverStore

    path = str(tmp_path / "failover.json")
    store = FailoverStore(path)
    store.switch_times = list(range(100, 133))
    store.last_switch_at = 132
    store.save()
    restored = FailoverStore(path)
    restored.load()
    assert restored.switch_times == store.switch_times


def test_flush_yields_when_delivery_requests_stop(monkeypatch):
    reporter = fleet_client.FleetReporter(
        "machine", "host", transport=lambda *args: [], broadcast_fn=lambda: []
    )
    for _ in range(3):
        reporter.resolved("dns", 1)

    def deliver(*args):
        reporter.stop()
        return True

    monkeypatch.setattr(reporter, "_deliver", deliver)
    assert reporter.flush() == 1
    assert reporter.pending() == 2


def test_duplicate_return_append_failure_keeps_machine_silent(tmp_path, monkeypatch):
    clock = [100]
    store = fleet_store.FleetStore(
        str(tmp_path / "events"),
        str(tmp_path / "state"),
        stale_seconds=1,
        now_fn=lambda: clock[0],
    )
    message = _fleet_message(fleet_store.proto.INCIDENT, "e1")
    store.record(message, "192.0.2.1")
    clock[0] = 102
    store.sweep()
    append = store._append

    def fail(event):
        raise OSError("synthetic full")

    monkeypatch.setattr(store, "_append", fail)
    with pytest.raises(OSError):
        store.record(message, "192.0.2.1")
    assert store.machines["A"]["silent"] is True
    monkeypatch.setattr(store, "_append", append)
    assert store.record(message, "192.0.2.1") == "duplicate"
    assert store.machines["A"]["silent"] is False


def test_worker_does_not_start_heartbeat_after_delivery_stops_it(monkeypatch):
    reporter = fleet_client.FleetReporter(
        "machine", "host", transport=lambda *args: [], broadcast_fn=lambda: []
    )
    reporter.resolved("dns", 1)
    heartbeats = []

    def deliver(*args):
        reporter.stop()
        return True

    monkeypatch.setattr(reporter, "_deliver", deliver)
    monkeypatch.setattr(reporter, "heartbeat", lambda: heartbeats.append(True))
    reporter._run()
    assert heartbeats == []
