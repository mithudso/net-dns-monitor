"""The peer registry: bucketing by recency, hostile-input handling, and the
on-disk record.

Clock injected, so every bucket boundary here is exact rather than timing
dependent.
"""

import json
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

from netdnsmonitor.localize import LOCAL_MACHINE, localize
from netdnsmonitor.peers import (
    CURRENT,
    OTHER,
    RECENT,
    PeerRegistry,
    load_record,
    sanitise,
    save_record,
)

START = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=START):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


def make_registry(clock=None, **kwargs):
    return PeerRegistry(self_id="me", clock=clock or Clock(), **kwargs)


# --- observing -------------------------------------------------------------


def test_a_new_peer_is_reported_as_new_once():
    reg = make_registry()
    assert reg.observe("peer-a", host="mac-a", address="192.168.1.5") is True
    assert reg.observe("peer-a", host="mac-a", address="192.168.1.5") is False
    assert len(reg.peers) == 1


def test_an_instance_never_records_itself_as_a_peer():
    """Broadcasts loop back on the sending host, so without this every instance
    would list itself and the peer count would always be off by one.
    """
    reg = make_registry()
    assert reg.observe("me", host="this-mac") is False
    assert reg.peers == {}


def test_an_empty_id_is_ignored():
    reg = make_registry()
    assert reg.observe("", host="nameless") is False
    assert reg.observe(None) is False
    assert reg.peers == {}


def test_first_seen_is_preserved_across_later_sightings():
    clock = Clock()
    reg = make_registry(clock)
    reg.observe("peer-a", host="mac-a")
    clock.advance(hours=3)
    reg.observe("peer-a", host="mac-a")
    peer = reg.peers["peer-a"]
    assert peer["first_seen"] == START.isoformat()
    assert peer["last_seen"] != peer["first_seen"]


def test_a_later_sighting_without_a_hostname_keeps_the_known_one():
    """A pong carries less than an announcement. Overwriting with "" would erase
    the hostname that makes the record readable.
    """
    reg = make_registry()
    reg.observe("peer-a", host="mac-a", address="192.168.1.5")
    reg.observe("peer-a", host="", address="")
    assert reg.peers["peer-a"]["host"] == "mac-a"
    assert reg.peers["peer-a"]["address"] == "192.168.1.5"


# --- buckets ---------------------------------------------------------------


def test_a_just_heard_peer_is_current():
    reg = make_registry()
    reg.observe("peer-a")
    assert reg.bucket(reg.peers["peer-a"]) == CURRENT


def test_a_peer_becomes_recent_then_other_purely_by_the_clock():
    """No code marks a peer as gone -- it is reclassified by elapsed time, so a
    machine that is switched off needs nothing to notice it left.
    """
    clock = Clock()
    reg = make_registry(clock, current_seconds=600, recent_seconds=86400)
    reg.observe("peer-a")

    clock.advance(seconds=599)
    assert reg.bucket(reg.peers["peer-a"]) == CURRENT
    clock.advance(seconds=2)
    assert reg.bucket(reg.peers["peer-a"]) == RECENT
    clock.advance(days=1)
    assert reg.bucket(reg.peers["peer-a"]) == OTHER


def test_current_window_tolerates_one_missed_announcement():
    """Default current_seconds is two announce intervals, so a single dropped
    broadcast does not demote a healthy peer.
    """
    clock = Clock()
    reg = make_registry(clock)
    reg.observe("peer-a")
    clock.advance(seconds=301)  # one announcement missed at a 300s cadence
    assert reg.bucket(reg.peers["peer-a"]) == CURRENT


def test_an_unparsable_last_seen_lands_in_other_rather_than_raising():
    """The record file is plain JSON on disk and can be hand-edited."""
    reg = make_registry()
    reg.peers["peer-a"] = {"id": "peer-a", "last_seen": "not a timestamp"}
    assert reg.bucket(reg.peers["peer-a"]) == OTHER


def test_buckets_are_ordered_most_recent_first():
    clock = Clock()
    reg = make_registry(clock)
    reg.observe("older")
    clock.advance(seconds=10)
    reg.observe("newer")
    assert [p["id"] for p in reg.buckets()[CURRENT]] == ["newer", "older"]


# --- hostile input ---------------------------------------------------------


def test_control_characters_are_stripped_from_anything_off_the_wire():
    """These strings go into a monospaced window and a JSON file; an embedded
    newline or escape sequence would corrupt both.
    """
    assert sanitise("mac-a\n\r\x1b[31mred") == "mac-a[31mred"
    assert "\n" not in sanitise("a\nb")


def test_absurdly_long_fields_are_truncated():
    reg = make_registry()
    reg.observe("x" * 5000, host="h" * 5000)
    peer = next(iter(reg.peers.values()))
    assert len(peer["id"]) == 64
    assert len(peer["host"]) == 253


def test_non_string_fields_are_coerced_not_stored_raw():
    reg = make_registry()
    reg.observe("peer-a", host={"evil": "dict"}, status=["list"])
    peer = reg.peers["peer-a"]
    assert isinstance(peer["host"], str)
    assert isinstance(peer["status"], str)


def test_the_table_is_capped_so_a_flood_cannot_exhaust_memory():
    """A host spraying announcements with a fresh id each time would otherwise
    grow this table and the record file without limit.
    """
    clock = Clock()
    reg = make_registry(clock, max_peers=5)
    for index in range(50):
        clock.advance(seconds=1)
        reg.observe(f"peer-{index}")
    assert len(reg.peers) == 5


def test_eviction_drops_the_least_recently_heard_peer():
    clock = Clock()
    reg = make_registry(clock, max_peers=2)
    reg.observe("oldest")
    clock.advance(seconds=10)
    reg.observe("middle")
    clock.advance(seconds=10)
    reg.observe("newest")
    assert set(reg.peers) == {"middle", "newest"}


# --- healthchecks ----------------------------------------------------------


def test_a_missed_healthcheck_is_counted():
    reg = make_registry()
    reg.observe("peer-a")
    reg.note_healthcheck_miss("peer-a")
    reg.note_healthcheck_miss("peer-a")
    assert reg.peers["peer-a"]["missed_healthchecks"] == 2


def test_being_heard_from_again_clears_the_missed_count():
    reg = make_registry()
    reg.observe("peer-a")
    reg.note_healthcheck_miss("peer-a")
    reg.observe("peer-a", via="pong")
    assert reg.peers["peer-a"]["missed_healthchecks"] == 0


def test_a_miss_for_an_unknown_peer_is_harmless():
    make_registry().note_healthcheck_miss("never-seen")


# --- the record file -------------------------------------------------------


def test_the_record_groups_hosts_into_current_recent_and_other(tmp_path):
    clock = Clock()
    reg = make_registry(clock, current_seconds=600, recent_seconds=86400)
    reg.observe("gone", host="old-mac")
    clock.advance(days=3)
    reg.observe("away", host="sometimes-mac")
    clock.advance(seconds=700)
    reg.observe("here", host="live-mac")

    path = tmp_path / "peers.json"
    assert save_record(reg, str(path)) is True
    record = json.loads(path.read_text(encoding="utf-8"))

    assert set(record["peers"]) == {CURRENT, RECENT, OTHER}
    assert [p["host"] for p in record["peers"][CURRENT]] == ["live-mac"]
    assert [p["host"] for p in record["peers"][RECENT]] == ["sometimes-mac"]
    assert [p["host"] for p in record["peers"][OTHER]] == ["old-mac"]
    assert record["counts"] == {CURRENT: 1, RECENT: 1, OTHER: 1}
    assert record["self_id"] == "me"


def test_each_entry_carries_its_bucket_so_the_file_reads_on_its_own(tmp_path):
    reg = make_registry()
    reg.observe("peer-a", host="mac-a")
    path = tmp_path / "peers.json"
    save_record(reg, str(path))
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["peers"][CURRENT][0]["bucket"] == CURRENT


def test_a_record_round_trips_so_a_restart_remembers_who_was_there(tmp_path):
    """This is what makes "try to connect to them on startup" possible at all --
    otherwise a fresh process knows nobody until someone announces.
    """
    clock = Clock()
    reg = make_registry(clock)
    reg.observe("peer-a", host="mac-a", address="192.168.1.5")
    path = tmp_path / "peers.json"
    save_record(reg, str(path))

    restored = make_registry(clock)
    restored.load(load_record(str(path)))
    assert restored.peers["peer-a"]["host"] == "mac-a"
    assert restored.peers["peer-a"]["address"] == "192.168.1.5"
    assert restored.addresses_to_probe() == [("peer-a", "192.168.1.5")]


def test_a_restart_probes_peers_from_every_bucket():
    """A machine last seen yesterday is exactly the one worth probing at startup;
    restricting to `current` would mean a restart finds nobody.
    """
    clock = Clock()
    reg = make_registry(clock)
    reg.observe("old", address="192.168.1.9")
    clock.advance(days=2)
    reg.observe("new", address="192.168.1.10")
    assert dict(reg.addresses_to_probe()) == {"old": "192.168.1.9", "new": "192.168.1.10"}


def test_duplicate_addresses_are_probed_once():
    reg = make_registry()
    reg.observe("peer-a", address="192.168.1.5")
    reg.observe("peer-b", address="192.168.1.5")
    assert len(reg.addresses_to_probe()) == 1


def test_a_corrupt_record_file_does_not_stop_startup(tmp_path):
    path = tmp_path / "peers.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert load_record(str(path)) == {}
    reg = make_registry()
    reg.load(load_record(str(path)))
    assert reg.peers == {}


def test_a_missing_record_file_is_not_an_error(tmp_path):
    assert load_record(str(tmp_path / "never-written.json")) == {}


def test_a_record_of_the_wrong_shape_is_ignored():
    reg = make_registry()
    reg.load({"peers": "not a dict"})
    reg.load({"peers": {"current": "not a list"}})
    reg.load({"peers": {"current": ["not a dict"]}})
    reg.load(["not a dict at all"])
    assert reg.peers == {}


def test_our_own_id_in_a_stale_record_is_not_loaded_as_a_peer():
    """The id is regenerated per process, but a hand-copied record file between
    machines could carry it.
    """
    reg = make_registry()
    reg.load({"peers": {"current": [{"id": "me", "host": "self"}]}})
    assert reg.peers == {}


def test_load_respects_the_peer_cap():
    reg = make_registry(max_peers=3)
    reg.load({"peers": {"current": [{"id": f"peer-{i}", "host": f"h{i}"} for i in range(50)]}})
    assert len(reg.peers) == 3


def test_an_unwritable_record_path_returns_false_rather_than_raising(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("I am a file", encoding="utf-8")
    reg = make_registry()
    reg.observe("peer-a")
    assert save_record(reg, str(blocker / "sub" / "peers.json")) is False


# --- localization view -----------------------------------------------------


def test_a_peer_last_seen_days_ago_is_not_counted_as_silent():
    """Silence from a machine that was switched off three days ago says nothing
    about this outage. Counted as silent, it was the only peer, so "none of the
    known peers answered" blamed this machine's own link at high confidence.
    """
    clock = Clock()
    reg = make_registry(clock)
    reg.load(
        {
            "peers": {
                OTHER: [
                    {
                        "id": "home-imac",
                        "host": "imac",
                        "address": "192.168.1.9",
                        "last_seen": (START - timedelta(days=3)).isoformat(),
                    }
                ]
            }
        }
    )
    view = reg.localization_view(fresh_seconds=15)
    assert view == []
    assert localize(False, None, view)["verdict"] != LOCAL_MACHINE


def test_a_current_peer_that_did_not_answer_is_still_reported_silent():
    """The cut is the `current` window, not the fresh one: a peer heard from a
    few minutes ago was probed and did not answer, which is real evidence.
    """
    clock = Clock()
    reg = make_registry(clock, current_seconds=600)
    reg.observe("peer-a", address="192.168.1.5")
    clock.advance(seconds=300)
    view = reg.localization_view(fresh_seconds=15)
    assert [(p["id"], p["answered"]) for p in view] == [("peer-a", False)]


def test_a_peer_that_answered_is_kept_even_when_fresh_exceeds_current():
    """A misconfigured `current` window shorter than the fresh window must not
    drop a peer that just answered.
    """
    clock = Clock()
    reg = make_registry(clock, current_seconds=5)
    reg.observe("peer-a")
    clock.advance(seconds=10)
    assert [p["answered"] for p in reg.localization_view(fresh_seconds=15)] == [True]


def test_a_future_dated_last_seen_is_neither_answered_nor_silent():
    """A negative age comes from a hand-edited record or a clock stepped back.
    It says nothing about when the peer was last heard from, so it must not count
    as a peer that answered, and must not count as one that went silent either.
    """
    clock = Clock()
    reg = make_registry(clock)
    reg.load(
        {
            "peers": {
                CURRENT: [
                    {
                        "id": "skewed",
                        "address": "192.168.1.7",
                        "last_seen": (START + timedelta(hours=1)).isoformat(),
                    }
                ]
            }
        }
    )
    assert not any(p["answered"] for p in reg.localization_view(fresh_seconds=15))
    assert reg.localization_view(fresh_seconds=15) == []


# --- concurrency -----------------------------------------------------------


def test_readers_survive_the_listener_thread_mutating_the_table():
    """peer_net.py calls observe() on its listener thread while the main thread
    reads. Unlocked, iteration raised "dictionary changed size during iteration",
    which aborted the peer sweep before the record was saved and dropped the
    fault verdict for an outage.
    """
    reg = PeerRegistry(self_id="me", max_peers=20)
    stop = threading.Event()

    def flood():
        index = 0
        while not stop.is_set():
            reg.observe(f"peer-{index}", host="h", address=f"10.0.{index % 250}.1")
            reg.note_healthcheck_miss(f"peer-{index - 3}")
            index += 1

    old_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    errors = []
    writer = threading.Thread(target=flood, daemon=True)
    writer.start()
    try:
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            try:
                reg.buckets()
                reg.to_dict()
                reg.localization_view(fresh_seconds=15)
                reg.addresses_to_probe()
            except RuntimeError as exc:
                errors.append(exc)
                break
    finally:
        stop.set()
        writer.join(timeout=5)
        sys.setswitchinterval(old_interval)
    assert errors == []


def test_buckets_hand_out_copies_not_the_live_entries():
    """The dashboard reads these on the main thread; a live entry would keep
    changing under it as the listener thread records pongs.
    """
    reg = make_registry()
    reg.observe("peer-a", host="mac-a")
    reg.buckets()[CURRENT][0]["host"] = "changed"
    assert reg.peers["peer-a"]["host"] == "mac-a"
