"""The forensic record of a down/up episode.

The clock is injected, so every timestamp here is deterministic. The writer is
real (report_storage._atomic_write) except where a failure is being forced --
these documents are the deliverable, so it is worth asserting against bytes
actually on disk.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netdnsmonitor.forensic_log import (
    DOWN,
    ESCALATION,
    OBSERVATION,
    RECHECK,
    STEP,
    UP,
    ForensicRecorder,
    render_episode_markdown,
)

START = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


class FakeClock:
    """Advances a fixed step per call, so ordering is visible in the output."""

    def __init__(self, start=START, step_seconds=5):
        self.now = start
        self.step = timedelta(seconds=step_seconds)

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


def make_recorder(tmp_path, clock=None):
    return ForensicRecorder(
        journal_path=str(tmp_path / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
        clock=clock or FakeClock(),
    )


def journal_lines(tmp_path):
    path = tmp_path / "forensic.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


# --- episode lifecycle -----------------------------------------------------


def test_a_ping_failure_opens_an_episode(tmp_path):
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply from 8.8.8.8")
    assert rec.is_open
    assert rec.episode["trigger_detector"] == "ping"


def test_recovery_closes_the_episode_and_writes_both_documents(tmp_path):
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply from 8.8.8.8")
    paths = rec.note(UP, "ping", reason="Pings answered again")

    assert not rec.is_open
    assert paths is not None
    for path in paths.values():
        assert path.endswith(("-episode.json", "-episode.md"))
    body = Path(paths["markdown_path"]).read_text(encoding="utf-8")
    assert "Network down/up episode" in body
    assert "8.8.8.8" in body


def test_a_gate_incident_joins_the_open_episode_rather_than_starting_a_second(tmp_path):
    """The two detectors run on different clocks -- 5s heartbeat, 30s gate -- so
    the gate almost always declares its incident while the heartbeat is already
    down. Opening a second episode there would split one outage across two
    documents, each missing half the story.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply from 8.8.8.8")
    first_started = rec.episode["started_at"]
    rec.note(DOWN, "flap_gate", reason="2 consecutive failed probes, dns classification")

    assert rec.episode["started_at"] == first_started
    assert rec.episode["trigger_detector"] == "ping"
    paths = rec.note(UP, "ping")
    assert len(json.loads(Path(paths["json_path"]).read_text(encoding="utf-8"))["events"]) == 3


def test_the_gate_can_open_an_episode_on_its_own(tmp_path):
    """The reverse order matters too: a DNS-layer incident can be declared while
    ICMP to 8.8.8.8 still answers perfectly, so the heartbeat never goes down.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "flap_gate", reason="dns incident declared")
    assert rec.is_open
    assert rec.episode["trigger_detector"] == "flap_gate"


def test_recovery_with_no_open_episode_writes_nothing(tmp_path):
    """Every healthy tick must not produce a document."""
    rec = make_recorder(tmp_path)
    assert rec.note(UP, "ping") is None
    assert not (tmp_path / "episodes").exists()


def test_a_second_outage_after_recovery_gets_its_own_document(tmp_path):
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="first")
    first = rec.note(UP, "ping")
    rec.note(DOWN, "ping", reason="second")
    second = rec.note(UP, "ping")
    assert first["json_path"] != second["json_path"]


def test_events_while_healthy_are_journaled_but_not_attributed_to_an_episode(tmp_path):
    rec = make_recorder(tmp_path)
    rec.note(OBSERVATION, "ping", detail="rtt 61ms")
    events = journal_lines(tmp_path)
    assert len(events) == 1
    assert "episode_started_at" not in events[0]


# --- durability ------------------------------------------------------------


def test_every_event_is_journaled_the_moment_it_happens(tmp_path):
    """The case this whole module exists for: an app killed, crashed, or powered
    off mid-outage still leaves the evidence behind. Buffering until recovery
    would lose exactly the outages worth investigating.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply")
    rec.note(STEP, "flap_gate", detail="flush_dns_cache", reason="stale answer", result="ok")

    # No UP yet, so no summary document exists -- but the journal already has it.
    assert not (tmp_path / "episodes").exists()
    events = journal_lines(tmp_path)
    assert [e["kind"] for e in events] == [DOWN, STEP]
    assert events[1]["result"] == "ok"
    assert all(e["episode_started_at"] == events[0]["at"] for e in events)


def test_an_unwritable_journal_does_not_raise(tmp_path):
    """Called every few seconds during an outage. A full disk must not be what
    finally kills the monitor.
    """
    rec = ForensicRecorder(
        journal_path=str(tmp_path / "not-a-dir" / "x" / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
        clock=FakeClock(),
    )
    (tmp_path / "not-a-dir").write_text("I am a file, not a directory", encoding="utf-8")
    rec.note(DOWN, "ping", reason="No reply")
    assert rec.is_open  # the in-memory episode still tracks


def test_a_failing_writer_does_not_wedge_the_episode_open(tmp_path):
    """If a failed write left the episode open, every subsequent outage would be
    swallowed into one endless episode that never closes.
    """

    def boom(path, text):
        raise OSError("disk full")

    rec = ForensicRecorder(
        journal_path=str(tmp_path / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
        clock=FakeClock(),
        writer=boom,
    )
    rec.note(DOWN, "ping", reason="No reply")
    assert rec.note(UP, "ping") is None
    assert not rec.is_open

    # And the next outage is still recorded.
    rec.note(DOWN, "ping", reason="No reply again")
    assert rec.is_open


def test_a_rendering_failure_does_not_raise_out_of_note(tmp_path):
    """note() promises never to raise, which is why _write_episode catches
    broader than OSError.
    """

    def unserialisable(path, text):
        raise TypeError("not JSON serialisable")

    rec = ForensicRecorder(
        journal_path=str(tmp_path / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
        clock=FakeClock(),
        writer=unserialisable,
    )
    rec.note(DOWN, "ping")
    assert rec.note(UP, "ping") is None


# --- timestamps ------------------------------------------------------------


def test_timestamps_are_wall_clock_not_monotonic(tmp_path):
    """The heartbeat's own arithmetic uses time.monotonic(), which would render
    here as `847293.44` -- useless in a document someone reads later.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping")
    at = journal_lines(tmp_path)[0]["at"]
    assert at.startswith("2026-08-04T12:00:00")
    assert datetime.fromisoformat(at).tzinfo is not None


def test_duration_is_recorded_and_humanised(tmp_path):
    rec = make_recorder(tmp_path, clock=FakeClock(step_seconds=45))
    rec.note(DOWN, "ping")
    paths = rec.note(UP, "ping")
    episode = json.loads(Path(paths["json_path"]).read_text(encoding="utf-8"))
    assert episode["duration_seconds"] == 45
    assert "45s" in Path(paths["markdown_path"]).read_text(encoding="utf-8")


def test_a_multi_minute_outage_reads_in_minutes(tmp_path):
    rec = make_recorder(tmp_path, clock=FakeClock(step_seconds=185))
    rec.note(DOWN, "ping")
    paths = rec.note(UP, "ping")
    assert "3m 5s" in Path(paths["markdown_path"]).read_text(encoding="utf-8")


# --- the document itself ---------------------------------------------------


def test_the_summary_records_each_step_with_its_reason_and_result(tmp_path):
    """The literal ask: steps taken, the reason it was taken, and the results."""
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply from 8.8.8.8")
    rec.note(
        STEP,
        "flap_gate",
        detail="flush_dns_cache",
        reason="A cached negative answer keeps failing after the fault is gone.",
        result="ok",
    )
    rec.note(RECHECK, "flap_gate", reason="Did the repair work", result="still failing")
    rec.note(ESCALATION, "flap_gate", reason="Ladder exhausted", result="sent to Claude")
    paths = rec.note(UP, "ping", reason="Pings answered again")

    body = Path(paths["markdown_path"]).read_text(encoding="utf-8")
    assert "flush_dns_cache" in body
    assert "cached negative answer" in body
    assert "still failing" in body
    assert "sent to Claude" in body
    assert "## Steps taken" in body
    assert "| Step | Kind | Why it was run | Result |" in body


def test_an_outage_with_no_steps_says_so_explicitly(tmp_path):
    """A short blip clears before the gate declares an incident, so the ladder
    never runs. An empty table would read like the app failed to act; the
    document should say the network recovered on its own.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping", reason="No reply")
    paths = rec.note(UP, "ping")
    body = Path(paths["markdown_path"]).read_text(encoding="utf-8")
    assert "No remedial step ran" in body
    assert "before the anti-flap gate" in body


def test_multi_line_command_output_cannot_break_the_steps_table(tmp_path):
    """`scutil --nwi` returns a dozen lines and route output contains pipes. A
    raw newline or pipe inside a cell breaks the table for every row after it.
    """
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping")
    rec.note(
        STEP,
        "flap_gate",
        detail="check_interface_state",
        reason="Confirm the link is up",
        result="network: reachable\nen0: active | flags=8863",
    )
    paths = rec.note(UP, "ping")
    body = Path(paths["markdown_path"]).read_text(encoding="utf-8")

    table_rows = [ln for ln in body.splitlines() if ln.startswith("| check_interface_state")]
    assert len(table_rows) == 1
    assert "\n" not in table_rows[0]
    assert "en0: active" in table_rows[0]
    assert r"\|" in table_rows[0]


def test_missing_reason_is_reported_as_such_rather_than_left_blank(tmp_path):
    """A blank cell is ambiguous between "no reason" and "rendering dropped it"."""
    rec = make_recorder(tmp_path)
    rec.note(DOWN, "ping")
    paths = rec.note(UP, "ping")
    assert "not recorded" in Path(paths["markdown_path"]).read_text(encoding="utf-8")


def test_the_timeline_is_chronological_not_grouped_by_kind():
    """The question asked of this document is what happened in what order."""
    episode = {
        "started_at": "2026-08-04T12:00:00+00:00",
        "ended_at": "2026-08-04T12:01:00+00:00",
        "duration_seconds": 60,
        "trigger_detector": "ping",
        "trigger_reason": "no reply",
        "recovered_detector": "ping",
        "events": [
            {"at": "t1", "kind": DOWN, "detector": "ping", "reason": "r1", "result": ""},
            {"at": "t2", "kind": STEP, "detector": "flap_gate", "detail": "s", "reason": "r2"},
            {"at": "t3", "kind": UP, "detector": "ping", "reason": "r3", "result": ""},
        ],
    }
    body = render_episode_markdown(episode)
    assert body.index("t1") < body.index("t2") < body.index("t3")


def test_rendering_an_episode_that_never_closed_does_not_crash():
    """The journal can be replayed into this renderer for an episode that was
    cut short by a crash, which is precisely when there is no ended_at.
    """
    body = render_episode_markdown({"started_at": "t0", "events": []})
    assert "still down" in body
    assert "unknown" in body
