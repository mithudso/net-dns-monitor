"""The rolling sample history behind the graphs.

Clock injected, so ordering and spans are exact. The file is real, because
append-then-compact is the whole point of the persistence design and asserting
against line counts on disk is the only way to pin it.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from netdnsmonitor.history import SampleHistory

START = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, step_seconds=5):
        self.now = START
        self.step = timedelta(seconds=step_seconds)

    def __call__(self):
        value = self.now
        self.now += self.step
        return value


def make(tmp_path=None, **kwargs):
    path = str(tmp_path / "history.jsonl") if tmp_path else None
    return SampleHistory(path=path, clock=kwargs.pop("clock", Clock()), **kwargs)


# --- recording -------------------------------------------------------------


def test_a_sample_is_recorded_with_a_wall_clock_timestamp():
    history = make()
    sample = history.record(rtt_ms=61.4, loss_pct=0.0, down_bps=1e6, up_bps=2e5)
    assert sample["at"].startswith("2026-08-04T12:00:00")
    assert sample["rtt_ms"] == 61.4


def test_the_window_is_bounded():
    """Unbounded, this grows for the life of the process at one sample per 5s."""
    history = make(max_samples=10)
    for _ in range(50):
        history.record(rtt_ms=1.0)
    assert len(history.samples) == 10


def test_a_failed_ping_is_recorded_as_a_gap_not_skipped():
    """Skipping it would draw a straight line across an outage as though nothing
    happened -- the graph would hide exactly what it exists to show.
    """
    history = make()
    history.record(rtt_ms=61.0)
    history.record(rtt_ms=None, down=True)
    history.record(rtt_ms=62.0)
    assert history.series("rtt_ms") == [61.0, None, 62.0]
    assert [s["down"] for s in history.samples] == [False, True, False]


def test_series_returns_one_entry_per_sample_including_gaps():
    history = make()
    history.record(down_bps=1000.0)
    history.record(down_bps=None)
    assert history.series("down_bps") == [1000.0, None]


def test_span_reports_the_time_covered():
    history = make(clock=Clock(step_seconds=5))
    for _ in range(13):
        history.record(rtt_ms=1.0)
    assert history.span_seconds() == 60.0


def test_span_is_unknown_until_there_are_two_samples():
    history = make()
    assert history.span_seconds() is None
    history.record(rtt_ms=1.0)
    assert history.span_seconds() is None


def test_latest_returns_the_newest_sample():
    history = make()
    history.record(rtt_ms=1.0)
    history.record(rtt_ms=2.0)
    assert history.latest()["rtt_ms"] == 2.0


def test_latest_is_none_when_empty():
    assert make().latest() is None


# --- persistence -----------------------------------------------------------


def test_each_sample_costs_one_appended_line(tmp_path):
    """The steady-state cost. A full rewrite per sample would be ~17,000
    rewrites of the whole file per day at a 5s cadence.
    """
    history = make(tmp_path, max_samples=100)
    for _ in range(5):
        history.record(rtt_ms=1.0)
    lines = (tmp_path / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    assert json.loads(lines[0])["rtt_ms"] == 1.0


def test_the_file_is_compacted_once_it_outgrows_the_window(tmp_path):
    """Without this the file grows without limit even though the in-memory window
    does not, so uptime alone would eventually fill the disk.
    """
    history = make(tmp_path, max_samples=5, compact_at=10)
    for index in range(30):
        history.record(rtt_ms=float(index))
    lines = (tmp_path / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) <= 11
    # And what survives is the newest window, not the oldest.
    assert json.loads(lines[-1])["rtt_ms"] == 29.0


def test_history_survives_a_restart(tmp_path):
    history = make(tmp_path, max_samples=100)
    history.record(rtt_ms=61.0, down_bps=1e6)
    history.record(rtt_ms=None, down=True)

    reloaded = make(tmp_path, max_samples=100)
    assert reloaded.load() == 2
    assert reloaded.series("rtt_ms") == [61.0, None]
    assert reloaded.latest()["down"] is True


def test_only_the_retained_window_is_loaded_back(tmp_path):
    history = make(tmp_path, max_samples=5, compact_at=1000)
    for index in range(40):
        history.record(rtt_ms=float(index))

    reloaded = make(tmp_path, max_samples=5)
    assert reloaded.load() == 5
    assert reloaded.series("rtt_ms") == [35.0, 36.0, 37.0, 38.0, 39.0]


def test_a_truncated_final_line_is_skipped_not_fatal(tmp_path):
    """Normal: the process was killed mid-append. Losing one sample is fine,
    refusing to start is not.
    """
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"at": "2026-08-04T12:00:00+00:00", "rtt_ms": 61.0}) + '\n{"at": "trunc',
        encoding="utf-8",
    )
    history = make(tmp_path, max_samples=10)
    assert history.load() == 1
    assert history.series("rtt_ms") == [61.0]


def test_a_non_utf8_byte_does_not_stop_startup(tmp_path):
    """`load()` runs inside `NetDnsMonitorApp.__init__`. UnicodeDecodeError is a
    ValueError, not an OSError, so one undecodable byte in a torn or hand-edited
    file escaped the OSError guard and the app never started under launchd.

    The bad byte sits in the JSON *syntax* so the replacement character leaves a
    line that cannot parse and is skipped like any torn line.
    """
    path = tmp_path / "history.jsonl"
    path.write_bytes(
        json.dumps({"at": "2026-08-04T12:00:00+00:00", "rtt_ms": 61.0}).encode()
        + b"\n"
        + b'{"at": "2026-08-04T12:00:05+00:00", \xff"rtt_ms": 62.0}\n'
    )
    history = make(tmp_path, max_samples=10)
    assert history.load() == 1
    assert history.series("rtt_ms") == [61.0]


def test_a_non_finite_value_on_disk_is_a_gap_not_a_point(tmp_path):
    """`float("Infinity")` passes the coercion, and one infinite point flattens
    every other value in the graph to the baseline.
    """
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"at": "2026-08-04T12:00:00+00:00", "rtt_ms": float("inf")}) + "\n",
        encoding="utf-8",
    )
    history = make(tmp_path)
    history.load()
    assert history.series("rtt_ms") == [None]


def test_the_compaction_bound_survives_a_restart(tmp_path):
    """The line count on disk is what triggers compaction. A fresh instance that
    started counting from zero would let the file grow to `compact_at` lines
    beyond whatever the previous run left behind, once per restart.
    """
    history = make(tmp_path, max_samples=5, compact_at=10)
    for index in range(10):
        history.record(rtt_ms=float(index))

    reloaded = make(tmp_path, max_samples=5, compact_at=10)
    reloaded.load()
    reloaded.record(rtt_ms=99.0)
    lines = (tmp_path / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 5
    assert json.loads(lines[-1])["rtt_ms"] == 99.0


def test_a_failed_compaction_keeps_the_window_and_the_appended_lines(tmp_path):
    """Compaction is a rewrite, and a rewrite that fails must cost nothing: the
    in-memory window is untouched and every appended line is still on disk.
    """

    def boom(path, text):
        raise OSError("disk full")

    history = SampleHistory(
        path=str(tmp_path / "history.jsonl"),
        max_samples=5,
        compact_at=10,
        clock=Clock(),
        writer=boom,
    )
    for index in range(12):
        history.record(rtt_ms=float(index))
    assert len(history.samples) == 5
    lines = (tmp_path / "history.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 12


def test_a_hand_edited_string_value_cannot_reach_a_draw_call(tmp_path):
    """The file is plain JSONL and editable. A string where a float is expected
    would raise inside drawing code, i.e. inside an AppKit callback where the
    traceback is invisible.
    """
    path = tmp_path / "history.jsonl"
    path.write_text(
        json.dumps({"at": "2026-08-04T12:00:00+00:00", "rtt_ms": "sixty one"}) + "\n",
        encoding="utf-8",
    )
    history = make(tmp_path)
    history.load()
    assert history.series("rtt_ms") == [None]


def test_a_line_without_a_timestamp_is_ignored(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text(json.dumps({"rtt_ms": 1.0}) + "\n", encoding="utf-8")
    history = make(tmp_path)
    assert history.load() == 0


def test_a_missing_file_loads_nothing_and_does_not_raise(tmp_path):
    assert make(tmp_path).load() == 0


def test_an_unwritable_path_degrades_to_no_history(tmp_path):
    """Called every 5 seconds. A full disk must not be what kills the monitor."""
    blocker = tmp_path / "blocker"
    blocker.write_text("I am a file", encoding="utf-8")
    history = SampleHistory(path=str(blocker / "sub" / "history.jsonl"), clock=Clock())
    history.record(rtt_ms=61.0)
    assert len(history.samples) == 1  # in-memory still works


def test_no_path_means_memory_only(tmp_path):
    history = SampleHistory(path=None, clock=Clock())
    history.record(rtt_ms=61.0)
    assert len(history.samples) == 1
    # No file anywhere under tmp_path. (Not "tmp_path is empty" -- conftest's
    # isolate_home fixture has already created a `home` directory in it.)
    assert not list(Path(tmp_path).rglob("*.jsonl"))


def test_a_zero_window_is_clamped_rather_than_crashing():
    """deque(maxlen=0) silently discards everything, so the graph would always be
    empty with no indication why.
    """
    history = SampleHistory(path=None, max_samples=0, clock=Clock())
    history.record(rtt_ms=61.0)
    assert len(history.samples) == 1
