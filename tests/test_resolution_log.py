import json
from datetime import datetime, timezone

from netdnsmonitor.resolution_log import append_resolution_findings
from netdnsmonitor.stall_log import select_stalled_domains


def _findings():
    # Shape must match what resolution_prober.resolve_domains_parallel actually
    # emits -- every finding it returns carries `outcome`, so a fixture without
    # it models a record the only producer cannot produce.
    return [
        {
            "domain": "a.example",
            "resolved": True,
            "error": None,
            "elapsed_seconds": 0.01,
            "outcome": "completed",
        },
        {
            "domain": "b.example",
            "resolved": False,
            "error": "timed out",
            "elapsed_seconds": 2.0,
            "outcome": "completed",
        },
    ]


def test_appends_one_jsonl_line_per_finding(tmp_path):
    path = tmp_path / "resolution-log.jsonl"
    append_resolution_findings(
        _findings(), str(path), checked_at=datetime(2026, 7, 20, 9, 0, tzinfo=timezone.utc)
    )
    lines = path.read_text().splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert record["domain"] == "a.example"
    assert record["resolved"] is True
    assert record["checked_at"] == "2026-07-20T09:00:00+00:00"


def test_appends_to_existing_file_without_truncating(tmp_path):
    path = tmp_path / "resolution-log.jsonl"
    append_resolution_findings(_findings()[:1], str(path))
    append_resolution_findings(_findings()[1:], str(path))
    lines = path.read_text().splitlines()
    assert len(lines) == 2


def test_creates_parent_directory_if_missing(tmp_path):
    path = tmp_path / "nested" / "dir" / "resolution-log.jsonl"
    append_resolution_findings(_findings(), str(path))
    assert path.exists()


def test_no_op_for_empty_findings(tmp_path):
    path = tmp_path / "resolution-log.jsonl"
    append_resolution_findings([], str(path))
    assert not path.exists()


def test_every_field_the_reader_depends_on_survives_the_round_trip(tmp_path):
    """stall_log.select_stalled_domains reads these records back: it needs
    `elapsed_seconds` to decide what counts as a stall and `outcome` to drop
    abandoned lookups. Nothing asserted the writer preserves them, so a writer
    that dropped either would break stall detection silently -- dropping
    `outcome` makes deadline-abandoned lookups count as stall evidence, which
    is exactly the runaway feedback loop stall_log exists to avoid.
    """
    path = tmp_path / "resolution-log.jsonl"
    finding = {
        "domain": "queued.example",
        "resolved": False,
        "error": "batch deadline exceeded before this lookup finished",
        "elapsed_seconds": 240.0,
        "outcome": "abandoned",
    }
    append_resolution_findings(
        [finding], str(path), checked_at=datetime(2026, 7, 20, 9, 0, tzinfo=timezone.utc)
    )
    record = json.loads(path.read_text().splitlines()[0])
    assert record == dict(finding, checked_at="2026-07-20T09:00:00+00:00")


def test_the_log_is_compacted_past_the_line_threshold_without_changing_what_the_reader_sees(
    tmp_path,
):
    """Append-only at ~3.9 MB/day, re-parsed in full every cycle. The compacted
    file keeps exactly the two aggregates `stall_log` computes -- per domain,
    the completed record with the largest `elapsed_seconds` (so "ever stalled"
    stays true) carrying the newest completed `checked_at` (so the rotation
    order is unchanged) -- and drops abandoned records, which the reader
    ignores anyway.
    """
    path = tmp_path / "resolution-log.jsonl"
    first = datetime(2026, 7, 20, 9, 0, tzinfo=timezone.utc)
    second = datetime(2026, 7, 20, 10, 0, tzinfo=timezone.utc)

    def finding(domain, elapsed, outcome="completed"):
        return {
            "domain": domain,
            "resolved": True,
            "error": None,
            "elapsed_seconds": elapsed,
            "outcome": outcome,
        }

    append_resolution_findings(
        [finding("a.example", 5.0), finding("b.example", 0.01)],
        str(path),
        checked_at=first,
        compact_at=3,
    )
    assert len(path.read_text().splitlines()) == 2
    before = select_stalled_domains(str(path), stall_seconds=1.0)

    append_resolution_findings(
        [finding("a.example", 0.02), finding("b.example", 240.0, outcome="abandoned")],
        str(path),
        checked_at=second,
        compact_at=3,
    )

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    records = {r["domain"]: r for r in map(json.loads, lines)}
    assert records["a.example"]["elapsed_seconds"] == 5.0
    assert records["a.example"]["checked_at"] == second.isoformat()
    assert records["b.example"]["elapsed_seconds"] == 0.01
    # An abandonment is not a check, so b's timestamp did not advance.
    assert records["b.example"]["checked_at"] == first.isoformat()
    assert select_stalled_domains(str(path), stall_seconds=1.0) == before == ["a.example"]


def test_one_checked_at_is_shared_by_every_record_in_a_batch(tmp_path):
    """Load-bearing, not an optimization: stall_log's
    least-recently-checked-first ordering is defined against a per-batch
    timestamp. Stamping per record would give a deadline-truncated cycle a
    different timestamp than the completions in the same cycle.
    """
    path = tmp_path / "resolution-log.jsonl"
    append_resolution_findings(_findings(), str(path))
    stamps = {json.loads(line)["checked_at"] for line in path.read_text().splitlines()}
    assert len(stamps) == 1
