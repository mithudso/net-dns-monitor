import json
from datetime import datetime, timezone

from netdnsmonitor.resolution_log import append_resolution_findings


def _findings():
    return [
        {"domain": "a.example", "resolved": True, "error": None, "elapsed_seconds": 0.01},
        {"domain": "b.example", "resolved": False, "error": "timed out", "elapsed_seconds": 2.0},
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
