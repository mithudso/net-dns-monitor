"""Append-mostly JSONL findings log for the periodic stalled-domain resolution
check -- every domain `stall_log.select_stalled_domains` picked out of this
same file. (It was the query log's top-N busiest domains until 5c647c4; that
selection, and `resolution_top_n` with it, is retired.) JSONL (not one big
JSON array) so a crash mid-write can't corrupt prior entries and so the file
can be tailed/grepped like any other log.

This is the writer half of a closed loop -- `stall_log` reads back what this
appends -- which is why one `checked_at` is stamped for the whole batch and
shared by every record in it. That shared timestamp is load-bearing, not an
optimization: the selector's least-recently-checked-first ordering is defined
against it, and stamping per record would give a deadline-truncated cycle a
different timestamp than the completions in the same cycle.

Compaction keeps the loop bounded. The reader re-parses the whole file every
cycle and the file grows ~3.9 MB a day, so once it passes `COMPACT_AT_LINES`
the writer rewrites it to one record per domain. What survives is exactly the
two aggregates the reader computes: the completed record with the largest
`elapsed_seconds` (so "ever stalled" stays true) carrying the newest completed
`checked_at` (so the rotation order is unchanged). Abandoned records are
dropped -- the reader ignores them, and they are not a check.
"""

import json
import math
import os
from datetime import datetime, timezone
from typing import Optional

from netdnsmonitor.report_storage import _atomic_write

COMPACT_AT_LINES = 50_000


def append_resolution_findings(
    findings: list[dict],
    path: str,
    checked_at: Optional[datetime] = None,
    compact_at: int = COMPACT_AT_LINES,
) -> None:
    if not findings:
        return
    checked_at = checked_at or datetime.now(timezone.utc)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # encoding pinned for the same reason report_storage pins it: under
    # launchd no LANG is set and the process locale encoding is ASCII, which
    # is how the .md half of incident reports came to be written as 0 bytes.
    # Nothing non-ASCII reaches this writer today (json.dumps defaults to
    # ensure_ascii=True), so this is defence in depth against an IDN domain
    # rather than a live bug -- but it is the same defect class, one keyword.
    with open(path, "a", encoding="utf-8") as f:
        for finding in findings:
            record = dict(finding)
            record["checked_at"] = checked_at.isoformat()
            f.write(json.dumps(record) + "\n")

    if _count_lines(path) > compact_at:
        _compact(path)


def _count_lines(path: str) -> int:
    count = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            count += chunk.count(b"\n")
    return count


def _compact(path: str) -> None:
    kept: dict[str, dict] = {}
    newest_checked: dict[str, str] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            domain = record.get("domain")
            if not domain or not isinstance(domain, str):
                continue
            if record.get("outcome") == "abandoned":
                continue
            checked_at = record.get("checked_at")
            if isinstance(checked_at, str):
                previous = newest_checked.get(domain)
                if previous is None or checked_at > previous:
                    newest_checked[domain] = checked_at
            current = kept.get(domain)
            if current is None or _elapsed(record) > _elapsed(current):
                kept[domain] = record

    lines = []
    for domain, record in kept.items():
        record = dict(record)
        if domain in newest_checked:
            record["checked_at"] = newest_checked[domain]
        lines.append(json.dumps(record) + "\n")
    # Atomic on purpose: a rewrite that dies mid-way must not leave a truncated
    # log behind, because a truncated log reads as "fewer domains ever stalled".
    _atomic_write(path, "".join(lines))


def _elapsed(record: dict) -> float:
    value = record.get("elapsed_seconds")
    # bool is an int subclass; the reader refuses it, so it must not win here.
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        elapsed = float(value)
        return -1.0 if math.isnan(elapsed) else elapsed
    return -1.0
