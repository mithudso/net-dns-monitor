"""Append-only JSONL findings log for the periodic stalled-domain resolution
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
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional


def append_resolution_findings(
    findings: list[dict],
    path: str,
    checked_at: Optional[datetime] = None,
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
