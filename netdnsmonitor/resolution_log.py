"""Append-only JSONL findings log for the periodic top-domain resolution
check. JSONL (not one big JSON array) so a crash mid-write can't corrupt
prior entries and so the file can be tailed/grepped like any other log.
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
    with open(path, "a") as f:
        for finding in findings:
            record = dict(finding)
            record["checked_at"] = checked_at.isoformat()
            f.write(json.dumps(record) + "\n")
