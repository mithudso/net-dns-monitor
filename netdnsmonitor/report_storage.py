"""Persist an incident report (report.py) to disk as both JSON (for tooling)
and Markdown (for a human to open and hand to IT) -- the automatic-save step
that produces the artifact IT needs without anyone re-running diagnostics.
"""

import json
import os

from netdnsmonitor.report import render_markdown


def save_report(report: dict, directory: str) -> dict:
    os.makedirs(directory, exist_ok=True)
    timestamp = report["started_at"].replace(":", "-")
    json_path = os.path.join(directory, f"{timestamp}.json")
    markdown_path = os.path.join(directory, f"{timestamp}.md")

    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    with open(markdown_path, "w") as f:
        f.write(render_markdown(report))

    return {"json_path": json_path, "markdown_path": markdown_path}
