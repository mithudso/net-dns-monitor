"""Build a self-contained incident report: a machine-readable dict and a
human-readable Markdown rendering, suitable for handing to IT without them
having to re-run any diagnostics themselves.
"""

import json
from datetime import datetime
from typing import Optional

from netdnsmonitor.classifier import Classification


def build_report(
    *,
    started_at: datetime,
    ended_at: datetime,
    classification: Classification,
    probe_results: dict,
    log_excerpts: list[str],
    ladder_results: list[dict],
    repair_outcome: Optional[str],
    recheck_ok: bool,
    escalation: Optional[dict],
) -> dict:
    resolved = bool(recheck_ok)
    resolution_word = "resolved" if resolved else "unresolved"
    # An empty ladder is real, not hypothetical: ladder_for returns [] for
    # UNCLASSIFIED, and a summary saying a ladder ran would describe steps
    # that never happened to the person reading the report.
    ladder_clause = (
        " after the offline troubleshooting ladder ran"
        if ladder_results
        else "; no offline troubleshooting ladder steps ran"
    )
    summary = (
        f"{classification.value.upper()}-layer incident detected at "
        f"{started_at.isoformat()}, {resolution_word}{ladder_clause}."
    )
    return {
        "started_at": started_at.isoformat(),
        "ended_at": ended_at.isoformat(),
        "duration_seconds": (ended_at - started_at).total_seconds(),
        "classification": classification.value,
        "probe_results": probe_results,
        "log_excerpts": list(log_excerpts),
        "ladder_results": list(ladder_results),
        "repair_outcome": repair_outcome,
        "recheck_ok": recheck_ok,
        "resolved": resolved,
        "escalation": escalation,
        "summary": summary,
    }


def _fenced(text: str) -> list[str]:
    # Four backticks, because the escalation analysis is model output and may
    # itself contain a three-backtick fence.
    return ["````", text, "````"]


def _pretty(value: object) -> str:
    try:
        return json.dumps(value, indent=2, default=str)
    except (TypeError, ValueError):
        return str(value)


def render_markdown(report: dict) -> str:
    lines = [
        "# Network/DNS Incident Report",
        "",
        f"**Started:** {report['started_at']}",
        f"**Duration:** {report['duration_seconds']:.0f}s",
        f"**Resolved:** {report['resolved']}",
        "",
        "## Classification",
        report["classification"],
        "",
        "## Summary",
        report["summary"],
        "",
        "## Probe Results",
        *_fenced(_pretty(report["probe_results"])),
        "",
        "## Ladder Steps",
    ]
    # One heading per step with the outcome fenced: `scutil --dns` and
    # `netstat -rn` are multi-line, and a dict repr collapses them into `\n`
    # escapes in the one document meant to let IT read that output.
    for step in report["ladder_results"]:
        name = step.get("name", "?")
        kind = step.get("kind")
        lines += ["", f"### {name} ({kind})" if kind else f"### {name}"]
        if step.get("reason"):
            lines.append(f"_{step['reason']}_")
        lines += _fenced(str(step.get("outcome")))
    lines += [
        "",
        "## Log Excerpts",
    ]
    for excerpt in report["log_excerpts"]:
        lines.append(f"- {excerpt}")
    lines += [
        "",
        "## Repair Outcome",
        *_fenced(str(report["repair_outcome"])),
        "",
        "## Escalation",
    ]
    escalation = report["escalation"]
    if isinstance(escalation, dict):
        for key, value in escalation.items():
            lines += [f"**{key}:**", *_fenced(str(value))]
    else:
        lines.append(str(escalation))
    return "\n".join(lines)
