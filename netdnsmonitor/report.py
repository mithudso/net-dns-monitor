"""Build a self-contained incident report: a machine-readable dict and a
human-readable Markdown rendering, suitable for handing to IT without them
having to re-run any diagnostics themselves.
"""

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
        str(report["probe_results"]),
        "",
        "## Ladder Steps",
    ]
    for step in report["ladder_results"]:
        lines.append(f"- {step}")
    lines += [
        "",
        "## Log Excerpts",
    ]
    for excerpt in report["log_excerpts"]:
        lines.append(f"- {excerpt}")
    lines += [
        "",
        "## Repair Outcome",
        str(report["repair_outcome"]),
        "",
        "## Escalation",
        str(report["escalation"]),
    ]
    return "\n".join(lines)
