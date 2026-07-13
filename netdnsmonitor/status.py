"""Pure menu-bar status logic, kept separate from the rumps.App shell so it's
testable without a real macOS event loop. The status only changes when a
report is produced (i.e. when the anti-flap gate declared and resolved/
escalated an incident) -- it holds steady on every tick in between.
"""

from typing import Optional

ICONS = {"healthy": "\U0001F7E2", "degraded": "\U0001F534"}


def next_status(current_status: str, report: Optional[dict]) -> str:
    if report is None:
        return current_status
    return "healthy" if report["resolved"] else "degraded"


def build_title(status: str, report: Optional[dict]) -> str:
    icon = ICONS.get(status, "⚪")
    if status == "healthy":
        return f"{icon} Net/DNS: healthy"
    classification = report["classification"] if report else "unknown"
    return f"{icon} Net/DNS: {classification} issue"
