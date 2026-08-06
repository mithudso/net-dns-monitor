"""Pure menu-bar title logic, kept separate from the rumps.App shell so it's
testable without a real macOS event loop.

Driven by the state machine's LIVE flap-gate state every tick, not by
whether a report was produced. A report only fires on the healthy->incident
edge (see state_machine.py) -- the incident->healthy recovery transition
produces no report at all, so a title driven off "last report" would get
stuck showing degraded forever after the network actually recovers. Reading
the gate's live state each tick means the title correctly flips back to
healthy once enough consecutive good probes accumulate, using the same
anti-flap hysteresis that declared the incident in the first place.
"""

from typing import Optional

ICONS = {"healthy": "\U0001F7E2", "incident": "\U0001F534"}


def build_title(flap_state: str, last_classification: Optional[str]) -> str:
    icon = ICONS.get(flap_state, "⚪")
    if flap_state == "healthy":
        return f"{icon} Net/DNS: healthy"
    return f"{icon} Net/DNS: {last_classification or 'unknown'} issue"


# Reachability is tri-state for the same reason it is everywhere else in this
# app: an absent adapter has not been probed, and saying "unreachable" about a
# cable that is simply unplugged sends someone looking for the wrong fault.
REACHABILITY = {True: "reachable", False: "unreachable", None: "not probed"}


def _describe_side(side: dict, label: str, is_active: bool) -> str:
    marker = "●" if is_active else "○"  # filled = carrying traffic
    if not side.get("found"):
        return f"{marker} {label}: {side['name']} — NOT FOUND in the service order"
    device = side.get("device") or "?"
    return (
        f"{marker} {label}: {side['name']} ({device}) — "
        f"{REACHABILITY.get(side.get('reachable'), 'unknown')}"
    )


def build_failover_lines(snapshot: Optional[dict]) -> list[str]:
    """The menu bar's failover indicator: three lines, always in the same
    order, so the answer to "which one am I on" is in a fixed place.

    Returns a single explanatory line instead when the feature is unconfigured
    or the service order could not be read -- an indicator that silently shows
    stale or invented state is worse than one that says it doesn't know.
    """
    if snapshot is None:
        return ["Failover: not configured (set both service names in config.yaml)"]
    if snapshot.get("error"):
        return [f"Failover: {snapshot['error']}"]

    mode = "automatic" if snapshot.get("auto_enabled") else "manual only"
    active_side = snapshot.get("active_side")
    return [
        f"Active: {snapshot.get('active_service')} — failover is {mode}",
        _describe_side(snapshot["preferred"], "Preferred", active_side == "preferred"),
        _describe_side(snapshot["backup"], "Backup", active_side == "backup"),
    ]
