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
