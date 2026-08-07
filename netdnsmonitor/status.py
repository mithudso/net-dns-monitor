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


def build_status_report(
    flap_state: str,
    last_classification: Optional[str] = None,
    last_report_path: Optional[str] = None,
    last_tick_error: Optional[str] = None,
    poll_interval_seconds: Optional[float] = None,
    domains: Optional[list] = None,
) -> str:
    """What `:status` prints in the console: the monitor's own view of itself.

    Pure and here rather than in the console because it is the same question the
    menu bar title answers, only at more length -- and because a console that
    reached into the running app to format its state would put a decision in the
    one file the suite cannot reach.

    `last_tick_error` is included deliberately. The tick guard in `app.py`
    swallows exceptions so that one bad tick cannot kill monitoring for the
    session, which means a persistently failing probe is otherwise invisible
    behind a title that just says "check failed".
    """
    lines = [f"state:          {flap_state}"]
    if flap_state != "healthy":
        lines.append(f"classification: {last_classification or 'unknown'}")
    if poll_interval_seconds is not None:
        lines.append(f"poll interval:  {poll_interval_seconds:g}s")
    if domains is not None:
        listed = ", ".join(domains) if domains else "(none)"
        lines.append(f"domains ({len(domains)}):   {listed}")
    lines.append(f"last report:    {last_report_path or '(none this session)'}")
    if last_tick_error:
        lines.append(f"last tick error: {last_tick_error}")
    return "\n".join(lines)
