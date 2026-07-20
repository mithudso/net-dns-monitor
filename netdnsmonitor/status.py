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

Two small heuristics add an intermediate signal beyond the binary
healthy/incident split, both from data the app already computes:
- `consecutive_failures` (below `failure_threshold`, so no incident yet) ->
  a yellow "flaky" state -- an early warning before the anti-flap gate
  would otherwise stay silent.
- a nonzero failure count from the most recent resolution-monitor batch ->
  an appended "N/total" suffix, independent of incident status, since a
  top-queried domain can stop resolving without external_reachable/dns_ok
  (checked against a single configured domain list) ever flipping.
"""

from typing import Optional

ICONS = {"healthy": "\U0001F7E2", "flaky": "\U0001F7E1", "incident": "\U0001F534"}


def build_title(
    flap_state: str,
    last_classification: Optional[str],
    consecutive_failures: int = 0,
    resolution_failed: Optional[int] = None,
    resolution_total: Optional[int] = None,
) -> str:
    if flap_state == "incident":
        title = f"{ICONS['incident']} Net/DNS: {last_classification or 'unknown'} issue"
    elif consecutive_failures > 0:
        title = f"{ICONS['flaky']} Net/DNS: flaky"
    else:
        title = f"{ICONS['healthy']} Net/DNS: healthy"

    if resolution_failed:
        title += f" | {resolution_failed}/{resolution_total} resolution fails"

    return title
