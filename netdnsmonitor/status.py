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
  an appended "N/total" suffix, independent of incident status, since an
  ever-stalled domain can stop resolving without external_reachable/dns_ok
  (checked against a single configured domain list) ever flipping.

The leading segment is live network statistics -- round-trip time to the ping
host, recent packet loss, and current throughput. It replaced a constant
signal-bars glyph that carried no information at all. The coloured circle after
it is still the part that changes with status, the way a badge overlays an icon
rather than replacing it. `status_state` is the single place the
healthy/flaky/incident decision is made; the menu bar title here, the Dock
tile in dock_icon.py, and the alert in alert.py all key off it, so the
indicators can't drift out of sync with each other.

A failing ping forces the incident state even while the anti-flap gate is still
healthy. The gate debounces a 30-second poll of TCP reachability and is
deliberately slow to react; the whole point of the 5-second heartbeat is to
react fast. The gate keeps owning what gets *repaired* and reported, this owns
what gets *shown*.
"""

from typing import Optional

ICONS = {"healthy": "\U0001f7e2", "flaky": "\U0001f7e1", "incident": "\U0001f534"}

# Deliberately digit-free. test_status pins that a title with no resolution
# failures contains no part of the resolution total, so a placeholder like
# "0ms" would turn that assertion into a landmine. It also shouldn't read as a
# real measurement, because it isn't one -- it covers the few seconds before
# the first ping comes back.
STATS_UNKNOWN = "--ms"

PING_DOWN_TEXT = "no reply"


def status_state(
    flap_state: str,
    consecutive_failures: int = 0,
    ping_down: bool = False,
) -> str:
    if flap_state == "incident" or ping_down:
        return "incident"
    if consecutive_failures > 0:
        return "flaky"
    return "healthy"


def format_rate(bits_per_second: Optional[float]) -> str:
    """A throughput figure short enough to sit in a menu bar."""
    if bits_per_second is None:
        return ""
    if bits_per_second >= 1e9:
        return f"{bits_per_second / 1e9:.1f}G"
    if bits_per_second >= 1e6:
        return f"{bits_per_second / 1e6:.1f}M"
    if bits_per_second >= 1e3:
        return f"{bits_per_second / 1e3:.0f}K"
    return "0"


def format_stats(
    rtt_ms: Optional[float] = None,
    loss_pct: Optional[float] = None,
    down_bps: Optional[float] = None,
    up_bps: Optional[float] = None,
    ping_down: bool = False,
) -> str:
    """The stats segment that replaced the signal-bars glyph.

    Loss is shown only when it is nonzero: menu bar width is the scarce
    resource here, and "0%" on a healthy network spends it saying nothing.
    """
    if ping_down:
        return PING_DOWN_TEXT

    parts = []
    if rtt_ms is not None:
        parts.append(f"{rtt_ms:.0f}ms")
    if loss_pct:
        parts.append(f"{loss_pct:.0f}%")
    if down_bps is not None or up_bps is not None:
        parts.append(f"{format_rate(down_bps)}↓{format_rate(up_bps)}↑")

    return " ".join(parts) if parts else STATS_UNKNOWN


def build_status_report(
    flap_state: str,
    last_classification: Optional[str] = None,
    consecutive_failures: int = 0,
    ping_down: bool = False,
    stats: Optional[str] = None,
    resolution_failed: Optional[int] = None,
    resolution_total: Optional[int] = None,
    last_report_path: Optional[str] = None,
    poll_interval_seconds: Optional[float] = None,
    domains: Optional[list] = None,
) -> str:
    """What the console's `:status` prints: the same question the menu bar
    title answers, at a length a title has no room for.

    Routed through `status_state` rather than re-reading `flap_state`, for the
    reason recorded at the top of this module: that function is the single place
    the healthy/flaky/incident decision is made, and a console that decided it
    again would be a fourth indicator free to disagree with the title, the Dock
    tile and the alert. A `:status` that says healthy under a red menu bar is
    worse than no `:status` at all.

    Lives here rather than in console.py because it is menu-bar logic, not
    console logic, and because a console reaching into the running app to format
    its state would put a decision in the one file the suite cannot reach.
    """
    state = status_state(flap_state, consecutive_failures, ping_down)

    lines = [
        f"state:          {state}",
        f"flap gate:      {flap_state}",
    ]
    # Shown only off-healthy: on a good network these are all zero or stale, and
    # a status pane that pads itself with "0 consecutive failures" trains the
    # reader to skim past the lines that do matter.
    if state != "healthy":
        lines.append(f"classification: {last_classification or 'unknown'}")
    if consecutive_failures:
        lines.append(f"consecutive failures: {consecutive_failures}")
    if ping_down:
        lines.append("ping:           no reply")
    if stats:
        lines.append(f"stats:          {stats}")
    if resolution_failed:
        lines.append(f"resolution:     {resolution_failed}/{resolution_total} failing")
    if poll_interval_seconds is not None:
        lines.append(f"poll interval:  {poll_interval_seconds:g}s")
    if domains is not None:
        listed = ", ".join(domains) if domains else "(none)"
        lines.append(f"domains ({len(domains)}):   {listed}")
    lines.append(f"last report:    {last_report_path or '(none this session)'}")
    return "\n".join(lines)


def build_title(
    flap_state: str,
    last_classification: Optional[str],
    consecutive_failures: int = 0,
    resolution_failed: Optional[int] = None,
    resolution_total: Optional[int] = None,
    stats: Optional[str] = None,
    ping_down: bool = False,
) -> str:
    state = status_state(flap_state, consecutive_failures, ping_down)
    prefix = stats or STATS_UNKNOWN

    if state == "incident":
        # A ping failure with a healthy gate labels itself a ping issue rather
        # than borrowing `last_classification`, which may still hold a stale
        # label from an unrelated incident hours ago.
        reason = (last_classification or "unknown") if flap_state == "incident" else "ping"
        title = f"{prefix} {ICONS['incident']} Net/DNS: {reason} issue"
    elif state == "flaky":
        title = f"{prefix} {ICONS['flaky']} Net/DNS: flaky"
    else:
        title = f"{prefix} {ICONS['healthy']} Net/DNS: healthy"

    if resolution_failed:
        title += f" | {resolution_failed}/{resolution_total} resolution fails"

    return title
