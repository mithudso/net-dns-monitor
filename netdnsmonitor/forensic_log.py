"""Forensic record of every network down/up episode: what happened, what the
app did about it, why it did it, and what came back.

**What counts as one episode.** This app has two detectors on different clocks
and neither one alone can answer the question:

  the ping heartbeat (5s)   notices an outage within seconds, but takes no
                            remedial action at all -- so on its own, "steps
                            taken" would always be empty.
  the anti-flap gate (30s)  runs the whole ladder and escalates, but only
                            after debounce -- so on its own, any outage
                            shorter than ~60s produces no record whatsoever.

So an episode opens on the first "down" signal from *either* detector and stays
open until pings are answered again. The heartbeat supplies the timing, the gate
supplies the actions, and one document covers both. A gate incident that starts
while the heartbeat is already down joins the open episode rather than starting
a second one.

**Why the journal is append-only and separate from the summary.** Every event is
appended to a JSONL journal the moment it happens. The summary document is
written when the episode closes. An app that is killed, crashes, or loses power
mid-outage therefore still leaves the evidence behind -- which is the one case a
forensic log exists for. A design that buffered everything in memory until
recovery would lose exactly the outages worth investigating.

**Wall clock, not monotonic.** The heartbeat's internal arithmetic uses
`time.monotonic()` because it needs a clock that cannot jump; feeding those
values in here would produce timestamps like `847293.44`. This takes an injected
`clock` returning timezone-aware datetimes, matching report.py.

Episode documents go through report_storage._atomic_write, which carries this
project's two hard-won lessons: explicit UTF-8 (launchd sets no LANG, so the
process encoding is ASCII and any curly quote raises) and write-to-temp then
os.replace (so a failed write cannot truncate an existing record). The journal
is a plain UTF-8 append: an append cannot truncate what is already there, and
the worst a crash mid-write leaves is one torn last line.
"""

import json
import os
import traceback
from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.report_storage import _atomic_write

# Event kinds. Deliberately a small closed vocabulary: the summary renderer
# groups by these, and a typo'd kind would silently vanish from the document.
DOWN = "down"
UP = "up"
STEP = "step"
OBSERVATION = "observation"
RECHECK = "recheck"
ESCALATION = "escalation"

# Observations arrive every heartbeat for the length of the outage: a 490s
# outage produced 2,583 of them and a 937 KB markdown file. The journal keeps
# every one; the document keeps this many and says how many more there were.
MAX_OBSERVATIONS_PER_EPISODE = 500


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ForensicRecorder:
    """Records one open episode at a time and writes it out on recovery."""

    def __init__(
        self,
        journal_path: str,
        episodes_dir: str,
        clock: Callable[[], datetime] = _utc_now,
        writer: Callable[[str, str], None] = _atomic_write,
    ):
        self.journal_path = journal_path
        self.episodes_dir = episodes_dir
        self.clock = clock
        self.writer = writer
        self._episode: Optional[dict] = None
        self._observations_included = 0

    @property
    def is_open(self) -> bool:
        return self._episode is not None

    @property
    def episode(self) -> Optional[dict]:
        return self._episode

    # --- recording ---------------------------------------------------------

    def note(
        self,
        kind: str,
        detector: str,
        reason: str = "",
        detail: str = "",
        result: str = "",
    ) -> Optional[dict]:
        """Record one event. Returns the written paths when this closes an
        episode, otherwise None.

        Never raises: this is called from the heartbeat's drain and from the
        incident pipeline, and losing the network is not a reason to also lose
        the monitor.
        """
        event = {
            "at": self.clock().isoformat(),
            "kind": kind,
            "detector": detector,
            "reason": reason,
            "detail": detail,
            "result": result,
        }

        if kind == DOWN and self._episode is None:
            self._episode = {
                "started_at": event["at"],
                "trigger_detector": detector,
                "trigger_reason": reason,
                "events": [],
                "observations_not_included": 0,
            }
            self._observations_included = 0

        if self._episode is not None:
            event["episode_started_at"] = self._episode["started_at"]
            if kind == OBSERVATION and self._observations_included >= MAX_OBSERVATIONS_PER_EPISODE:
                # Still journaled below, still attributed to the episode; only
                # the document stops growing.
                self._episode["observations_not_included"] += 1
            else:
                self._episode["events"].append(event)
                if kind == OBSERVATION:
                    self._observations_included += 1

        self._append_journal(event)

        if kind == UP and self._episode is not None:
            return self._close(event)
        return None

    def _close(self, up_event: dict) -> Optional[dict]:
        episode = self._episode
        # Cleared before writing, so a failing write cannot leave an episode
        # wedged open and swallow every later outage.
        self._episode = None
        episode["ended_at"] = up_event["at"]
        episode["recovered_detector"] = up_event["detector"]
        episode["duration_seconds"] = _duration_seconds(episode["started_at"], episode["ended_at"])
        return self._write_episode(episode)

    # --- persistence -------------------------------------------------------

    def _append_journal(self, event: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self.journal_path) or ".", exist_ok=True)
            with open(self.journal_path, "a", encoding="utf-8") as f:
                # default=str: a caller passing bytes (raw command output) must
                # cost a lossy value, not a TypeError out of note().
                f.write(json.dumps(event, default=str) + "\n")
        except OSError:
            # An unwritable journal must not take the monitor down. Deliberately
            # not printed: this would be called every 5 seconds during an
            # outage on a full disk and would bury the alert lines in the log.
            pass

    def _write_episode(self, episode: dict) -> Optional[dict]:
        try:
            os.makedirs(self.episodes_dir, exist_ok=True)
            stamp = episode["started_at"].replace(":", "-")
            json_path = os.path.join(self.episodes_dir, f"{stamp}-episode.json")
            markdown_path = os.path.join(self.episodes_dir, f"{stamp}-episode.md")
            self.writer(json_path, json.dumps(episode, indent=2, default=str))
            self.writer(markdown_path, render_episode_markdown(episode))
            return {"json_path": json_path, "markdown_path": markdown_path}
        except Exception:  # noqa: BLE001 - note() promises never to raise
            # Broader than OSError on purpose. This runs from the heartbeat
            # drain and the incident pipeline; a rendering bug must cost the
            # document, not the monitor (serialisation itself cannot raise --
            # both dumps use default=str). The episode has already been
            # cleared, so the next outage still records. The trace is printed
            # because the document is the deliverable: an episode that silently
            # never appeared is a hole nobody can explain later.
            traceback.print_exc()
            return None


def _duration_seconds(started_at: str, ended_at: str) -> Optional[float]:
    try:
        return (
            datetime.fromisoformat(ended_at) - datetime.fromisoformat(started_at)
        ).total_seconds()
    except ValueError:
        # None renders as "unknown"; 0.0 would claim an instant recovery.
        return None


KIND_HEADINGS = {
    DOWN: "Detected down",
    UP: "Recovered",
    STEP: "Step",
    OBSERVATION: "Observation",
    RECHECK: "Recheck",
    ESCALATION: "Escalation",
}


def render_episode_markdown(episode: dict) -> str:
    """Human-readable episode summary -- the artifact someone actually reads.

    Ordered as a timeline rather than grouped by kind, because the question
    being asked of this document is "what happened, in what order, and did it
    help".
    """
    lines = [
        f"# Network down/up episode -- {episode.get('started_at', 'unknown')}",
        "",
        f"- **Down at:** {episode.get('started_at', 'unknown')}",
        f"- **Back up at:** {episode.get('ended_at', 'still down')}",
        f"- **Down for:** {_format_duration(episode.get('duration_seconds'))}",
        f"- **First noticed by:** {episode.get('trigger_detector', 'unknown')}",
        f"- **Why that counted as down:** {episode.get('trigger_reason') or 'not recorded'}",
        f"- **Recovery noticed by:** {episode.get('recovered_detector', 'not recorded')}",
        "",
        "## Timeline",
        "",
    ]

    events = episode.get("events") or []
    steps = [e for e in events if e.get("kind") == STEP]

    for event in events:
        heading = KIND_HEADINGS.get(event.get("kind", ""), event.get("kind", "Event"))
        lines.append(f"### {event.get('at', '?')} -- {heading}")
        lines.append("")
        lines.append(f"- **Detector:** {event.get('detector') or 'n/a'}")
        if event.get("detail"):
            lines.append(f"- **What:** {event['detail']}")
        lines.append(f"- **Why:** {event.get('reason') or 'not recorded'}")
        lines.append(f"- **Result:** {event.get('result') or 'no result recorded'}")
        lines.append("")

    not_included = episode.get("observations_not_included") or 0
    if not_included:
        lines.append(
            f"{not_included} further observations were journaled in the forensic "
            "journal but not included here."
        )
        lines.append("")

    lines.append("## Steps taken")
    lines.append("")
    if steps:
        lines.append("| Step | Kind | Why it was run | Result |")
        lines.append("| --- | --- | --- | --- |")
        for step in steps:
            lines.append(
                f"| {step.get('detail') or '?'} "
                f"| {step.get('detector') or '?'} "
                f"| {_cell(step.get('reason'))} "
                f"| {_cell(step.get('result'))} |"
            )
    else:
        lines.append(
            "No remedial step ran. The outage cleared before the anti-flap gate "
            "declared an incident, so the troubleshooting ladder never started -- "
            "the recovery was the network's own, not this app's."
        )
    lines.append("")
    return "\n".join(lines)


def _cell(value: Optional[str]) -> str:
    """Flatten a value for a Markdown table cell.

    Ladder outcomes are multi-line command output (`scutil --nwi` is a dozen
    lines), and a raw newline or pipe inside a cell breaks the table for every
    row after it.
    """
    if not value:
        return "not recorded"
    return value.replace("|", "\\|").replace("\n", " / ").strip()


def _format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 0:
        # Wall clock on purpose (see the module docstring), and wall clocks get
        # stepped. "-70s" reads as a rendering bug; say what happened instead.
        return (
            f"unknown (recovery stamped {abs(seconds):.0f}s before the outage "
            "began -- the wall clock moved)"
        )
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"
