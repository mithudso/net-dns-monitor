"""A bounded rolling history of heartbeat samples, so the graphs have something
to draw and survive a restart.

Only ever touched from the main thread -- the ping drain records, the window
reads -- which is the same discipline `ping_stats` follows and the reason there
is no lock here. Anything calling `record` from a worker would need one.

**Persistence is append-then-compact, not rewrite-per-sample.** At a 5-second
cadence a full rewrite would be ~17,000 rewrites of the whole file per day. So
each sample is one appended JSONL line, and the file is rewritten only when it
has grown past `compact_at` lines -- at which point it is replaced with just the
retained window. That keeps the steady-state cost at one short append per tick
and bounds the file regardless of uptime.

Gaps matter as much as values. A failed ping records `rtt_ms: None` rather than
being skipped, so an outage is a visible hole in the latency graph instead of a
straight line drawn across it as though nothing happened.
"""

import json
import math
import os
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.report_storage import _atomic_write

# 720 samples at the default 5s cadence is the last hour.
DEFAULT_MAX_SAMPLES = 720

FIELDS = ("rtt_ms", "loss_pct", "down_bps", "up_bps")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SampleHistory:
    def __init__(
        self,
        path: Optional[str] = None,
        max_samples: int = DEFAULT_MAX_SAMPLES,
        clock: Callable[[], datetime] = _utc_now,
        compact_at: Optional[int] = None,
        writer: Callable[[str, str], None] = _atomic_write,
    ):
        self.path = path
        self.max_samples = max(1, int(max_samples or 1))
        self.clock = clock
        self._write = writer
        # Compact at twice the window by default: the file never holds more than
        # two windows' worth, and a compaction happens once per window rather
        # than once per sample.
        self.compact_at = compact_at or self.max_samples * 2
        self.samples: deque = deque(maxlen=self.max_samples)
        self._lines_on_disk = 0

    # --- recording ---------------------------------------------------------

    def record(
        self,
        rtt_ms: Optional[float] = None,
        loss_pct: Optional[float] = None,
        down_bps: Optional[float] = None,
        up_bps: Optional[float] = None,
        down: bool = False,
    ) -> dict:
        sample = {
            "at": self.clock().isoformat(),
            "rtt_ms": rtt_ms,
            "loss_pct": loss_pct,
            "down_bps": down_bps,
            "up_bps": up_bps,
            "down": bool(down),
        }
        self.samples.append(sample)
        self._persist(sample)
        return sample

    def series(self, field: str) -> list:
        """One value per retained sample, `None` where it was not measured.

        Callers must keep the None entries: they are what makes an outage a gap
        in the graph rather than an interpolated line through it.
        """
        return [sample.get(field) for sample in self.samples]

    def latest(self) -> Optional[dict]:
        return self.samples[-1] if self.samples else None

    def span_seconds(self) -> Optional[float]:
        if len(self.samples) < 2:
            return None
        try:
            first = datetime.fromisoformat(self.samples[0]["at"])
            last = datetime.fromisoformat(self.samples[-1]["at"])
        except (KeyError, ValueError, TypeError):
            return None
        return (last - first).total_seconds()

    # --- persistence -------------------------------------------------------

    def _persist(self, sample: dict) -> None:
        if not self.path:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(sample) + "\n")
            self._lines_on_disk += 1
            if self._lines_on_disk > self.compact_at:
                self._compact()
        except OSError:
            # This runs every 5 seconds forever. A full disk must degrade to "no
            # graph history" rather than taking the monitor down, and it is
            # deliberately not logged -- at this cadence it would bury the alert
            # lines it shares a log with.
            pass

    def _compact(self) -> None:
        try:
            self._write(self.path, "".join(json.dumps(s) + "\n" for s in self.samples))
            self._lines_on_disk = len(self.samples)
        except OSError:
            # The append already succeeded and the write is atomic, so a failed
            # compaction costs nothing but disk; the next append retries it.
            pass

    def load(self) -> int:
        """Read the tail of a previous run's file. Returns how many were loaded.

        Never raises: a truncated final line from a process killed mid-append is
        normal, and a hand-edited file must not stop the app from starting.
        """
        if not self.path or not os.path.isfile(self.path):
            return 0
        loaded = 0
        try:
            # errors="replace": UnicodeDecodeError is a ValueError, not an
            # OSError, and this runs inside NetDnsMonitorApp.__init__ -- one
            # undecodable byte in a torn file must not stop the app starting.
            with open(self.path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return 0

        self._lines_on_disk = len(lines)
        # Only the retained window is worth parsing; a long-lived file can hold
        # twice that before compaction.
        for line in lines[-self.max_samples :]:
            line = line.strip()
            if not line:
                continue
            try:
                sample = json.loads(line)
            except ValueError:
                continue  # a partial final line from a killed process
            if isinstance(sample, dict) and "at" in sample:
                self.samples.append(_coerce(sample))
                loaded += 1
        if loaded:
            # The graphs draw by index, not by timestamp, so the previous run's
            # last sample and this run's first would be adjacent points and the
            # time the app was not running would render as a continuous line.
            # One all-None sample makes that downtime a gap. It is not appended to
            # the file here; a later compaction keeps it, which is still true.
            self.samples.append(_coerce({"at": self.clock().isoformat()}))
        return loaded


def _coerce(sample: dict) -> dict:
    """Force the shape the graphs expect, whatever was on disk.

    The file is plain JSONL and hand-editable, and a string where a float is
    expected would raise inside a draw call -- i.e. inside an AppKit callback,
    where the traceback is invisible.
    """
    # `down` stays None when it was never recorded -- the restart gap marker, or a
    # hand-edited line -- because nothing was probed and "not down" is a claim.
    down = sample.get("down")
    out = {"at": str(sample.get("at", "")), "down": None if down is None else bool(down)}
    for field in FIELDS:
        value = sample.get(field)
        try:
            number = None if value is None else float(value)
        except (TypeError, ValueError):
            number = None
        # json.loads accepts Infinity and NaN. One infinite point flattens every
        # other value in the graph to the baseline, so it is a gap, not a point.
        out[field] = number if number is not None and math.isfinite(number) else None
    return out
