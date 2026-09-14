"""Read the network-related parts of macOS's unified log, so the window can show
what the system itself is saying about the network instead of only what this app
measured.

`log_watcher.py` already shells out to `log show`, but for a different job: it
grabs a 5-minute excerpt to staple into an incident report, and it decides what
counts as interesting by scanning the text for any of six error-like substrings
("error", "fail", "timed out", "timeout", "unreachable", "refused"). That is fine
for an attachment and wrong for a live pane -- it re-runs the whole query every
time, keeps no history, and cannot answer "show me only the DNS lines".

Four measurements on the machine this was built for shaped everything here:

1. **`log show` cost is dominated by the window, not the predicate.** Timed with
   the error/fault predicate below: 1 minute took 1.4s, 5 minutes 1.6s,
   15 minutes 4.2s -- and 60 minutes took **16.9s**. So this polls a 1-minute
   window on a cadence and backfills 15 minutes once, rather than re-querying a
   long window. It also means `log_watcher.py`'s `timeout=10` is not a safe
   ceiling to copy: `LOG_TIMEOUT_SECONDS` is 45, and a timeout is reported as
   text rather than as an empty result, because an empty pane looks like a quiet
   network.

2. **Unfiltered network log volume is unusable.** A predicate matching
   `eventMessage CONTAINS "network"` returned 192,901 lines over 30 minutes.
   Restricting to error and fault message types over the same subsystems returned
   919 lines over 15 minutes. Errors-only is therefore the default. Asking for all
   levels is a deliberate button press, and what keeps it survivable is
   `LogBuffer`'s entry cap plus coalescing, not a smaller window -- the window
   stays the same so that the timestamps either side of the switch line up.

3. **What is left is still mostly one line repeated.** Of those, hundreds were a
   single CrowdStrike `nw_endpoint_get_address called with null endpoint` and a
   single WeatherMenu `quic_crypto_queue_append` line. `coalesce` coalesces
   identical messages into one row with a count, which matters more than a bigger
   buffer: it is what makes the genuinely interesting line -- `Socket SO_ERROR
   [51: Network is unreachable]` -- visible at all.

4. **Messages span lines.** A compact-style entry starts with a timestamp; the
   rest of a multi-line message follows on lines that do not. Splitting on "\\n"
   and treating every line as an entry produced ~14,000 header-less fragments in
   a 5-minute sample, so `parse_lines` folds continuations into the entry above.

Nothing here does I/O except the `reader` that `make_log_reader` returns, and its
`run_fn` is injected the way the rest of this project does it -- no test in the
suite runs `log`. Every free function is pure; `LogBuffer` is the one piece that
deliberately carries mutable state.

One thing this cannot fix: macOS redacts private data, so DNS queries arrive as
`qname: <mask.hash: '+ii6T0lMiN55NCEFRMdtqQ=='>` rather than a hostname. That is
a logging configuration profile, not a permission this app can request. See
`privileges.py`.
"""

import re
import subprocess
from collections.abc import Iterable
from typing import Callable, Optional

# Processes that carry network and DNS state. Matched on process name because
# many of them log under several subsystems.
NETWORK_PROCESSES = (
    "mDNSResponder",
    "configd",
    "symptomsd",
    "airportd",
    "networkd",
    "nesessionmanager",
    "socketfilterfw",
)

# Subsystems, for the much larger set of processes that log network trouble
# through Apple's frameworks -- this is where a browser's or a daemon's failed
# connection shows up, and it is where the useful lines were found.
NETWORK_SUBSYSTEM_PREFIXES = (
    "com.apple.network",
    "com.apple.mdns",
    "com.apple.mDNSResponder",
    "com.apple.SystemConfiguration",
    "com.apple.WiFiManager",
    "com.apple.symptomsd",
)

# OS_LOG_TYPE_ERROR and OS_LOG_TYPE_FAULT. Filtering in the predicate rather than
# on the text is what turns 192,901 lines into 919 (see the module docstring);
# `log`'s own filter runs inside the archive scan, a text filter cannot.
ERROR_MESSAGE_TYPES = (16, 17)

# 45s, not the 10s used elsewhere for `log show`: a 15-minute backfill measured
# 4.2s and the machine is not always idle. A query that does hit this is reported
# as a timeout, never as "no entries".
LOG_TIMEOUT_SECONDS = 45

# Lines that are always noise on this machine: high-frequency framework
# complaints from unrelated apps, matched as substrings. Coalescing already
# collapses each to one row, so this list is only for entries not worth a row at
# all. Overridable via the `log_view_noise_patterns` config key.
DEFAULT_NOISE_PATTERNS = (
    "nw_endpoint_get_address called with null endpoint",
    "nw_protocol_instance_set_output_handler",
    "quic_crypto_queue_append not enqueing more packets",
    "Too many groups requested",
)

# The two-character type column of `--style compact`. "E" and "F" are the ones
# the errors-only predicate can return; the rest appear once all levels are asked
# for.
TYPE_NAMES = {
    "Df": "default",
    "I": "info",
    "In": "info",
    "Db": "debug",
    "E": "error",
    "Er": "error",
    "F": "fault",
    "Fa": "fault",
    "A": "activity",
    "Ac": "activity",
    "T": "timesync",
}

ERROR_SEVERITIES = ("error", "fault")

# A new entry begins with `2026-08-04 12:48:56.386 `. Anything else continues the
# entry above it.
_ENTRY_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})\.(?P<micros>\d+)\s+"
    r"(?P<type>\S+)\s+(?P<rest>.*)$"
)

# `identityservicesd[762:ac80d] [com.apple.network:connection] nw_socket...`
_PROCESS_RE = re.compile(
    r"^(?P<process>[^\[\]]+)\[(?P<pid>\d+)(?::[0-9a-fA-Fx]+)?\]\s*(?P<rest>.*)$"
)

_SUBSYSTEM_RE = re.compile(r"^\[(?P<subsystem>[^\]\s]*)\]\s*(?P<rest>.*)$")

RunFn = Callable[..., object]


def build_predicate(errors_only: bool = True) -> str:
    """The NSPredicate handed to `log show`.

    Process names and subsystem prefixes are both listed: a subsystem catches
    another app's failed connection (`com.apple.network` under
    `identityservicesd`), a process name catches the daemons that log under
    several subsystems (`mDNSResponder`).
    """
    processes = ", ".join(f'"{name}"' for name in NETWORK_PROCESSES)
    subsystems = " OR ".join(
        f'subsystem BEGINSWITH "{prefix}"' for prefix in NETWORK_SUBSYSTEM_PREFIXES
    )
    scope = f"(process IN {{{processes}}} OR {subsystems})"
    if not errors_only:
        return scope
    levels = " OR ".join(f"messageType == {value}" for value in ERROR_MESSAGE_TYPES)
    return f"{scope} AND ({levels})"


def log_show_command(window: str, errors_only: bool = True) -> list[str]:
    """The argv, kept separate from the subprocess call so a test can assert on it
    without running anything.
    """
    return [
        "/usr/bin/log",
        "show",
        "--style",
        "compact",
        "--last",
        window,
        "--predicate",
        build_predicate(errors_only),
    ]


def parse_lines(lines: Iterable[str]) -> list[dict]:
    """Compact-style output -> entries, folding multi-line messages together.

    Returns dicts of timestamp/time/severity/process/subsystem/message/raw. A
    line before the first timestamp -- `log`'s own header row, or the "Filtering
    the log data using ..." notice -- is dropped rather than becoming an entry
    with no time.
    """
    entries: list[dict] = []
    for line in lines:
        match = _ENTRY_RE.match(line)
        if match is None:
            if entries and line.strip():
                entries[-1]["message"] += "\n" + line.rstrip()
                entries[-1]["raw"] += "\n" + line.rstrip()
            continue

        rest = match.group("rest")
        process = ""
        subsystem = ""
        process_match = _PROCESS_RE.match(rest)
        if process_match is not None:
            process = process_match.group("process").strip()
            rest = process_match.group("rest")
        subsystem_match = _SUBSYSTEM_RE.match(rest)
        if subsystem_match is not None:
            subsystem = subsystem_match.group("subsystem").strip()
            rest = subsystem_match.group("rest")

        type_token = match.group("type")
        entries.append(
            {
                "timestamp": f"{match.group('date')} {match.group('time')}.{match.group('micros')}",
                "time": match.group("time"),
                "severity": TYPE_NAMES.get(type_token, type_token.lower()),
                "process": process,
                "subsystem": subsystem,
                "message": rest.strip(),
                "raw": line.rstrip(),
            }
        )
    return entries


def is_error(entry: dict) -> bool:
    return entry.get("severity") in ERROR_SEVERITIES


def is_noise(entry: dict, patterns: Iterable[str] = DEFAULT_NOISE_PATTERNS) -> bool:
    message = entry.get("message", "")
    return any(pattern and pattern in message for pattern in patterns)


def _haystack(entry: dict) -> str:
    return " ".join(
        (
            entry.get("time", ""),
            entry.get("severity", ""),
            entry.get("process", ""),
            entry.get("subsystem", ""),
            entry.get("message", ""),
        )
    ).lower()


def matches(entry: dict, query: str) -> bool:
    """Whitespace-separated terms, all of which must appear; a term prefixed with
    `-` must not.

    Deliberately substring rather than regex: this is a search box in a log pane,
    and `[C134.1.1:3]` is the kind of thing someone pastes into it. A regex would
    make that an error instead of a search, and an unanchored user-supplied regex
    over thousands of entries every second is its own problem.
    """
    terms = (query or "").split()
    if not terms:
        return True
    haystack = _haystack(entry)
    for term in terms:
        if term.startswith("-") and len(term) > 1:
            if term[1:].lower() in haystack:
                return False
        elif term.lower() not in haystack:
            return False
    return True


def coalesce(entries: Iterable[dict]) -> list[dict]:
    """Collapse identical (process, message) pairs into one row carrying a count.

    Keyed on the message rather than on adjacency, because the repeats interleave
    -- CrowdStrike and WeatherMenu take turns. A burst of one message therefore
    cannot push everything else off the pane.

    **Assumes `entries` arrive oldest-first**, which is how `log show` emits them
    and how `LogBuffer` stores them. Given that, each row keeps its most recent
    occurrence's time and rows come out newest-first. Fed newest-first input it
    would silently do the opposite on both counts, so the ordering is a
    precondition rather than something this function establishes.
    """
    grouped: dict[tuple, dict] = {}
    for index, entry in enumerate(entries):
        key = (entry.get("process", ""), entry.get("message", ""))
        existing = grouped.get(key)
        if existing is None:
            row = dict(entry)
            row["count"] = 1
            row["_order"] = index
            grouped[key] = row
            continue
        existing["count"] += 1
        # Later entries arrive in log order, so the last one seen is the newest.
        existing["time"] = entry.get("time", existing.get("time", ""))
        existing["timestamp"] = entry.get("timestamp", existing.get("timestamp", ""))
        existing["_order"] = index
    rows = sorted(grouped.values(), key=lambda row: row["_order"], reverse=True)
    for row in rows:
        row.pop("_order", None)
    return rows


def format_entry(entry: dict) -> str:
    """One display line. Newlines inside a folded message are indented so the
    entry still reads as one item.
    """
    message = entry.get("message", "").replace("\n", "\n" + " " * 4)
    count = entry.get("count", 1)
    repeat = f"  (x{count})" if count > 1 else ""
    severity = entry.get("severity", "")
    flag = "!" if severity in ERROR_SEVERITIES else " "
    process = entry.get("process") or "?"
    return f"{entry.get('time', '')} {flag} {process}: {message}{repeat}"


def format_entries(entries: Iterable[dict], limit: Optional[int] = None) -> str:
    rows = list(entries)
    if limit is not None:
        rows = rows[:limit]
    if not rows:
        return ""
    return "\n".join(format_entry(row) for row in rows) + "\n"


def summarize(
    *,
    total: int,
    shown: int,
    errors: int,
    query: str,
    error: Optional[str],
    captured: int = 0,
) -> str:
    """The one-line status above the pane.

    Four states, all of which produce an empty pane and only some of which say
    anything about the network: the read failed, nothing was captured, everything
    captured was filtered out, or the search excluded it all.

    `captured` is the pre-filter count, and it exists to separate the middle two.
    `total` is post-filter, so on its own it reports a quarter-hour in which every
    captured error matched a noise pattern as "nothing captured yet" -- which is
    indistinguishable from a silent log, and the log was not silent.
    """
    if error:
        return error
    if total == 0:
        if captured:
            return f"{captured} entries captured, all filtered out by the noise/level filters."
        return "No network log entries captured yet."
    parts = [f"{total} entries", f"{errors} error/fault"]
    if query.strip():
        parts.append(
            f"{shown} match {query.strip()!r}" if shown else f"no match for {query.strip()!r}"
        )
    return "  |  ".join(parts)


class LogBuffer:
    """Bounded newest-last store of entries, with identity de-duplication.

    De-duplication is not optional: the poll window (1 minute) is deliberately
    longer than the poll interval (30 seconds) so that nothing is missed between
    runs, which means every entry arrives about twice. Keyed on
    (timestamp, process, message) -- the same message logged twice in the same
    microsecond by the same process is not worth distinguishing, so it is stored
    once.

    That is also what keeps `coalesce`'s counts honest, and the two are *not*
    interchangeable: coalesce turns two identical entries into one row reading
    `(x2)`, so without the de-duplication here every poll-overlap copy would
    inflate the count of an event that happened once.

    De-duplication survives eviction, which it did not at first. `_trim` discards evicted
    keys from `_seen`, so an entry pushed out of the buffer could be re-fetched by the next
    overlapping poll and stored again as new -- double-announced, double-counted, and
    duplicated in an open forensic episode. That needs the buffer to hold less than one poll
    overlap, which cannot happen at the errors-only default (~60 entries/min against a 3,000
    cap) but is reachable the moment "All levels" is pressed: roughly 6,000 entries a minute
    against a 30-second overlap is the cap exactly, and log arrival is bursty. A high-water
    mark of the newest evicted timestamp closes it without depending on capacity.
    """

    def __init__(self, max_entries: int = 3000):
        # 3000 at the observed error/fault volume (roughly 900 per 15 minutes on
        # the machine this was built for) is a bit under an hour of history --
        # enough to still see the start of an outage you noticed a few minutes
        # late, and a hard bound on a buffer nothing ever flushes to disk.
        self.max_entries = max_entries
        self._entries: list[dict] = []
        self._seen: set[tuple] = set()
        # Newest timestamp ever evicted. Anything at or below it has already been through
        # this buffer, so an overlapping poll re-fetching it is not news. `log show` emits
        # oldest-first and "YYYY-MM-DD HH:MM:SS.ffffff" sorts lexicographically, so a string
        # comparison is a time comparison here.
        self._evicted_through: str = ""

    @staticmethod
    def _key(entry: dict) -> tuple:
        return (entry.get("timestamp", ""), entry.get("process", ""), entry.get("message", ""))

    def add(self, entries: Iterable[dict]) -> list[dict]:
        """Store what has not been stored before, and return just that.

        The return value is what makes automatic reporting possible: the caller
        announces new error lines without having to diff the buffer itself.
        """
        batch = list(entries)
        # The timestamps are local wall-clock time, so the clock can step back: at
        # the end of daylight saving the 01:00 hour repeats, and every new line
        # compares below the mark from the first pass. A poll window runs up to
        # "now", so while the clock runs forward a batch holding any line older
        # than the mark also holds the line at the mark. A whole batch strictly
        # below the mark therefore means the clock stepped back, and the mark no
        # longer means "already seen". `_seen` still de-duplicates what the
        # buffer holds.
        if (
            batch
            and self._evicted_through
            and max(entry.get("timestamp", "") for entry in batch) < self._evicted_through
        ):
            self._evicted_through = ""
        added = []
        for entry in batch:
            if self._evicted_through and entry.get("timestamp", "") <= self._evicted_through:
                continue
            key = self._key(entry)
            if key in self._seen:
                continue
            self._seen.add(key)
            self._entries.append(entry)
            added.append(entry)
        self._trim()
        return added

    def _trim(self):
        overflow = len(self._entries) - self.max_entries
        if overflow <= 0:
            return
        for entry in self._entries[:overflow]:
            self._seen.discard(self._key(entry))
            stamp = entry.get("timestamp", "")
            if stamp > self._evicted_through:
                self._evicted_through = stamp
        del self._entries[:overflow]

    def entries(self) -> list[dict]:
        return list(self._entries)

    def error_count(self) -> int:
        return sum(1 for entry in self._entries if is_error(entry))

    def clear(self):
        self._entries.clear()
        self._seen.clear()
        # Emptying means "forget everything", including what was evicted -- otherwise
        # "Empty buffer" would silently refuse to re-accept the recent past.
        self._evicted_through = ""

    def view(
        self,
        *,
        query: str = "",
        errors_only: bool = False,
        noise_patterns: Iterable[str] = DEFAULT_NOISE_PATTERNS,
        limit: Optional[int] = None,
    ) -> dict:
        """What the pane should show, plus the numbers behind its status line.

        `errors_only` here filters what was captured, which is a different switch
        from the one in the predicate: the buffer can hold all levels while the
        pane shows only the errors, without another log query.
        """
        patterns = tuple(noise_patterns or ())
        kept = [entry for entry in self._entries if not is_noise(entry, patterns)]
        if errors_only:
            kept = [entry for entry in kept if is_error(entry)]
        matched = [entry for entry in kept if matches(entry, query)]
        rows = coalesce(matched)
        return {
            "text": format_entries(rows, limit=limit),
            "rows": rows,
            # Post-filter, which is what the pane draws from.
            "total": len(kept),
            "shown": len(matched),
            "errors": sum(1 for entry in kept if is_error(entry)),
            # Pre-filter. Without this the caller cannot tell "the log is quiet"
            # from "everything captured was suppressed"; see summarize.
            "captured": len(self._entries),
        }


def make_log_reader(
    run_fn: RunFn = subprocess.run,
    timeout: float = LOG_TIMEOUT_SECONDS,
):
    """Returns `reader(window, errors_only) -> {"entries": [...], "error": str|None}`.

    Never raises and never reports a failure as an empty result. An empty pane
    with no explanation reads as "the network is quiet", which is the opposite of
    what a timed-out or refused log query means.
    """

    def reader(window: str = "1m", errors_only: bool = True) -> dict:
        try:
            result = run_fn(
                log_show_command(window, errors_only),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {
                "entries": [],
                "error": (
                    f"Reading the system log took longer than {timeout:.0f}s and was "
                    f"given up on. A shorter window than {window} would help."
                ),
            }
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            return {"entries": [], "error": f"Could not read the system log: {exc}"}

        if getattr(result, "returncode", 1) != 0:
            detail = (getattr(result, "stderr", "") or "").strip().splitlines()
            return {
                "entries": [],
                "error": "`log show` failed: " + (detail[0] if detail else "no output"),
            }
        # getattr, like the two branches above: the docstring promises this never
        # raises, and a direct .stdout would break that promise for any run_fn
        # whose result object does not carry one.
        stdout = getattr(result, "stdout", "") or ""
        return {"entries": parse_lines(stdout.splitlines()), "error": None}

    return reader
