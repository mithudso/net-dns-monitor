"""Select the domains to re-resolve from this machine's own resolution-log
history: every domain that has *ever stalled*, rather than the current top-N
busiest domains mined from the query log.

Why "stalled" means slow, not failed
------------------------------------
A record with `resolved: false` is usually an instant, definitive answer --
NXDOMAIN in ~70ms. On the observed log, 14,845 of 16,282 records were that
case, nearly all of them non-domains the query-log regex swept up (bundle IDs
like `com.apple.mDNSResponder`, truncated tokens like `com.code42.agen`).
Treating those as stalls would build a permanent 300-entry retry list of
things that are not domains and never resolve.

A stall is the other failure mode: the lookup *hung*. That shows up in
`elapsed_seconds`, not in `resolved` -- the observed log has a clear tail at
30s and 35s. So the selector keys on elapsed time crossing
`resolution_stall_seconds`, which admits both slow successes and slow
failures and excludes fast ones of either kind.

Abandoned records are not stall evidence
----------------------------------------
`resolution_prober` marks records it gave up on at the batch deadline with
`outcome: "abandoned"`. Those are excluded from stall detection on purpose.
An abandoned record means "the batch ran out of time", which can be caused by
queueing behind *other* slow domains rather than by this domain being slow.
Counting them would be a feedback loop: a long batch abandons domains, those
abandonments enlarge the stall list, the larger list makes batches longer.
Only a real measured elapsed time counts as a stall.

Ordering is least-recently-checked first
----------------------------------------
The stall list never shrinks -- the log is append-only and "ever stalled" is
permanent, so nothing ever leaves the set -- and a single cycle is
deadline-bounded, so a fixed order would starve the tail of the list forever.
Least-recently-checked-first rotates coverage across cycles. (Never shrinking
is not the same as growing without bound; see the seeding section below for
what can actually enter the set.)

That rotation holds only while something in a cycle still completes. It is
built out of completions advancing `checked_at` and abandonments not, so once
at least `resolution_max_workers` domains hang past the batch deadline, every
record in a cycle is an abandonment, no `checked_at` advances anywhere, every
sort key freezes at once, and the name tiebreak below re-picks the same head of
the list every cycle -- the alphabetical freeze this section treats as the
thing to avoid. That is a real ceiling, not a hypothesis: 91 domains against 10
workers on this machine, and the set is mostly `.local` and `in-addr.arpa`
names, which are the ones that hang. It has not been reached yet (no
`outcome: "abandoned"` record exists in the log so far). Nothing here can
prevent it either -- the fix would have to cap how much of the list a single
cycle claims, which is the caller's decision, not the selector's.

That rotation is why abandoned records are skipped *before* the
`checked_at` bookkeeping and not just before the elapsed-time test.
`resolution_log.append_resolution_findings` stamps one `checked_at` for the
whole batch, so every domain a cycle touched shares a single timestamp. If an
abandonment counted as "checked", the domains a deadline truncated would tie
with the ones that actually completed, `sorted` would fall through to the
domain-name tiebreak, and the order would be frozen alphabetically -- the
truncated tail would be abandoned again every cycle and never measured. Only a
completed lookup advances `checked_at`, so an abandoned domain keeps its older
timestamp and sorts to the front of the next cycle.

The log is append-only and already 3.4MB / 16k lines, so it is streamed line
by line and only one aggregate per domain is retained -- never the full record
list. That existing history is a leftover of the retired query-log top-N path
-- the log's first cycle holds exactly 50 records, the old `resolution_top_n`
default -- which is why there is anything here to read at all.

This selector needs seeding, and does not seed itself
-----------------------------------------------------
It is a pure reader, and the only writer of the same log is the resolution job
that consumes its output, so the two form a closed loop. With no log on disk
this returns [], an empty domain list resolves to no findings, and no findings
append nothing: the log is never created and every later cycle repeats that
same no-op. On this machine the loop is already primed by the history above,
but a fresh install has nothing to prime it, and
`query_log.extract_top_domains` -- which used to -- is no longer wired into
`app.py`.

So the set is closed as well as non-shrinking: a domain that is not already in
the log can never enter it, because only domains already selected here are
ever re-resolved and appended. Whatever writes the first records has to live in
the caller. Nothing can be done about it from in here, since "no history" and
"nothing to retry" are the same observation at this layer.
"""

import json
from collections.abc import Iterable
from contextlib import AbstractContextManager
from typing import Callable, Optional

# Injection seam, matching the ResolveFn/ConnectFn/RunFn idiom the sibling
# modules use. Anything that opens `log_path` as a context manager yielding
# lines works.
#
# The annotation does NOT enforce the streaming requirement, and no annotation
# could: `Iterable[str]` constrains shape, not laziness, so a whole-file
# materializer like `lambda p: nullcontext(open(p).read().splitlines())`
# satisfies it. Streaming is enforced behaviorally by `for line in f` below and
# pinned by `test_read_failure_part_way_through_keeps_the_records_already_parsed`,
# whose opener is only observable if lines are consumed lazily. Don't drop that
# test on the belief that the type covers it.
LogOpener = Callable[[str], AbstractContextManager[Iterable[str]]]


def _open_lenient(log_path: str):
    """The default opener. `errors="replace"` keeps a corrupt byte contained to
    its own line instead of raising mid-iteration and ending the read. That
    distinction matters because the log is chronological: aborting the read
    would silently drop the *newest* records, so a domain whose only stall is
    near the end of the file would stop being monitored.

    The containment is not free. Replacement substitutes U+FFFD, so corruption
    in JSON syntax yields a line that fails `json.loads` and is skipped like a
    torn line, but corruption inside a quoted value yields *valid* JSON with a
    mangled string -- a garbage domain name that gets one wasted lookup. One
    wasted lookup per corrupt record is the cheaper failure than dropping every
    record after it.

    `encoding` is pinned, matching `log_watcher` / `query_log` /
    `repair_executor`. Without it the locale default decides, so a launchd
    start with `LANG` unset could decode the log differently than the process
    that wrote it -- and `errors="replace"` would then hide that silently.
    """
    return open(log_path, encoding="utf-8", errors="replace")


def select_stalled_domains(
    log_path: str,
    stall_seconds: float = 1.0,
    opener: LogOpener = _open_lenient,
) -> list[str]:
    """Every domain in `log_path` whose lookup ever took >= `stall_seconds`,
    ordered least-recently-checked first.

    Returns [] if the log cannot be opened at all -- no history is a normal
    state here, not an error. Note that it is not a self-correcting one: see
    "This selector needs seeding" in the module docstring. A read that fails
    part-way through returns the domains found before the failure rather than
    [], so one bad byte cannot silently switch the monitor off.
    """
    stalled: set[str] = set()
    last_checked: dict[str, str] = {}

    try:
        with opener(log_path) as f:
            for line in f:
                record = _parse_line(line)
                if record is None:
                    continue
                domain = record.get("domain")
                if not domain or not isinstance(domain, str):
                    continue
                # A decode-corruption check, not a "is this a real domain"
                # heuristic (that was ruled out on purpose -- see above).
                # `_open_lenient` substitutes U+FFFD for undecodable bytes, and
                # when the corruption lands inside the quoted domain value the
                # line still parses as valid JSON, yielding a mangled name.
                # That name cannot resolve, so it would be re-probed, appended,
                # and -- if that probe happened to be slow -- would enter the
                # stall set permanently. The set is closed and never shrinks,
                # so admitting one is forever.
                if "�" in domain:
                    continue

                # Before the checked_at bookkeeping, not just before the
                # elapsed test: an abandonment must not count as a check, or
                # the truncated tail ties with the completions and starves.
                # See "Ordering is least-recently-checked first" above.
                if record.get("outcome") == "abandoned":
                    continue

                checked_at = record.get("checked_at")
                if isinstance(checked_at, str):
                    previous = last_checked.get(domain)
                    if previous is None or checked_at > previous:
                        last_checked[domain] = checked_at

                elapsed = record.get("elapsed_seconds")
                # `bool` is a subclass of `int`, so a hand-edited or externally
                # written `"elapsed_seconds": true` would otherwise read as 1,
                # clear the 1.0s default threshold, and admit a domain to a set
                # that is closed and never shrinks -- one bad line buys a
                # permanent re-probe. (`NaN` needs no guard: `nan >= x` is
                # False. `Infinity` is admitted, which is correct.)
                if (
                    isinstance(elapsed, (int, float))
                    and not isinstance(elapsed, bool)
                    and elapsed >= stall_seconds
                ):
                    stalled.add(domain)
    except (OSError, UnicodeError):
        # Two different cases land here, and neither should raise.
        #
        # Cannot open the log at all: both aggregates stay empty and this falls
        # out as [] -- the intended first-run-with-no-history answer.
        #
        # Failure part-way through the read: this is a last-resort net for what
        # the per-line paths cannot absorb -- an I/O error mid-file, or a
        # decode error from a caller-supplied strict `opener`. Unlike
        # `_parse_line`'s torn-line skip, it does end the read, so the records
        # after the failure point are lost; keeping the ones already parsed is
        # still strictly better than reporting "no stalls" and silently
        # switching the monitor off. `_open_lenient` exists so the common
        # corruption case degrades per-line and never reaches here.
        pass

    # "" sorts before any ISO timestamp, so a stalled domain with no usable
    # checked_at is treated as never checked and goes to the front.
    return sorted(stalled, key=lambda d: (last_checked.get(d, ""), d))


def _parse_line(line: str) -> Optional[dict]:
    line = line.strip()
    if not line:
        return None
    try:
        record = json.loads(line)
    except ValueError:
        # A crash mid-append can leave one torn line; skip it, keep the rest.
        return None
    return record if isinstance(record, dict) else None
