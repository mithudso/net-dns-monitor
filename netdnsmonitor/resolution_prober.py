"""Resolve a batch of domains (every ever-stalled domain, from `stall_log.py`)
concurrently rather than one at a time. Sequentially resolving them at ~2s
each would take minutes if several are unreachable; a thread pool bounds the
whole batch to roughly one timeout period per worker-load, which matters since
this runs on a fixed 5-minute cadence.

Why there is a batch deadline
-----------------------------
`timeout` is not actually enforceable per lookup. `socket.setdefaulttimeout()`
does not bound `socket.getaddrinfo()` -- that is a blocking C call into the
system resolver and is not interruptible from Python. Measured on macOS: with
`setdefaulttimeout(2.0)`, a missing `.local` name still took 5.01s, and the
resolution log has real lookups at 30s and 35s against the same 2.0 setting.

Since the input list is now "every domain that ever stalled" and only grows,
an unbounded batch would eventually exceed the 5-minute cadence. So the batch
takes a wall-clock `deadline_seconds`: work still outstanding when the
deadline passes is recorded as `outcome: "abandoned"` and the batch returns.
Not-yet-started lookups are cancelled; already-running ones are left to finish
on their own rather than blocking the caller.

"Not blocking the caller" is not the same as not blocking the process.
`concurrent.futures.thread` registers a `threading._register_atexit` hook that
joins every live pool worker at interpreter exit -- daemon or not, and
regardless of `shutdown(wait=False)`. An abandoned worker still inside
`getaddrinfo` therefore delays process exit by the rest of its hang. Measured
in this repo: `pytest tests/test_resolution_prober.py` reports 0.85s of tests
and took 30.8s of wall clock, all of it that join, until the sentinel sleeps in
those tests were shortened.

Abandoned workers also outlive the batch that gave up on them. A fresh pool is
built per cycle, so up to `max_workers` threads can overlap the next cycle
whenever a lookup outlasts the slack between the cadence and the deadline (60s
at the shipped 300/240). It is self-limiting -- each exits as soon as its
lookup returns -- but it is not zero, and the regime where it happens is
exactly the DNS stall this app exists to watch.

Abandoned records deliberately do NOT feed back into stall detection -- see
the module docstring in `stall_log.py` for why that would be a runaway loop.

`resolve_fn` is injectable (returns `(resolved, error)`) so this is testable
without touching a real resolver; `default_resolve_with_error` below is the
real `socket.getaddrinfo` call used in production. It is deliberately not
named `default_resolve`: prober.py has one of those with the same signature
and a bool return, and a tuple handed to that caller is always truthy, so a
failed lookup would read as healthy.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Callable, Optional

ResolveFn = Callable[[str, float], tuple]


def default_resolve_with_error(domain: str, timeout: float) -> tuple:
    # `timeout` is accepted because ResolveFn requires it and it documents the
    # intended ceiling; nothing here can enforce it. getaddrinfo never consults
    # socket.setdefaulttimeout(), and setting that process-wide from a pool
    # thread only changed every other socket in the app.
    try:
        socket.getaddrinfo(domain, None)
        return True, None
    except OSError as exc:
        return False, str(exc)


# Kept for callers written against the other name; see the docstring above for why
# the descriptive name is the one used here.
default_resolve = default_resolve_with_error


def _resolve_one(domain: str, timeout: float, resolve_fn: ResolveFn) -> dict:
    started = time.monotonic()
    try:
        resolved, error = resolve_fn(domain, timeout)
    except Exception as exc:  # noqa: BLE001 - any resolver failure is a finding, not a crash
        resolved, error = False, str(exc)
    elapsed = time.monotonic() - started
    return {
        "domain": domain,
        "resolved": resolved,
        "error": error,
        "elapsed_seconds": elapsed,
        "outcome": "completed",
    }


def resolve_domains_parallel(
    domains: list[str],
    timeout: float = 2.0,
    max_workers: int = 10,
    resolve_fn: Optional[ResolveFn] = None,
    deadline_seconds: Optional[float] = None,
) -> list[dict]:
    """Resolve every domain, returning one finding per input domain in input
    order. With `deadline_seconds` set, stops waiting once that much wall-clock
    has passed and records the outstanding domains as `outcome: "abandoned"`.
    """
    if not domains:
        return []
    if deadline_seconds is not None and deadline_seconds <= 0:
        # Decide this before submitting. `wait(..., timeout=0.0)` below is a
        # race a fast resolver can win, so the same config yields "completed"
        # on one run and "abandoned" on the next; and every submitted lookup
        # still runs to completion in a worker while its result is discarded.
        # resolution_batch_deadline_seconds is user-settable YAML, so a `0`
        # typo would otherwise mean every cycle performs all the real lookups
        # and throws all of them away, forever.
        return [
            {
                "domain": domain,
                "resolved": False,
                "error": "non-positive deadline_seconds; no lookup attempted",
                "elapsed_seconds": 0.0,
                "outcome": "abandoned",
            }
            for domain in domains
        ]
    resolve_fn = resolve_fn or default_resolve_with_error

    started = time.monotonic()
    # `resolution_max_workers` is user-settable YAML; ThreadPoolExecutor raises
    # on 0 or below, which the worker guard in app.py would swallow on every
    # cycle, leaving the monitor silently dead.
    pool = ThreadPoolExecutor(max_workers=max(1, int(max_workers)))
    try:
        futures = [pool.submit(_resolve_one, d, timeout, resolve_fn) for d in domains]

        if deadline_seconds is None:
            wait(futures)
        else:
            remaining = deadline_seconds - (time.monotonic() - started)
            wait(futures, timeout=max(0.0, remaining))

        findings = []
        for domain, future in zip(domains, futures, strict=True):
            findings.append(_finding_for(domain, future, started))
        return findings
    finally:
        # wait=False so a lookup still hung inside getaddrinfo cannot hold up
        # the caller; cancel_futures drops the ones that never started.
        pool.shutdown(wait=False, cancel_futures=True)


def _finding_for(domain: str, future, batch_started: float) -> dict:
    if future.done() and not future.cancelled():
        try:
            return future.result()
        except Exception as exc:  # noqa: BLE001 - a pool failure is a finding, not a crash
            # The worker raised outside resolve_fn, so no lookup happened.
            # "abandoned" with zero elapsed keeps it out of stall detection:
            # a "completed" record carrying the batch's elapsed time would
            # admit the domain to a stall set that is closed and never shrinks.
            return {
                "domain": domain,
                "resolved": False,
                "error": f"resolution pool failure: {type(exc).__name__}",
                "elapsed_seconds": 0.0,
                "outcome": "abandoned",
            }
    future.cancel()
    return {
        "domain": domain,
        "resolved": False,
        "error": "batch deadline exceeded before this lookup finished",
        "elapsed_seconds": time.monotonic() - batch_started,
        "outcome": "abandoned",
    }
