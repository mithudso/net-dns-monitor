"""Resolve a batch of domains (the top-queried domains from `query_log.py`)
concurrently rather than one at a time. Sequentially resolving 50 domains at
~2s timeout each could take minutes if several are unreachable; a thread pool
bounds the whole batch to roughly one timeout period regardless of list size,
which matters since this runs on a fixed 5-minute cadence.

`resolve_fn` is injectable (returns `(resolved, error)`) so this is testable
without touching a real resolver; `default_resolve` below is the real
`socket.getaddrinfo` call used in production.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional

ResolveFn = Callable[[str, float], tuple]


def default_resolve(domain: str, timeout: float) -> tuple:
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True, None
    except OSError as exc:
        return False, str(exc)


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
    }


def resolve_domains_parallel(
    domains: list[str],
    timeout: float = 2.0,
    max_workers: int = 10,
    resolve_fn: Optional[ResolveFn] = None,
) -> list[dict]:
    if not domains:
        return []
    resolve_fn = resolve_fn or default_resolve
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        results = list(
            pool.map(lambda d: _resolve_one(d, timeout, resolve_fn), domains)
        )
    return results
