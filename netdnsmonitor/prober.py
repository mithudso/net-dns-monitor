"""Real connectivity probing: TCP-connect reachability (not ICMP ping, which
is widely filtered/rate-limited and produces false "down" readings) and DNS
resolution for a configured domain list.

The aggregation logic (any target up = reachable, all domains resolve = DNS
ok) is injectable via connect_fn/resolve_fn so it's unit-testable without
touching a real network; make_prober's defaults do the real socket/DNS work.
"""

import socket
import threading
import time
from typing import Callable, Optional

ConnectFn = Callable[[str, int, float], bool]
ResolveFn = Callable[[str, float], bool]


def default_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def default_resolve(domain: str, timeout: float) -> bool:
    """One blocking lookup. The deadline is enforced by `resolve_all`'s join,
    not here.

    `socket.setdefaulttimeout()` looks like it would bound this but does not:
    it sets the default for new socket *objects*, while `getaddrinfo` is a
    module-level C call that never consults it. With an unreachable resolver
    the lookup blocks for the OS resolver's own multi-second retry budget, so
    it must never run on the rumps UI thread. `resolve_all` already puts every
    domain on its own worker and joins them against one shared deadline; a
    second thread-and-join in here doubled the thread count per tick (42 at a
    full learned list) and bounded nothing the outer join did not.
    """
    try:
        socket.getaddrinfo(domain, None)
        return True
    except OSError:
        return False


def resolve_all(
    domains: list[str], timeout: float, resolve_fn: ResolveFn = default_resolve
) -> dict:
    """Resolve every domain against ONE shared deadline, not one deadline each.

    Sequential lookups would make the block additive: with the auto-learned
    list capped at 20 names plus a control domain, a resolver outage would
    freeze the rumps main thread for 21 x timeout instead of timeout. A domain
    whose worker has not answered by the deadline counts as failed.
    """
    if not domains:
        return {}
    results: dict[str, bool] = {}
    workers = []
    for domain in domains:

        def lookup(domain=domain) -> None:
            results[domain] = bool(resolve_fn(domain, timeout))

        worker = threading.Thread(target=lookup, daemon=True)
        workers.append(worker)
        worker.start()

    deadline = time.monotonic() + timeout
    for worker in workers:
        worker.join(max(0.0, deadline - time.monotonic()))
    return {domain: results.get(domain, False) for domain in domains}


def make_prober(
    external_targets: list[tuple[str, int]],
    internal_targets: list[tuple[str, int]],
    domains,
    timeout: float = 2.0,
    connect_fn: ConnectFn = default_connect,
    resolve_fn: ResolveFn = default_resolve,
):
    """`domains` is either a list or a zero-arg callable returning one. The
    callable form exists so an auto-learned domain list (domain_learner) can
    grow between ticks without rebuilding the prober or the state machine.
    """

    def prober() -> dict:
        domain_list = list(domains() if callable(domains) else domains)
        external_reachable: Optional[bool] = (
            any(connect_fn(host, port, timeout) for host, port in external_targets)
            if external_targets
            else None
        )
        internal_reachable: Optional[bool] = (
            any(connect_fn(host, port, timeout) for host, port in internal_targets)
            if internal_targets
            else None
        )
        # Per-domain results, not just the aggregate: whoever prunes a dead
        # learned domain needs to know *which* name failed while others
        # resolved (see domain_learner.prune_dead_domains).
        domain_results = resolve_all(domain_list, timeout, resolve_fn)
        dns_ok: Optional[bool] = all(domain_results.values()) if domain_results else None
        return {
            "external_reachable": external_reachable,
            "internal_reachable": internal_reachable,
            "dns_ok": dns_ok,
            "domain_results": domain_results,
        }

    return prober
