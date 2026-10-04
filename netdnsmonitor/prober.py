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
    errors: list[Exception] = []
    lock = threading.Lock()
    workers = []
    for domain in domains:

        def lookup(domain=domain) -> None:
            try:
                result = bool(resolve_fn(domain, timeout))
            except Exception as exc:  # noqa: BLE001 - propagate on the caller thread
                with lock:
                    errors.append(exc)
            else:
                with lock:
                    results[domain] = result

        worker = threading.Thread(target=lookup, daemon=True)
        workers.append(worker)
        worker.start()

    deadline = time.monotonic() + timeout
    for worker in workers:
        worker.join(max(0.0, deadline - time.monotonic()))
    with lock:
        # A programming or encoding error is not evidence of a DNS outage.
        # The app's tick guard records the failure without classifying it.
        if errors:
            raise errors[0]
        return {domain: results.get(domain, False) for domain in domains}


class _ConnectRace:
    """Connect to every target at once and settle on the first that answers.

    Sequential connects made the block additive, the same trap resolve_all
    exists to avoid: two blackholing external targets at a 2s timeout, then
    DNS, froze the rumps main thread for 6s on every failing tick. Each connect
    runs on its own daemon thread bounded by `timeout`, so a worker still
    running after `result()` gives up exits on its own shortly after.
    """

    def __init__(self, targets: list[tuple[str, int]], timeout: float, connect_fn: ConnectFn):
        self._cond = threading.Condition()
        self._pending = len(targets)
        self._answered = False
        self._error: Optional[BaseException] = None
        for host, port in targets:
            threading.Thread(
                target=self._attempt, args=(connect_fn, host, port, timeout), daemon=True
            ).start()

    def _attempt(self, connect_fn: ConnectFn, host: str, port: int, timeout: float) -> None:
        answered, error = False, None
        try:
            answered = bool(connect_fn(host, port, timeout))
        except Exception as exc:  # noqa: BLE001 - carried to the caller's thread by result()
            error = exc
        with self._cond:
            self._pending -= 1
            self._answered = self._answered or answered
            if error is not None and self._error is None:
                self._error = error
            self._cond.notify_all()

    def result(self, deadline: float) -> bool:
        with self._cond:
            while not self._answered and self._pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._cond.wait(remaining)
            if self._answered:
                return True
            # Swallowed on the worker thread, a broken connect_fn would surface
            # as "unreachable", which classify() turns into a confident NETWORK
            # diagnosis. Re-raised here, it reaches the tick guard instead.
            if self._error is not None:
                raise self._error
            return False


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
    # A 0 timeout fails every connect instantly, so every tick would report a
    # NETWORK incident nobody measured; a negative one raises ValueError from
    # socket code that only catches OSError. `not >` also refuses NaN.
    if not timeout > 0:
        raise ValueError("timeout must be > 0")

    def prober() -> dict:
        domain_list = list(domains() if callable(domains) else domains)
        # The connects run while resolve_all blocks below, and both are held
        # to the same deadline, so the probe costs about one timeout in total
        # rather than one per phase.
        deadline = time.monotonic() + timeout
        external = _ConnectRace(external_targets, timeout, connect_fn) if external_targets else None
        internal = _ConnectRace(internal_targets, timeout, connect_fn) if internal_targets else None
        # Per-domain results, not just the aggregate: whoever prunes a dead
        # learned domain needs to know *which* name failed while others
        # resolved (see domain_learner.prune_dead_domains).
        domain_results = resolve_all(domain_list, timeout, resolve_fn)
        external_reachable: Optional[bool] = external.result(deadline) if external else None
        internal_reachable: Optional[bool] = internal.result(deadline) if internal else None
        dns_ok: Optional[bool] = all(domain_results.values()) if domain_results else None
        return {
            "external_reachable": external_reachable,
            "internal_reachable": internal_reachable,
            "dns_ok": dns_ok,
            "domain_results": domain_results,
        }

    return prober
