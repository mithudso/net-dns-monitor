"""Real connectivity probing: TCP-connect reachability (not ICMP ping, which
is widely filtered/rate-limited and produces false "down" readings) and DNS
resolution for a configured domain list.

The aggregation logic (any target up = reachable, all domains resolve = DNS
ok) is injectable via connect_fn/resolve_fn so it's unit-testable without
touching a real network; make_prober's defaults do the real socket/DNS work.
"""

import socket
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
    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(domain, None)
        return True
    except OSError:
        return False


def make_prober(
    external_targets: list[tuple[str, int]],
    internal_targets: list[tuple[str, int]],
    domains: list[str],
    timeout: float = 2.0,
    connect_fn: ConnectFn = default_connect,
    resolve_fn: ResolveFn = default_resolve,
):
    def prober() -> dict:
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
        dns_ok: Optional[bool] = (
            all(resolve_fn(domain, timeout) for domain in domains) if domains else None
        )
        return {
            "external_reachable": external_reachable,
            "internal_reachable": internal_reachable,
            "dns_ok": dns_ok,
        }

    return prober
