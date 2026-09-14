"""Measure how fast a named interface actually moves data.

Reachability says a path works; it says nothing about whether it is a 2.5G
wired link or a congested phone hotspot. When several backups are available,
that difference is the whole decision.

The measurement is a bounded HTTPS download forced out of one interface with
`IP_BOUND_IF` (see interface_probe for why source-address binding does not
work). It is slower than a probe -- seconds, not milliseconds -- so it never
runs on the poll path. It runs when a failover is choosing between candidates,
when the CLI is asked to benchmark, and nowhere else.

**An unmeasurable interface reports `None`, never 0.0.** Zero is a real
reading meaning "carries nothing"; a link that could not be measured is
unknown, and ranking it as the slowest option would hand traffic to a worse
path on no evidence.
"""

import contextlib
import socket
import ssl
import threading
import time
from collections.abc import Sequence
from typing import Callable, Optional, Union

from netdnsmonitor.interface_probe import (
    IP_BOUND_IF,
    IPV6_BOUND_IF,
    default_device_index,
)

# Cloudflare's speed-test endpoint: it serves an exact byte count over plain
# HTTPS with no account, no token and no redirect, which is what makes it
# usable from a bound socket. Configurable -- nothing here is special about
# Cloudflare beyond that it answers predictably.
DEFAULT_HOST = "speed.cloudflare.com"
DEFAULT_PATH = "/__down?bytes=2000000"
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 5.0
DEFAULT_MAX_BYTES = 2_000_000

MeasureFn = Callable[..., Optional[float]]
# One pre-resolved literal, or several (one per family, from resolve_addresses).
Addresses = Union[str, Sequence[str]]
ResolveFn = Callable[[str, float], Union[Addresses, None]]

# Floor for a per-read socket timeout. settimeout(0) makes a socket
# non-blocking, so a budget that is exactly spent must not reach it as zero.
MIN_STEP_TIMEOUT = 0.05


def is_success_status(first_bytes: bytes) -> bool:
    """Whether an HTTP response line reports 2xx.

    Split out and given the whole first read rather than a fixed slice: TCP and
    TLS may hand back a first segment shorter than the status line, and judging
    "HTTP/1.1 2" from ten bytes reported a healthy 200 as a failure -- which
    reads downstream as an interface that cannot be measured.
    """
    line = first_bytes.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = line.split(" ", 2)
    return len(parts) >= 2 and parts[1].startswith("2")


def mbps(total_bytes: int, elapsed: float) -> Optional[float]:
    """None rather than a number when the arithmetic has no meaning."""
    if elapsed <= 0 or total_bytes <= 0:
        return None
    return (total_bytes * 8) / elapsed / 1_000_000


def resolve_addresses(
    host: str,
    timeout: float,
    getaddrinfo_fn: Callable[..., list] = socket.getaddrinfo,
) -> list[str]:
    """Resolve a hostname to one literal per address family, bounded.

    `socket.connect((hostname, port))` resolves inside the call, and
    `settimeout` does not bound that resolution -- measured at 78ms against a
    1ms timeout, and unbounded when the resolver itself is the thing that is
    broken, which during a network outage it may well be. Doing the lookup
    here, on a worker thread with a deadline, keeps the whole measurement
    inside its budget. The result is cached by the meter, so this cost is paid
    once per session rather than once per interface.

    One literal per family, in the resolver's order, rather than the first
    answer: on a dual-stack network the first answer is IPv6, the meter shares
    it with every interface, and a backup link with no IPv6 route then fails
    its connect and reads as unmeasurable. Empty when the lookup fails or runs
    out of time.
    """
    result: list[list[str]] = []

    def lookup() -> None:
        try:
            infos = getaddrinfo_fn(host, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return
        literals: list[str] = []
        families: set = set()
        for family, _kind, _proto, _canonname, sockaddr in infos:
            if family not in (socket.AF_INET, socket.AF_INET6) or family in families:
                continue
            families.add(family)
            literals.append(sockaddr[0])
        result.append(literals)

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return list(result[0]) if result else []


def resolve_once(host: str, timeout: float) -> Optional[str]:
    """The resolver's first literal for `host`, bounded, or None.

    Kept for callers that want a single address. The meter uses
    resolve_addresses so a measurement can fall back to the other family.
    """
    addresses = resolve_addresses(host, timeout)
    return addresses[0] if addresses else None


def _default_tls_wrap(sock: socket.socket, server_hostname: str):
    return ssl.create_default_context().wrap_socket(sock, server_hostname=server_hostname)


def _connect_bound(
    addresses: Sequence[str],
    port: int,
    index: int,
    remaining: Callable[[], float],
    socket_factory: Callable[..., socket.socket],
) -> Optional[socket.socket]:
    """The first literal that accepts a connection from this interface, or None.

    A literal of a family the interface cannot route fails here, and the next
    literal gets what is left of the budget instead of the whole measurement
    reporting the interface as unmeasurable.

    Each connect is armed with a *slice* of the budget, not all of it. A family
    with no route may blackhole rather than refuse, and a connect armed with the
    whole budget then spends every second of it, so the literal after it is
    never tried. Each slice is what is left over the literals still to try, so
    time a fast refusal leaves unspent goes to the literals after it. This is
    the same slicing interface_probe uses, for the same reason.
    """
    for i, literal in enumerate(addresses):
        left = remaining()
        if left <= 0:
            return None
        if ":" in literal:
            family, level, option = socket.AF_INET6, socket.IPPROTO_IPV6, IPV6_BOUND_IF
        else:
            family, level, option = socket.AF_INET, socket.IPPROTO_IP, IP_BOUND_IF
        sock = None
        try:
            sock = socket_factory(family, socket.SOCK_STREAM)
            sock.setsockopt(level, option, index)
            sock.settimeout(left / (len(addresses) - i))
            sock.connect((literal, port))
            return sock
        except OSError:
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.close()
    return None


def default_measure(
    device: str,
    host: str = DEFAULT_HOST,
    path: str = DEFAULT_PATH,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    address: Optional[Addresses] = None,
    *,
    device_index_fn: Callable[[str], Optional[int]] = default_device_index,
    socket_factory: Callable[..., socket.socket] = socket.socket,
    tls_wrap: Optional[Callable] = None,
    clock: Callable[[], float] = time.monotonic,
) -> Optional[float]:
    """Megabits per second, or None if the question could not be answered.

    `address` is the pre-resolved literal for `host`, or a list of them tried
    in order; when omitted the lookup happens here. Lookup, connect, TLS and
    transfer all share the one `timeout` budget.
    """
    index = device_index_fn(device)
    if index is None:
        return None

    budget_end = clock() + timeout

    def remaining() -> float:
        return budget_end - clock()

    if address is None:
        addresses = resolve_addresses(host, timeout)
    elif isinstance(address, str):
        addresses = [address]
    else:
        addresses = list(address)
    if not addresses:
        return None

    # Connect to the literal, present the hostname for SNI and certificate
    # validation. Passing the hostname to connect would re-resolve, unbounded.
    sock = _connect_bound(addresses, port, index, remaining, socket_factory)
    if sock is None:
        return None
    stream = sock

    # A socket timeout applies to each operation, not to the whole call. Armed
    # once with the full budget, connect, the TLS handshake and every read could
    # each spend all of it, so each blocking step gets only what is left.
    def arm(target) -> None:
        target.settimeout(max(MIN_STEP_TIMEOUT, remaining()))

    try:
        arm(sock)
        stream = (tls_wrap or _default_tls_wrap)(sock, host)
        stream.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Connection: close\r\nUser-Agent: net-dns-monitor\r\n\r\n".encode()
        )

        started = clock()
        arm(stream)
        first = stream.recv(65536)
        if not first:
            return None
        # The status line may be split across reads, so gather until the first
        # CRLF before judging it -- bounded, so a server that never sends one
        # cannot hold the thread.
        while b"\r\n" not in first and remaining() > 0:
            arm(stream)
            more = stream.recv(65536)
            if not more:
                break
            first += more
        # A redirect or an error page still transfers bytes, and timing those
        # would report a broken target as a slow interface. Only a 2xx counts.
        if not is_success_status(first):
            return None

        total = len(first)
        while total < max_bytes and remaining() > 0:
            arm(stream)
            try:
                chunk = stream.recv(65536)
            except TimeoutError:
                # Each read is armed with the remaining budget, so a timeout
                # here means the budget ran out mid-read. The bytes that did
                # arrive still measure this link; returning None would report
                # a slow link as unmeasurable.
                break
            if not chunk:
                break
            total += len(chunk)

        return mbps(total, clock() - started)
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        with contextlib.suppress(OSError):
            stream.close()
        with contextlib.suppress(OSError):
            sock.close()


def make_throughput_meter(
    host: str = DEFAULT_HOST,
    path: str = DEFAULT_PATH,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    measure_fn: MeasureFn = default_measure,
    resolve_fn: ResolveFn = resolve_addresses,
):
    """Returns meter(device) -> Optional[float] in Mbps.

    Disabled entirely by passing an empty host, which reports None for every
    interface -- ranking then falls back to reachability alone rather than
    inventing numbers. `resolve_fn` is the lookup seam; the default leaves the
    machine, so tests inject one.
    """

    # Resolved once and reused: the lookup is the same for every interface, and
    # paying it per candidate is both slower and a second chance to block.
    cache: dict = {}

    def meter(device: Optional[str]) -> Optional[float]:
        if not device or not host:
            return None
        if "address" not in cache:
            cache["address"] = resolve_fn(host, timeout)
        # A failed lookup is passed on as None, not as "no addresses", so the
        # measurement retries the lookup inside its own budget.
        address = cache["address"] or None
        try:
            return measure_fn(
                device,
                host=host,
                path=path,
                port=port,
                timeout=timeout,
                max_bytes=max_bytes,
                address=address,
            )
        except TypeError:
            # An injected fake that predates the `address` argument.
            return measure_fn(
                device,
                host=host,
                path=path,
                port=port,
                timeout=timeout,
                max_bytes=max_bytes,
            )
        except Exception:  # noqa: BLE001 - a benchmark must never take down a caller
            return None

    return meter


def measure_all(
    devices: list[str],
    meter: Callable[[Optional[str]], Optional[float]],
    timeout: float = DEFAULT_TIMEOUT,
    grace: float = 1.0,
) -> dict:
    """Benchmark several interfaces against ONE shared deadline.

    Serially, three candidates at a 5s ceiling is 15s of frozen UI during the
    outage being diagnosed -- the additive stall this project has already been
    bitten by once with per-domain DNS timeouts. Run concurrently the whole
    round costs roughly one timeout, and a device that has not answered by the
    deadline is reported as unmeasured rather than waited for.

    `grace` is slack past `timeout` for work outside a measurement's own
    budget, such as the meter's one-time lookup.
    """
    results: dict = {}
    workers = []
    for device in devices:

        def measure(device=device) -> None:
            results[device] = meter(device)

        worker = threading.Thread(target=measure, daemon=True)
        workers.append(worker)
        worker.start()

    deadline = time.monotonic() + timeout + max(0.0, grace)
    for worker in workers:
        worker.join(max(0.0, deadline - time.monotonic()))
    return {device: results.get(device) for device in devices}
