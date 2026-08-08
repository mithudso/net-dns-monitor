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

import socket
import ssl
import threading
import time
from typing import Callable, Optional

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


def resolve_once(host: str, timeout: float) -> Optional[str]:
    """Resolve a hostname to a literal address, bounded.

    `socket.connect((hostname, port))` resolves inside the call, and
    `settimeout` does not bound that resolution -- measured at 78ms against a
    1ms timeout, and unbounded when the resolver itself is the thing that is
    broken, which during a network outage it may well be. Doing the lookup
    here, on a worker thread with a deadline, keeps the whole measurement
    inside its budget. The result is cached by the meter, so this cost is paid
    once per session rather than once per interface.
    """
    result: list[str] = []

    def lookup() -> None:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            if infos:
                result.append(infos[0][4][0])
        except OSError:
            pass

    worker = threading.Thread(target=lookup, daemon=True)
    worker.start()
    worker.join(timeout)
    return result[0] if result else None


def default_measure(
    device: str,
    host: str = DEFAULT_HOST,
    path: str = DEFAULT_PATH,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    address: Optional[str] = None,
) -> Optional[float]:
    """Megabits per second, or None if the question could not be answered.

    `address` is the pre-resolved literal for `host`; when omitted the lookup
    happens here and counts against the same budget.
    """
    index = default_device_index(device)
    if index is None:
        return None

    started_total = time.monotonic()
    if address is None:
        address = resolve_once(host, timeout)
        if address is None:
            return None
    # Whatever resolution cost, the transfer gets what is left.
    remaining = timeout - (time.monotonic() - started_total)
    if remaining <= 0:
        return None
    timeout = remaining

    if ":" in address:
        family, level, option = socket.AF_INET6, socket.IPPROTO_IPV6, IPV6_BOUND_IF
    else:
        family, level, option = socket.AF_INET, socket.IPPROTO_IP, IP_BOUND_IF

    sock = socket.socket(family, socket.SOCK_STREAM)
    stream = sock
    try:
        sock.setsockopt(level, option, index)
        sock.settimeout(timeout)
        # Connect to the literal, present the hostname for SNI and certificate
        # validation. Passing the hostname here would re-resolve, unbounded.
        sock.connect((address, port))
        stream = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        stream.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
            "Connection: close\r\nUser-Agent: net-dns-monitor\r\n\r\n".encode()
        )

        started = time.monotonic()
        deadline = started + timeout
        first = stream.recv(65536)
        if not first:
            return None
        # The status line may be split across reads, so gather until the first
        # CRLF before judging it -- bounded, so a server that never sends one
        # cannot hold the thread.
        while b"\r\n" not in first and time.monotonic() < deadline:
            more = stream.recv(65536)
            if not more:
                break
            first += more
        # A redirect or an error page still transfers bytes, and timing those
        # would report a broken target as a slow interface. Only a 2xx counts.
        if not is_success_status(first):
            return None

        total = len(first)
        while total < max_bytes and time.monotonic() < deadline:
            chunk = stream.recv(65536)
            if not chunk:
                break
            total += len(chunk)

        return mbps(total, time.monotonic() - started)
    except (OSError, ssl.SSLError, ValueError):
        return None
    finally:
        try:
            stream.close()
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def make_throughput_meter(
    host: str = DEFAULT_HOST,
    path: str = DEFAULT_PATH,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    measure_fn: MeasureFn = default_measure,
):
    """Returns meter(device) -> Optional[float] in Mbps.

    Disabled entirely by passing an empty host, which reports None for every
    interface -- ranking then falls back to reachability alone rather than
    inventing numbers.
    """

    # Resolved once and reused: the lookup is the same for every interface, and
    # paying it per candidate is both slower and a second chance to block.
    cache: dict = {}

    def meter(device: Optional[str]) -> Optional[float]:
        if not device or not host:
            return None
        if "address" not in cache:
            cache["address"] = resolve_once(host, timeout)
        try:
            return measure_fn(
                device,
                host=host,
                path=path,
                port=port,
                timeout=timeout,
                max_bytes=max_bytes,
                address=cache["address"],
            )
        except TypeError:
            # An injected fake that predates the `address` argument.
            return measure_fn(
                device, host=host, path=path, port=port,
                timeout=timeout, max_bytes=max_bytes,
            )
        except Exception:  # noqa: BLE001 - a benchmark must never take down a caller
            return None

    return meter


def measure_all(
    devices: list[str], meter: Callable[[Optional[str]], Optional[float]],
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Benchmark several interfaces against ONE shared deadline.

    Serially, three candidates at a 5s ceiling is 15s of frozen UI during the
    outage being diagnosed -- the additive stall this project has already been
    bitten by once with per-domain DNS timeouts. Run concurrently the whole
    round costs roughly one timeout, and a device that has not answered by the
    deadline is reported as unmeasured rather than waited for.
    """
    results: dict = {}
    workers = []
    for device in devices:

        def measure(device=device) -> None:
            results[device] = meter(device)

        worker = threading.Thread(target=measure, daemon=True)
        workers.append(worker)
        worker.start()

    deadline = time.monotonic() + timeout + 1.0  # +1s for connect/TLS overhead
    for worker in workers:
        worker.join(max(0.0, deadline - time.monotonic()))
    return {device: results.get(device) for device in devices}
