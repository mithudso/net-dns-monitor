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


def default_measure(
    device: str,
    host: str = DEFAULT_HOST,
    path: str = DEFAULT_PATH,
    port: int = DEFAULT_PORT,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> Optional[float]:
    """Megabits per second, or None if the question could not be answered."""
    index = default_device_index(device)
    if index is None:
        return None

    if ":" in host:
        family, level, option = socket.AF_INET6, socket.IPPROTO_IPV6, IPV6_BOUND_IF
    else:
        family, level, option = socket.AF_INET, socket.IPPROTO_IP, IP_BOUND_IF

    sock = socket.socket(family, socket.SOCK_STREAM)
    stream = sock
    try:
        sock.setsockopt(level, option, index)
        sock.settimeout(timeout)
        sock.connect((host, port))
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
        # A redirect or an error page still transfers bytes, and timing those
        # would report a broken target as a slow interface. Only a 2xx counts.
        status_line = first.split(b"\r\n", 1)[0].decode("ascii", "replace")
        if " 2" not in status_line[:12]:
            return None

        total = len(first)
        while total < max_bytes and time.monotonic() < deadline:
            chunk = stream.recv(65536)
            if not chunk:
                break
            total += len(chunk)

        elapsed = time.monotonic() - started
        if elapsed <= 0 or total <= 0:
            return None
        return (total * 8) / elapsed / 1_000_000
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

    def meter(device: Optional[str]) -> Optional[float]:
        if not device or not host:
            return None
        try:
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
