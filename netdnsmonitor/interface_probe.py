"""Reachability of a target *through a named interface*, regardless of which
interface currently holds the default route.

This is what makes failover a decision rather than a guess. While the wired
link is primary, an ordinary connect() says nothing about whether the Wi-Fi
hotspot works -- every packet leaves via the wired link. Switching without
first confirming the backup carries traffic just trades one dead path for
another and thrashes the service order doing it.

Binding the *source address* is the obvious way to do this and it does not
work: on Darwin the route lookup is driven by the destination, so a socket
bound to the Wi-Fi address still leaves through whichever interface owns the
route. The mechanism that does work is the IP_BOUND_IF socket option, which
pins the socket to an interface index.
"""

import socket
import time
from typing import Callable, Optional

# From Darwin's netinet/in.h. CPython exposes no constant for it, so the raw
# option number is used; it is stable ABI, not a version-specific detail.
IP_BOUND_IF = 25

BoundConnectFn = Callable[[str, str, int, float], bool]
DeviceIndexFn = Callable[[str], Optional[int]]


def default_device_index(device: str) -> Optional[int]:
    """None when the interface is not present.

    An unplugged USB Ethernet adapter disappears from the interface list
    entirely, and that is *not* the same reading as "present but unreachable":
    macOS has already routed around a missing interface on its own, so there is
    nothing to fail over. Reported as None -- not probed -- so the policy layer
    cannot mistake it for a failure.
    """
    try:
        return socket.if_nametoindex(device)
    except OSError:
        return None


def default_bound_connect(device: str, host: str, port: int, timeout: float) -> bool:
    index = default_device_index(device)
    if index is None:
        return False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, index)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return True
    except OSError:
        # A down interface fails here immediately with ENETUNREACH rather than
        # blocking, so this path costs nothing on the common case.
        return False
    finally:
        sock.close()


def make_interface_prober(
    targets: list[tuple[str, int]],
    timeout: float = 2.0,
    connect_fn: BoundConnectFn = default_bound_connect,
    index_fn: DeviceIndexFn = default_device_index,
):
    """Returns probe(device) -> Optional[bool].

    True if any target answered through that interface, False if none did,
    None if the question could not be asked at all (no device configured, the
    device is absent, or there is nothing to probe against).
    """

    def probe(device: Optional[str]) -> Optional[bool]:
        if not device or not targets:
            return None
        if index_fn(device) is None:
            return None
        # One deadline for all targets, not one each. This runs on the rumps
        # timer thread, and a blackholing-but-routable interface burns the full
        # timeout per target -- the additive stall that non-negotiable 7 exists
        # to prevent.
        deadline = time.monotonic() + timeout
        for host, port in targets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if connect_fn(device, host, port, remaining):
                return True
        return False

    return probe
