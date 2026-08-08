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

# From Darwin's netinet/in.h and netinet6/in6.h. CPython exposes no constants
# for these, so the raw option numbers are used; they are stable ABI, not
# version-specific details. Both were confirmed against a live interface.
IP_BOUND_IF = 25
IPV6_BOUND_IF = 125

BoundConnectFn = Callable[[str, str, int, float], bool]
DeviceIndexFn = Callable[[str], Optional[int]]


def default_device_index(device: str) -> Optional[int]:
    """None when the interface is not present.

    An unplugged USB Ethernet adapter disappears from the interface list
    entirely, and that is *not* the same reading as "present but unreachable":
    macOS has already routed around a missing interface on its own.

    Both readings happen to refuse the same switches today, so this is about
    what gets *reported*, not what gets decided -- the incident report says
    "the adapter is not there" rather than "the link is dead", which are
    different things to hand a human. Collapsing them would also make the
    policy's refusal reasons wrong the first time the two need to diverge.
    """
    try:
        return socket.if_nametoindex(device)
    except OSError:
        return None


def default_bound_connect(device: str, host: str, port: int, timeout: float) -> bool:
    index = default_device_index(device)
    if index is None:
        return False
    # The bind option is family-specific. The ordinary prober uses
    # socket.create_connection, which is family-agnostic, so an IPv6 external
    # target is a perfectly valid thing to find in the config -- forcing every
    # probe through AF_INET would report such a target as unreachable rather
    # than unprobed, and a preferred link that had recovered over IPv6 would
    # never be failed back to.
    if ":" in host:
        family, level, option = socket.AF_INET6, socket.IPPROTO_IPV6, IPV6_BOUND_IF
    else:
        family, level, option = socket.AF_INET, socket.IPPROTO_IP, IP_BOUND_IF
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(level, option, index)
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
        #
        # The budget is also *sliced*, which the first version left out, and the
        # omission mattered: handing each connect the whole remaining budget let
        # one blackholing target consume all of it, so every later target was
        # skipped and the probe reported unreachable about a working link.
        # Raising the budget made it worse rather than better -- the blackhole
        # simply stalled for longer. Found on a live machine where the targets
        # are per-link gateways, so all but one are unreachable from any given
        # interface by construction.
        #
        # A target that answers does so in milliseconds, so the slice only ever
        # binds the ones that were going to fail anyway, and unspent time stays
        # available to whatever comes next.
        deadline = time.monotonic() + timeout
        share = timeout / len(targets)
        for host, port in targets:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if connect_fn(device, host, port, min(remaining, share)):
                return True
        return False

    return probe
