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

import errno
import functools
import ipaddress
import socket
import time
from typing import Callable, Optional

# From Darwin's netinet/in.h and netinet6/in6.h. CPython exposes no constants
# for these, so the raw option numbers are used; they are stable ABI, not
# version-specific details. Both were confirmed against a live interface.
IP_BOUND_IF = 25
IPV6_BOUND_IF = 125

# None: the question was not asked (no such interface, or this process could not
# open a socket); False: it was asked and nothing answered.
BoundConnectFn = Callable[[str, str, int, float], Optional[bool]]
DeviceIndexFn = Callable[[str], Optional[int]]

# Failures that say something about this process or the interface table, not
# about the path to the target. Reporting them as "unreachable" would send
# someone after a dead link when the fault was a file-descriptor limit.
_LOCAL_FAILURE_ERRNOS = frozenset(
    {errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EPERM, errno.EACCES}
)


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


def default_bound_connect(
    device: str,
    host: str,
    port: int,
    timeout: float,
    index_fn: DeviceIndexFn = default_device_index,
) -> Optional[bool]:
    """True if the connect completed through `device`, False if it was tried and
    failed, None if it could not be tried (the interface is absent or went away,
    or this process could not open a socket).
    """
    index = index_fn(device)
    if index is None:
        return None
    try:
        # The config accepts literals only: a hostname lookup here could block
        # outside the socket deadline and mistake a DNS fault for a dead link.
        ipaddress.ip_address(host)
        deadline = time.monotonic() + timeout
        # Select from the addresses the OS supplies rather than guessing from
        # the input string. Darwin may supply a synthesized IPv6 destination for
        # an IPv4 literal on NAT64; flags=0 does not promise that synthesis on
        # every OS/network. Actual NAT64 acceptance still requires live testing.
        candidates = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (OSError, OverflowError, TypeError, ValueError):
        return False
    candidates = [c for c in candidates if c[0] in (socket.AF_INET, socket.AF_INET6)]
    asked = False
    for i, (family, kind, _proto, _canon, address) in enumerate(candidates):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        level, option = (
            (socket.IPPROTO_IPV6, IPV6_BOUND_IF)
            if family == socket.AF_INET6
            else (socket.IPPROTO_IP, IP_BOUND_IF)
        )
        sock = None
        stage_bound = False
        try:
            sock = socket.socket(family, kind)
            sock.setsockopt(level, option, index)
            stage_bound = True
            # An unreachable candidate must not starve a working address of
            # the same target, just as one target must not starve the next.
            sock.settimeout(remaining / (len(candidates) - i))
            sock.connect(address)
            return True
        except ConnectionRefusedError:
            # An RST is the target answering through this interface. A router
            # that answers but runs no DNS over TCP is a working link, not a
            # dead one.
            return True
        except OSError as exc:
            # ENXIO from the bind is the interface vanishing between the index
            # lookup and here: an unplugged adapter, not a dead link.
            vanished = not stage_bound and exc.errno == errno.ENXIO
            if not (vanished or exc.errno in _LOCAL_FAILURE_ERRNOS):
                asked = True
            continue
        except (OverflowError, TypeError, ValueError):
            asked = True
            continue
        finally:
            if sock is not None:
                sock.close()
    return False if asked else None


def make_interface_prober(
    targets: list[tuple[str, int]],
    timeout: float = 2.0,
    connect_fn: BoundConnectFn = default_bound_connect,
    index_fn: DeviceIndexFn = default_device_index,
):
    """Returns probe(device) -> Optional[bool].

    True if any target answered through that interface, False if none did,
    None if the question could not be asked at all (no device configured, the
    device is absent, there is nothing to probe against, the timeout left no
    budget to try even one target, or every attempt failed locally -- the
    interface vanished or this process could not open a socket).
    """
    # The injected index_fn has to reach the connect side too, or the default
    # connect consults the real interface table while probe() consulted the
    # fake -- and the two disagree exactly when a test is pretending an
    # adapter is absent.
    if connect_fn is default_bound_connect:
        connect_fn = functools.partial(default_bound_connect, index_fn=index_fn)

    def probe(device: Optional[str]) -> Optional[bool]:
        if not device or not targets:
            return None
        # A non-positive budget asks nothing; False would say "dead" about a
        # link nobody probed. `probe_timeout_seconds` is user-settable YAML.
        if timeout <= 0:
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
        # binds the ones that were going to fail anyway. Each slice is the
        # remaining budget over the targets still to try, so time a fast
        # failure (ENETUNREACH) leaves unspent goes to the targets after it; a
        # fixed timeout / N stranded it.
        deadline = time.monotonic() + timeout
        attempted = False
        for i, (host, port) in enumerate(targets):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            answer = connect_fn(device, host, port, remaining / (len(targets) - i))
            if answer is True:
                return True
            # None is "not asked", the same as no budget: it must not turn into
            # a measured failure.
            if answer is not None:
                attempted = True
        # No budget for even the first target is no reading at all, and False
        # would tell the report and the failover policy the link is dead.
        return False if attempted else None

    return probe
