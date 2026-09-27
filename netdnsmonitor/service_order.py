"""Parse `networksetup -listnetworkserviceorder` and build a new order.

Pure text in, text out -- no subprocess here, so the parser is testable against
the literal output of a real machine (see tests).

The care taken here is not incidental. `networksetup -ordernetworkservices`
takes the *entire* service list as arguments and rewrites the order to exactly
what it is given: a name dropped from that list is a network service removed
from the system's order. So every service in the listing has to survive the
round trip, including the ones marked disabled with `(*)` -- disabled is a
separate attribute from position, and omitting those entries would quietly
discard them.
"""

import re
from dataclasses import dataclass
from typing import Optional

# "(1) Wi-Fi" or "(*) M3100" -- the marker is the position, or "*" for a
# service that exists in the order but is currently disabled. The name is
# captured verbatim, trailing whitespace included: it goes back to networksetup
# as an argv token, and a trimmed name would pass the permutation guard (both
# sides of that comparison come through this parse) while naming a service
# that does not exist. networksetup prints exactly one space after the marker.
_ENTRY_RE = re.compile(r"^\((\d+|\*)\) (.+)$")
# "(Hardware Port: Wi-Fi, Device: en0)" -- the device is what IP_BOUND_IF needs.
_PORT_RE = re.compile(r"^\(Hardware Port:\s*(.*?),\s*Device:\s*(.*?)\s*\)\s*$")


@dataclass(frozen=True)
class NetworkService:
    name: str
    device: Optional[str]
    enabled: bool


def parse_service_order(text: str) -> list[NetworkService]:
    """Parse the listing into ordered services. Unparseable input yields [],
    which callers must treat as "unknown" -- never as "no services".
    """
    services: list[NetworkService] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = _ENTRY_RE.match(line)
        if not match:
            continue
        marker, name = match.groups()
        device = None
        if index + 1 < len(lines):
            port_match = _PORT_RE.match(lines[index + 1].strip())
            if port_match:
                device = port_match.group(2) or None
        services.append(NetworkService(name=name, device=device, enabled=marker != "*"))
    return services


def find_service(services: list[NetworkService], name: str) -> Optional[NetworkService]:
    """Exact match only. Two of this machine's adapters are named
    "USB 10/100/1000 LAN" and "USB 10/100/1G/2.5G LAN"; a prefix or fuzzy match
    would silently reorder the wrong physical link.
    """
    for service in services:
        if service.name == name:
            return service
    return None


def promote(services: list[NetworkService], name: str) -> Optional[list[str]]:
    """Return every service name with `name` moved to the front, all others
    keeping their relative order. Returns None if the name is not present --
    the caller must not fall back to a guess.
    """
    if find_service(services, name) is None:
        return None
    return [name] + [s.name for s in services if s.name != name]


def is_order_intact(services: list[NetworkService], new_order: list[str]) -> bool:
    """The guard against the failure mode this module exists to prevent: the
    new order must be a permutation of the current one. Same length, same set,
    no duplicates.

    It can only compare against the `services` it is handed, so it cannot see
    a service added after that listing was taken. `failover.apply_service_order`
    closes most of that window by listing the order again right before the
    write and refusing on any difference; one subprocess of window remains.
    """
    current = [s.name for s in services]
    if not current or len(new_order) != len(current):
        return False
    # macOS keys services by id, so the live order can hold two services with
    # one name. A list of names cannot say which is which, and networksetup
    # takes names -- so no reorder built from such a listing can be trusted
    # to leave both in place.
    if len(set(current)) != len(current):
        return False
    if len(set(new_order)) != len(new_order):
        return False
    # Each name is passed to networksetup as its own argv token, so a service
    # named like a flag would be read as one. There is no shell involved and
    # names round-trip from the machine's own listing, so this is a long shot --
    # but refusing costs nothing and this command rewrites system state.
    if any(name.startswith("-") for name in new_order):
        return False
    return set(new_order) == set(current)


def order_argv(services: list[NetworkService], new_order: list[str]) -> Optional[list[str]]:
    """The one place the `-ordernetworkservices` command line is built.

    Returns None when `is_order_intact` refuses, so a caller cannot reach the
    argv without passing the guard. Every reorder -- automatic, manual, CLI --
    goes through here, because this is the command that deletes a service
    when handed a list with a name missing.
    """
    if not is_order_intact(services, new_order):
        return None
    return ["networksetup", "-ordernetworkservices", *new_order]
