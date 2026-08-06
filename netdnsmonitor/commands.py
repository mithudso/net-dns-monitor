"""The catalogue of network diagnostic commands the console offers.

Data, not behaviour: a list of commands with what each one answers and whether
it changes anything. Both the CLI console and the menu bar window read this, so
the two never drift apart, and the "is this safe to run" judgement lives in one
place instead of being re-decided per surface.

`mutates` is the load-bearing field. A console that offers `ifconfig en0 down`
next to `scutil --nwi` with no distinction is a foot-gun; anything that changes
system state has to be marked, and the console refuses to run it without an
explicit confirmation.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class DiagnosticCommand:
    key: str
    argv: list[str]
    answers: str
    mutates: bool = False
    needs_admin: bool = False
    # Filled in from the live service list when the command targets one.
    placeholder: Optional[str] = None
    notes: str = ""


CATALOG: list[DiagnosticCommand] = [
    # --- what is the system actually doing right now ---
    DiagnosticCommand(
        "nwi", ["scutil", "--nwi"],
        "which interfaces are active and reachable, and which is primary",
    ),
    DiagnosticCommand(
        "order", ["networksetup", "-listnetworkserviceorder"],
        "the service priority list, and which services are disabled (*)",
    ),
    DiagnosticCommand(
        "routes", ["netstat", "-rn", "-f", "inet"],
        "the routing table -- which interface the default route points at",
    ),
    DiagnosticCommand(
        "ifconfig", ["ifconfig"], "every interface, its flags, addresses and link status",
    ),
    DiagnosticCommand(
        "iface", ["ifconfig", "{device}"],
        "one interface: is the link up, does it have an address",
        placeholder="device",
    ),
    DiagnosticCommand(
        "hwports", ["networksetup", "-listallhardwareports"],
        "the hardware behind each device name",
    ),
    # --- DNS ---
    DiagnosticCommand(
        "dns", ["scutil", "--dns"],
        "the resolver configuration, per search domain and per interface",
    ),
    DiagnosticCommand(
        "resolvers", ["ls", "-la", "/etc/resolver"],
        "split-DNS overrides that beat the normal resolver order",
    ),
    DiagnosticCommand(
        "dig", ["dig", "+short", "{domain}"],
        "resolve one name through the system resolver",
        placeholder="domain",
    ),
    DiagnosticCommand(
        "dig-direct", ["dig", "+short", "@1.1.1.1", "{domain}"],
        "resolve one name bypassing the system resolver entirely",
        placeholder="domain",
        notes="Differing from `dig` means the local resolver is the problem, not the network.",
    ),
    # --- reachability ---
    DiagnosticCommand(
        "ping", ["ping", "-c", "3", "1.1.1.1"],
        "raw reachability to a known-good address",
        notes="ICMP is widely filtered; a failure here is weaker evidence than a TCP probe.",
    ),
    DiagnosticCommand(
        "ping-gw", ["ping", "-c", "3", "{gateway}"],
        "whether the local gateway answers -- separates LAN from uplink faults",
        placeholder="gateway",
    ),
    DiagnosticCommand(
        "traceroute", ["traceroute", "-w", "1", "-m", "12", "1.1.1.1"],
        "where along the path packets stop",
    ),
    # --- Wi-Fi ---
    DiagnosticCommand(
        "wifi", ["wdutil", "info"],
        "the current Wi-Fi association: SSID, channel, RSSI, rate",
        needs_admin=True,
        notes="Needs sudo on recent macOS; without it the output is redacted.",
    ),
    DiagnosticCommand(
        "wifi-scan", ["networksetup", "-listpreferredwirelessnetworks", "{device}"],
        "the remembered Wi-Fi networks for an interface, in join order",
        placeholder="device",
    ),
    # --- things that change state ---
    DiagnosticCommand(
        "enable", ["networksetup", "-setnetworkserviceenabled", "{service}", "on"],
        "turn a disabled service on so it can carry traffic",
        mutates=True, needs_admin=True, placeholder="service",
        notes="A disabled service is skipped no matter its position in the order.",
    ),
    DiagnosticCommand(
        "disable", ["networksetup", "-setnetworkserviceenabled", "{service}", "off"],
        "turn a service off entirely",
        mutates=True, needs_admin=True, placeholder="service",
    ),
    DiagnosticCommand(
        "renew-dhcp", ["ipconfig", "set", "{device}", "DHCP"],
        "force a fresh DHCP lease on one interface",
        mutates=True, needs_admin=True, placeholder="device",
    ),
    DiagnosticCommand(
        "flush-dns", ["dscacheutil", "-flushcache"],
        "drop the DNS cache",
        mutates=True,
        notes="Only half a flush: the mDNSResponder HUP needs privilege and is separate.",
    ),
]

BY_KEY = {c.key: c for c in CATALOG}


def resolve(key: str, **values) -> Optional[list[str]]:
    """Turn a catalogue key plus placeholder values into a real argv.

    Returns None for an unknown key, and leaves an unfilled placeholder in
    place so the caller can see what is still needed rather than silently
    running a command with a literal "{device}" in it.
    """
    command = BY_KEY.get(key)
    if command is None:
        return None
    argv = []
    for token in command.argv:
        if token.startswith("{") and token.endswith("}"):
            name = token[1:-1]
            if name not in values or values[name] in (None, ""):
                return None
            argv.append(str(values[name]))
        else:
            argv.append(token)
    return argv


def missing_placeholder(key: str, **values) -> Optional[str]:
    """Which placeholder still needs a value, if any."""
    command = BY_KEY.get(key)
    if command is None or command.placeholder is None:
        return None
    if values.get(command.placeholder) in (None, ""):
        return command.placeholder
    return None
