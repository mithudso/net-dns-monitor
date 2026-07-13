"""Offline troubleshooting ladder: an ordered list of steps to run once an
incident is classified, branching on the network-vs-DNS split. Each step is
either a check (informational, no side effect) or a repair (attempts a fix)
and is tagged with whether it needs elevated privilege the sandboxed app may
not have (see the plan's sandbox/privileged-helper decision).
"""

from dataclasses import dataclass

from netdnsmonitor.classifier import Classification


@dataclass(frozen=True)
class LadderStep:
    name: str
    kind: str  # "check" or "repair"
    needs_privilege: bool


NETWORK_LADDER = [
    LadderStep("check_interface_state", "check", needs_privilege=False),
    LadderStep("check_default_route", "check", needs_privilege=False),
    LadderStep("renew_dhcp_lease", "repair", needs_privilege=True),
    LadderStep("toggle_network_service", "repair", needs_privilege=True),
]

DNS_LADDER = [
    LadderStep("check_configured_dns_servers", "check", needs_privilege=False),
    LadderStep("check_resolver_overrides", "check", needs_privilege=False),
    LadderStep("flush_dns_cache", "repair", needs_privilege=False),
    LadderStep("resolve_against_public_resolver", "check", needs_privilege=False),
]


def ladder_for(classification: Classification) -> list[LadderStep]:
    if classification == Classification.NETWORK:
        return list(NETWORK_LADDER)
    if classification == Classification.DNS:
        return list(DNS_LADDER)
    return []
