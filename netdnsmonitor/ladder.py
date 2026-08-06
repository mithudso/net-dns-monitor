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

# Moving to the backup network rewrites the system's network service order, so
# it goes last: every cheaper and more easily reversed repair on the ladder is
# tried first. It is tagged needs_privilege because the write genuinely needs
# an administrator right -- unlike the two stubs, though, it is really
# attempted, and its outcome string says whether the write landed.
FAILOVER_STEP = LadderStep("switch_to_backup_network", "repair", needs_privilege=True)

# Which classifications may trigger a network switch. Network-only by default:
# a DNS fault is usually local (resolver cache, /etc/resolver override) and
# moving the physical path does not address it.
DEFAULT_FAILOVER_CLASSIFICATIONS = frozenset({"network"})


def ladder_for(
    classification: Classification,
    failover_classifications: frozenset = DEFAULT_FAILOVER_CLASSIFICATIONS,
) -> list[LadderStep]:
    if classification == Classification.NETWORK:
        steps = list(NETWORK_LADDER)
    elif classification == Classification.DNS:
        steps = list(DNS_LADDER)
    else:
        return []
    if classification.value in failover_classifications:
        steps.append(FAILOVER_STEP)
    return steps
