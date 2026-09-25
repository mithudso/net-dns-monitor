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
    # Why this step is worth running, in the words a human would want to read
    # months later in a forensic log. Defaulted so the positional constructions
    # in the tests keep working, but every real step below fills it -- a log
    # that records what was done without recording why is a list of commands,
    # not an explanation.
    reason: str = ""


NETWORK_LADDER = [
    LadderStep(
        "check_interface_state",
        "check",
        needs_privilege=False,
        reason="Confirm the link itself is up before blaming anything above it.",
    ),
    LadderStep(
        "check_default_route",
        "check",
        needs_privilege=False,
        reason="A missing default route is indistinguishable from an outage "
        "from userspace, and is fixed completely differently.",
    ),
    LadderStep(
        "renew_dhcp_lease",
        "repair",
        needs_privilege=True,
        reason="A stale or conflicting lease is the most common recoverable network-layer fault.",
    ),
    LadderStep(
        "toggle_network_service",
        "repair",
        needs_privilege=True,
        reason="Re-initialising the interface clears driver and association "
        "state that renewing a lease cannot.",
    ),
]

DNS_LADDER = [
    LadderStep(
        "check_configured_dns_servers",
        "check",
        needs_privilege=False,
        reason="Establish which resolvers the system is actually using before "
        "changing anything about them.",
    ),
    LadderStep(
        "check_resolver_overrides",
        "check",
        needs_privilege=False,
        reason="/etc/resolver entries silently redirect specific domains and "
        "routinely outlive the VPN or lab network that needed them.",
    ),
    LadderStep(
        "flush_dns_cache",
        "repair",
        needs_privilege=False,
        reason="A cached negative or stale answer keeps failing long after the "
        "underlying fault is gone.",
    ),
    LadderStep(
        "resolve_against_public_resolver",
        "check",
        needs_privilege=False,
        reason="Separates a broken local resolver from a name that genuinely "
        "cannot be resolved anywhere.",
    ),
]

# Moving to the backup network rewrites the system's network service order, so
# it goes last: every cheaper and more easily reversed repair on the ladder is
# tried first. It is tagged needs_privilege because the write genuinely needs
# an administrator right -- unlike toggle_network_service, though, it is really
# attempted, and its outcome string says whether the write landed.
FAILOVER_STEP = LadderStep(
    "switch_to_backup_network",
    "repair",
    needs_privilege=True,
    reason="Every cheaper, more easily reversed repair has already been tried; "
    "moving to the backup link can restore connectivity while the preferred "
    "link is investigated.",
)


def step_by_name(name: str):
    """Look a step up by its dispatch name.

    The dashboard's troubleshooting buttons identify a step by name, and need the
    step object to report which kind it is and why it runs. Returns None for an
    unknown name so a stale button label cannot raise inside a click handler,
    where the traceback would be invisible.
    """
    for step in NETWORK_LADDER + DNS_LADDER:
        if step.name == name:
            return step
    return None


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
