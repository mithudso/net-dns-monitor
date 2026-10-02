"""Dispatch ladder steps (see ladder.py) to real macOS actions.

Check steps shell out to read-only system tools and report their output; none of
them mutate system state.

Repair steps that need root used to be stubbed unconditionally. They are now
gated on whether the user has granted the app the specific rights involved --
see privileges.py, which is also where the reasoning about how narrow that grant
is lives:

* `flush_dns_cache` always clears the cache (`dscacheutil` needs no privilege)
  and, with the grant, also restarts mDNSResponder. Without it, the cache is
  still cleared and the outcome says so, and says how to fix it.
* `renew_dhcp_lease` runs with the grant and reports NEEDS_PRIVILEGE without it.
  It first confirms the interface holds a DHCP lease, because `ipconfig set`
  replaces whatever IPv4 configuration the interface had.
* `toggle_network_service` is never automated. Down and up cannot be one command,
  and shipping two means a crash in between leaves the machine offline. The stub
  explains that rather than pretending the grant is missing.

`is_granted_fn` and `primary_interface_fn` default to "no privilege, no
interface" rather than to the real probes, so a caller passing a fake `run_fn`
(i.e. every test) gets deterministic behaviour and no extra subprocesses. app.py
passes the real ones in.

`is_granted_fn` answers for the mDNSResponder rule only. The grant lists the
DHCP renewal per interface, so `dhcp_granted_fn(interface)` answers for the
interface actually being renewed. Without it, renewal falls back to
`is_granted_fn`, which is what every caller got before it existed.
"""

import os
import re
import subprocess
from types import SimpleNamespace
from typing import Callable, Optional

from netdnsmonitor import privileges
from netdnsmonitor.dns_query import query_public_dns_any
from netdnsmonitor.ladder import LadderStep

RunFn = Callable[..., object]

RESOLVER_DIR = "/etc/resolver"

# Absolute paths, like privileges.py: a menu-bar app's PATH is whatever launchd
# handed it, and a step that resolves its binary through it is one PATH entry away
# from running something else under the same name.
DSCACHEUTIL = "/usr/bin/dscacheutil"
SCUTIL = "/usr/sbin/scutil"
NETSTAT = "/usr/sbin/netstat"

GRANT_HINT = 'Use "Grant elevated permissions" in the app window to allow this.'

# A DHCP server must put a lease time in every ACK that grants an address (RFC
# 2131 section 4.3.1, table 3). The ACK to an INFORM -- an address set by hand
# that only asks the server for options -- must not carry one (4.3.5), so a
# packet alone does not show the interface is on DHCP; the lease line does.
_LEASE_LINE = re.compile(r"^lease_time\b", re.MULTILINE)


def make_repair_executor(
    run_fn: RunFn = subprocess.run,
    query_fn: Callable[[str], Optional[bool]] = query_public_dns_any,
    resolver_dir_exists_fn: Callable[[str], bool] = os.path.isdir,
    resolver_listdir_fn: Callable[[str], list] = os.listdir,
    probe_domain: str = "example.com",
    is_granted_fn: Optional[Callable[[], bool]] = None,
    primary_interface_fn: Optional[Callable[[], Optional[str]]] = None,
    failover_fn: Optional[Callable[[str], str]] = None,
    dhcp_granted_fn: Optional[Callable[[str], bool]] = None,
    unavailable_fn: Optional[Callable[[str], str]] = None,
    covered_interfaces_fn: Optional[Callable[[], list]] = None,
):
    """`unavailable_fn(what)` marks the privileged repairs as not part of this
    build (the Mac App Store edition may not ask for root). When it is set, those
    steps run nothing and return its text, which never reads as ok, failed or
    NEEDS_PRIVILEGE -- the grant hint would point at a button that build lacks.
    """
    is_granted_fn = is_granted_fn or (lambda: False)
    primary_interface_fn = primary_interface_fn or (lambda: None)
    # `is_granted_fn` answers only for the mDNSResponder restart. The DHCP rules
    # are separate lines, enumerated at grant time, so a renewal also has to ask
    # which interfaces those lines name. An empty answer means "unknown" and the
    # renewal is attempted; the sudo refusal, if any, is then reported honestly.
    covered_interfaces_fn = covered_interfaces_fn or (lambda: [])

    def run(args: list[str]) -> object:
        try:
            return run_fn(
                args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5
            )
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))

    def report_command(args: list[str]) -> str:
        """A check step's finding: the tool's output, or an explicit failure.

        A non-zero exit with empty stdout used to be reported as "" -- which the
        report, the LLM bundle and the alert all read as "the tool found nothing",
        when the truth was that the tool did not run.
        """
        result = run(args)
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode != 0:
            return f"failed: {' '.join(args)} exited {result.returncode} -- {output or 'no output'}"
        return output or f"no output from {' '.join(args)}"

    def flush_dns_cache() -> str:
        if unavailable_fn is not None:
            return unavailable_fn("flushing the DNS cache")
        flush = run([DSCACHEUTIL, "-flushcache"])
        if flush.returncode != 0:
            return f"failed: {flush.stderr.strip()}"
        hup = run(list(privileges.MDNS_HUP))
        if hup.returncode == 0:
            return "ok"
        # dscacheutil succeeds unprivileged, but mDNSResponder is owned by
        # another user (root/_mdnsresponder) -- signaling it without elevated
        # privilege reliably fails. Report what actually happened rather than a
        # blanket failure.
        if is_granted_fn():
            elevated = run([privileges.SUDO, "-n", *privileges.MDNS_HUP])
            if elevated.returncode == 0:
                return "ok (mDNSResponder restarted using the granted privilege)"
            # The grant exists but did not work: the rule may not match, or
            # sudoers.d may not be included. Distinguished from "no grant"
            # because the fix is completely different.
            return (
                "partial: cache flushed, but the granted sudo rule did not restart "
                f"mDNSResponder ({elevated.stderr.strip()})"
            )
        return (
            "partial: dscacheutil cache flushed, but mDNSResponder HUP "
            f"failed ({hup.stderr.strip()}) -- requires elevated privilege. {GRANT_HINT}"
        )

    def needs_privilege_stub(step_name: str) -> str:
        return (
            f"NEEDS_PRIVILEGE: {step_name} needs to run as root, and that has not "
            f"been granted. {GRANT_HINT}"
        )

    def renew_dhcp_lease() -> str:
        if unavailable_fn is not None:
            return unavailable_fn("renewing the DHCP lease")
        # Without a per-interface answer, keep the old order: refuse before the
        # interface lookup, so an ungranted machine spends no subprocess on it.
        if dhcp_granted_fn is None and not is_granted_fn():
            return needs_privilege_stub("renew_dhcp_lease")
        interface = primary_interface_fn()
        if interface is None:
            # primary_interface only returns en* names, so None also means a
            # full-tunnel VPN holds the route on utun, or `route` could not be
            # read. "No interface carries the default route" is false then.
            return (
                "cannot renew: no Ethernet or Wi-Fi interface carries the default "
                "route (there is none, a VPN or other tunnel holds it, or the route "
                "could not be read), so there is no interface to request a lease on"
            )
        if dhcp_granted_fn is not None and not dhcp_granted_fn(interface):
            return needs_privilege_stub("renew_dhcp_lease")
        covered = list(covered_interfaces_fn())
        if (
            covered
            and covered != list(privileges.ALL_INTERFACES_SENTINEL)
            and interface not in covered
        ):
            return needs_privilege_stub(f"renew_dhcp_lease on {interface}")
        # `ipconfig set` de-configures the interface's existing IPv4 service
        # before starting DHCP. On an address set by hand, that swaps the static
        # configuration for DHCP, and on a network with no DHCP server the
        # interface is left with no usable IPv4 until the next network
        # configuration change (man ipconfig). So the renewal only runs on an
        # interface that already holds a lease. `getpacket` is an unprivileged
        # read that prints nothing when DHCP is not active or has no lease.
        packet = run([privileges.IPCONFIG, "getpacket", interface])
        if packet.returncode != 0:
            # A failed read is not evidence of a manual configuration; saying
            # "not using DHCP" here would be a guess.
            return (
                f"failed: could not read the DHCP state of {interface} (ipconfig getpacket "
                f"-- {packet.stderr.strip()}), so it is unknown whether renewing would "
                "replace a configuration set by hand. Nothing was changed."
            )
        if not _LEASE_LINE.search(packet.stdout or ""):
            return (
                f"cannot renew: {interface} holds no DHCP lease (ipconfig getpacket shows "
                "none): either it is not configured for DHCP or DHCP has not obtained one, and "
                f"ipconfig set {interface} DHCP would replace a configuration set by hand. "
                "Nothing was changed."
            )
        result = run([privileges.SUDO, "-n", privileges.IPCONFIG, "set", interface, "DHCP"])
        if result.returncode != 0:
            return f"failed: ipconfig set {interface} DHCP -- {result.stderr.strip()}"
        return f"ok: re-requested a DHCP lease on {interface}"

    def toggle_network_service() -> str:
        """Never automated, and not because of privilege. See privileges.py.

        Reported as its own outcome rather than as NEEDS_PRIVILEGE so that granting
        permissions does not leave someone waiting for a step that is never going to
        run.
        """
        return (
            "NOT_AUTOMATED: taking an interface down and back up cannot be done as "
            "one command, and doing it as two risks leaving this machine offline "
            "with no network to fix it over if anything interrupts the second one. "
            "Toggle Wi-Fi or the cable by hand if the other steps have not helped."
        )

    def check_interface_state() -> str:
        return report_command([SCUTIL, "--nwi"])

    def check_default_route() -> str:
        return report_command([NETSTAT, "-rn", "-f", "inet"])

    def check_configured_dns_servers() -> str:
        return report_command([SCUTIL, "--dns"])

    def check_resolver_overrides() -> str:
        if not resolver_dir_exists_fn(RESOLVER_DIR):
            return f"no {RESOLVER_DIR} overrides configured"
        try:
            entries = resolver_listdir_fn(RESOLVER_DIR)
        except OSError as exc:
            # Every subprocess path here is wrapped by run(); this one was not.
            # os.listdir can raise PermissionError, or FileNotFoundError via a
            # TOCTOU race with the isdir check above. state_machine's per-step
            # guard would keep the incident alive, but it can only report the
            # exception class; handling it here keeps the reason in the outcome.
            return f"failed: could not read {RESOLVER_DIR} ({exc})"
        if not entries:
            return f"no {RESOLVER_DIR} overrides configured"
        return f"{RESOLVER_DIR} overrides present for: {', '.join(entries)}"

    def resolve_against_public_resolver() -> str:
        answered = query_fn(probe_domain)
        if answered is None:
            # No reply is not a negative answer. Saying "did NOT resolve" here
            # would tell someone DNS is broken everywhere when nothing was learned.
            return (
                f"could not reach the public resolver to test {probe_domain} "
                "(no reply: timed out, no route, or UDP port 53 blocked); this "
                "says nothing about the name"
            )
        if answered:
            return f"{probe_domain} resolved via public resolver"
        return f"{probe_domain} did NOT resolve via public resolver"

    dispatch = {
        "flush_dns_cache": flush_dns_cache,
        "renew_dhcp_lease": renew_dhcp_lease,
        "toggle_network_service": toggle_network_service,
        "check_interface_state": check_interface_state,
        "check_default_route": check_default_route,
        "check_configured_dns_servers": check_configured_dns_servers,
        "check_resolver_overrides": check_resolver_overrides,
        "resolve_against_public_resolver": resolve_against_public_resolver,
    }

    def executor(step: LadderStep, classification: Optional[str] = None) -> str:
        # Failover is the one step that needs to know what it is responding to,
        # because the policy refuses classifications it was not configured for.
        if step.name == "switch_to_backup_network":
            if failover_fn is None:
                return "disabled: network failover is not configured"
            # Not defaulted: "network" is the classification most likely to be
            # permitted, so filling it in would turn a caller's omission into a
            # switch the operator never authorised.
            if not classification:
                return "refused: the failover step needs the classification it is responding to"
            try:
                return failover_fn(classification)
            except Exception as exc:  # noqa: BLE001 - every step reports as a string
                # The one path here that does not go through run(). state_machine
                # has no per-step guard, so an escape aborts the incident unreported.
                return f"failed: the failover step raised {type(exc).__name__}"
        handler = dispatch.get(step.name)
        if handler is None:
            return f"unknown step: {step.name}"
        return handler()

    return executor
