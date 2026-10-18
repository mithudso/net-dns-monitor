"""renew_dhcp_lease -- ask the DHCP server to renew the primary interface's lease.

Runs `sudo -n ipconfig set <interface> DHCP`, but only when all of these hold:

  1. The privilege grant covers it. `ctx.dhcp_granted(interface)` answers for the
     interface being renewed (the grant lists interfaces one by one); if the app
     did not wire that in, `ctx.is_granted()` stands in. Without it the outcome is
     `NEEDS_PRIVILEGE:` and nothing runs.
  2. `ctx.primary_interface()` names an interface. It returns None when no
     Ethernet or Wi-Fi interface holds the default route (none, or a VPN tunnel
     does), and the outcome is `cannot renew: ...`.
  3. `ipconfig getpacket <interface>` shows a `lease_time` line. `ipconfig set
     ... DHCP` REPLACES the interface's IPv4 configuration, so on an address set
     by hand it would swap that for DHCP and, with no DHCP server, leave the
     interface with no usable IPv4. No lease line -> `cannot renew: ...`, and
     nothing was changed.

Outcomes: `ok: re-requested a DHCP lease on <if>`; `failed: ...` when a read or
the command failed; `unknown: ...` when `ipconfig set` timed out (the request may
or may not have been sent, so neither ok nor failed was observed).

Order matters and is tested: the grant is checked before the interface lookup, so
an ungranted machine spends no subprocess on it.
"""

import re

NAME = "renew_dhcp_lease"
KIND = "repair"
NEEDS_PRIVILEGE = True
REASON = "A stale or conflicting lease is the most common recoverable network-layer fault."
CLASSIFICATIONS = ("network",)
ORDER = 30
ENABLED = True

# RFC 2131 4.3.1: every ACK that grants an address carries a lease time. The ACK
# to an INFORM (an address set by hand that only asks for options) must not
# (4.3.5), so a packet alone does not show the interface is on DHCP; this line does.
_LEASE_LINE = re.compile(r"^lease_time\b", re.MULTILINE)


def run(ctx):
    unavailable = ctx.unavailable("renewing the DHCP lease")
    if unavailable is not None:
        return unavailable
    if ctx.dhcp_granted is None and not ctx.is_granted():
        return ctx.needs_privilege("renew_dhcp_lease")
    interface = ctx.primary_interface()
    if interface is None:
        return (
            "cannot renew: no Ethernet or Wi-Fi interface carries the default "
            "route (there is none, a VPN or other tunnel holds it, or the route "
            "could not be read), so there is no interface to request a lease on"
        )
    if ctx.dhcp_granted is not None and not ctx.dhcp_granted(interface):
        return ctx.needs_privilege("renew_dhcp_lease")
    covered = list(ctx.covered_interfaces())
    if covered and covered != list(ctx.tools.ALL_INTERFACES_SENTINEL) and interface not in covered:
        return ctx.needs_privilege(f"renew_dhcp_lease on {interface}")
    packet = ctx.run([ctx.tools.IPCONFIG, "getpacket", interface])
    if ctx.did_not_complete(packet):
        return (
            f"failed: could not read the DHCP state of {interface} (ipconfig getpacket "
            f"did not complete ({packet.stderr})), so it is unknown whether renewing "
            "would replace a configuration set by hand. Nothing was changed."
        )
    if packet.returncode != 0:
        # A failed read is not evidence of a manual configuration.
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
    result = ctx.run([ctx.tools.SUDO, "-n", ctx.tools.IPCONFIG, "set", interface, "DHCP"])
    if ctx.did_not_complete(result):
        return (
            f"unknown: ipconfig set {interface} DHCP did not complete ({result.stderr}); "
            "the lease request may or may not have been sent"
        )
    if result.returncode != 0:
        return f"failed: ipconfig set {interface} DHCP -- {result.stderr.strip()}"
    return f"ok: re-requested a DHCP lease on {interface}"
