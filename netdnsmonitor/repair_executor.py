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
* `toggle_network_service` is never automated. Down and up cannot be one command,
  and shipping two means a crash in between leaves the machine offline. The stub
  explains that rather than pretending the grant is missing.

`is_granted_fn` and `primary_interface_fn` default to "no privilege, no
interface" rather than to the real probes, so a caller passing a fake `run_fn`
(i.e. every test) gets deterministic behaviour and no extra subprocesses. app.py
passes the real ones in.
"""

import os
import subprocess
from types import SimpleNamespace
from typing import Callable, Optional

from netdnsmonitor import privileges
from netdnsmonitor.dns_query import query_public_dns
from netdnsmonitor.ladder import LadderStep

RunFn = Callable[..., object]

RESOLVER_DIR = "/etc/resolver"

GRANT_HINT = 'Use "Grant elevated permissions" in the app window to allow this.'


def make_repair_executor(
    run_fn: RunFn = subprocess.run,
    query_fn: Callable[[str], bool] = query_public_dns,
    resolver_dir_exists_fn: Callable[[str], bool] = os.path.isdir,
    resolver_listdir_fn: Callable[[str], list] = os.listdir,
    probe_domain: str = "example.com",
    is_granted_fn: Optional[Callable[[], bool]] = None,
    primary_interface_fn: Optional[Callable[[], Optional[str]]] = None,
):
    is_granted_fn = is_granted_fn or (lambda: False)
    primary_interface_fn = primary_interface_fn or (lambda: None)

    def run(args: list[str]) -> object:
        try:
            return run_fn(
                args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5
            )
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))

    def flush_dns_cache() -> str:
        flush = run(["dscacheutil", "-flushcache"])
        if flush.returncode != 0:
            return f"failed: {flush.stderr.strip()}"
        hup = run(["killall", "-HUP", "mDNSResponder"])
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
        if not is_granted_fn():
            return needs_privilege_stub("renew_dhcp_lease")
        interface = primary_interface_fn()
        if interface is None:
            return (
                "cannot renew: no interface currently carries the default route, so "
                "there is nothing to request a lease on"
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
        result = run(["scutil", "--nwi"])
        return result.stdout.strip() or result.stderr.strip()

    def check_default_route() -> str:
        result = run(["netstat", "-rn", "-f", "inet"])
        return result.stdout.strip() or result.stderr.strip()

    def check_configured_dns_servers() -> str:
        result = run(["scutil", "--dns"])
        return result.stdout.strip() or result.stderr.strip()

    def check_resolver_overrides() -> str:
        if not resolver_dir_exists_fn(RESOLVER_DIR):
            return f"no {RESOLVER_DIR} overrides configured"
        try:
            entries = resolver_listdir_fn(RESOLVER_DIR)
        except OSError as exc:
            # Every subprocess path here is wrapped by run(); this one was not.
            # os.listdir can raise PermissionError, or FileNotFoundError via a
            # TOCTOU race with the isdir check above. state_machine has no
            # per-step guard, so an escape kills the whole incident and no
            # report gets written -- the opposite of this module's contract of
            # reporting each step's outcome as a string.
            return f"failed: could not read {RESOLVER_DIR} ({exc})"
        if not entries:
            return f"no {RESOLVER_DIR} overrides configured"
        return f"{RESOLVER_DIR} overrides present for: {', '.join(entries)}"

    def resolve_against_public_resolver() -> str:
        if query_fn(probe_domain):
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

    def executor(step: LadderStep) -> str:
        handler = dispatch.get(step.name)
        if handler is None:
            return f"unknown step: {step.name}"
        return handler()

    return executor
