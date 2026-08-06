"""Dispatch ladder steps (see ladder.py) to real macOS actions.

Repair steps tagged needs_privilege=True are stubbed rather than executed:
renewing a DHCP lease or toggling a network service needs rights a sandboxed
menu-bar app doesn't have (see the plan's sandbox/privileged-helper decision
in section (g)). Flushing the DNS cache is low-risk and doesn't need that
privilege, so it actually runs. Check steps shell out to read-only system
tools and report their output; none of them mutate system state.
"""

import os
import subprocess
from types import SimpleNamespace
from typing import Callable, Optional

from netdnsmonitor.dns_query import query_public_dns
from netdnsmonitor.ladder import LadderStep

RunFn = Callable[..., object]

RESOLVER_DIR = "/etc/resolver"


def make_repair_executor(
    run_fn: RunFn = subprocess.run,
    query_fn: Callable[[str], bool] = query_public_dns,
    resolver_dir_exists_fn: Callable[[str], bool] = os.path.isdir,
    resolver_listdir_fn: Callable[[str], list] = os.listdir,
    probe_domain: str = "example.com",
    failover_fn: Optional[Callable[[str], str]] = None,
):
    def run(args: list[str]) -> object:
        try:
            return run_fn(args, capture_output=True, text=True, timeout=5)
        except (subprocess.SubprocessError, OSError) as exc:
            return SimpleNamespace(returncode=1, stdout="", stderr=str(exc))

    def flush_dns_cache() -> str:
        flush = run(["dscacheutil", "-flushcache"])
        if flush.returncode != 0:
            return f"failed: {flush.stderr.strip()}"
        hup = run(["killall", "-HUP", "mDNSResponder"])
        if hup.returncode != 0:
            # dscacheutil succeeds unprivileged, but mDNSResponder is owned by
            # another user (root/_mdnsresponder) -- signaling it without
            # elevated privilege reliably fails. Report what actually
            # happened rather than a blanket failure.
            return (
                "partial: dscacheutil cache flushed, but mDNSResponder HUP "
                f"failed ({hup.stderr.strip()}) -- likely requires elevated privilege"
            )
        return "ok"

    def needs_privilege_stub(step_name: str) -> str:
        return f"NEEDS_PRIVILEGE: {step_name} requires an elevated helper (not implemented in this MVP)"

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
        entries = resolver_listdir_fn(RESOLVER_DIR)
        if not entries:
            return f"no {RESOLVER_DIR} overrides configured"
        return f"{RESOLVER_DIR} overrides present for: {', '.join(entries)}"

    def resolve_against_public_resolver() -> str:
        if query_fn(probe_domain):
            return f"{probe_domain} resolved via public resolver"
        return f"{probe_domain} did NOT resolve via public resolver"

    dispatch = {
        "flush_dns_cache": flush_dns_cache,
        "renew_dhcp_lease": lambda: needs_privilege_stub("renew_dhcp_lease"),
        "toggle_network_service": lambda: needs_privilege_stub("toggle_network_service"),
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
            return failover_fn(classification or "network")
        handler = dispatch.get(step.name)
        if handler is None:
            return f"unknown step: {step.name}"
        return handler()

    return executor
