"""Dispatch ladder steps (see ladder.py) to real macOS actions.

The logic of each step is a Python script (`netdnsmonitor/remediations/`, edited
and extended through `remediation_scripts.ScriptStore`; see
`docs/REMEDIATION_SCRIPTS.md`). This module is what stays in code: it builds the
`RemediationContext` a script receives -- the only route a script has to the
subprocess, the resolver, the privilege probes and the failover -- and runs the
script for a step. The behaviour described below is the shipped scripts'.

Check steps shell out to read-only system tools and report their output; none of
them mutate system state.

Repair steps that need root used to be stubbed unconditionally. They are now
gated on whether the user has granted the app the specific rights involved --
see privileges.py, which is also where the reasoning about how narrow that grant
is lives:

* `flush_dns_cache` always clears the cache (`dscacheutil` needs no privilege)
  and, with the grant, also sends mDNSResponder a HUP (a signal; the result is
  not read back, so "restarted" would claim more than was observed). Without it, the cache is
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
import subprocess
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Callable, Optional

from netdnsmonitor import privileges
from netdnsmonitor.dns_query import query_public_dns_any
from netdnsmonitor.ladder import LadderStep
from netdnsmonitor.remediation_scripts import (
    DEFAULT_TIMEOUT_SECONDS,
    RunResult,
    ScriptStore,
    execute,
)

RunFn = Callable[..., object]

RESOLVER_DIR = "/etc/resolver"

# Absolute paths, like privileges.py: a menu-bar app's PATH is whatever launchd
# handed it, and a step that resolves its binary through it is one PATH entry away
# from running something else under the same name.
DSCACHEUTIL = "/usr/bin/dscacheutil"
SCUTIL = "/usr/sbin/scutil"
NETSTAT = "/usr/sbin/netstat"

GRANT_HINT = 'Use "Grant elevated permissions" in the app window to allow this.'


@dataclass
class RemediationContext:
    """Everything a remediation script may use. Documented in
    docs/REMEDIATION_SCRIPTS.md; a field added here is documented there.

    A script gets side effects only through this object, which is why the offline
    suite can run every shipped script against fakes.
    """

    step_name: str
    classification: Optional[str]
    probe_domain: str
    tools: SimpleNamespace
    run: Callable[[list], object]
    report_command: Callable[[list], str]
    did_not_complete: Callable[[object], bool]
    query_public_dns: Callable[[str], Optional[bool]]
    resolver_dir_exists: Callable[[str], bool]
    listdir: Callable[[str], list]
    is_granted: Callable[[], bool]
    primary_interface: Callable[[], Optional[str]]
    dhcp_granted: Optional[Callable[[str], bool]]
    covered_interfaces: Callable[[], list]
    failover: Optional[Callable[[str], str]]
    unavailable: Callable[[str], Optional[str]]
    needs_privilege: Callable[[str], str]
    log_lines: list = field(default_factory=list)

    def log(self, message: str) -> None:
        """A note for the editor's test run. Never part of the recorded outcome."""
        self.log_lines.append(str(message))


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
    store: Optional[ScriptStore] = None,
    script_timeout: float = DEFAULT_TIMEOUT_SECONDS,
):
    """`unavailable_fn(what)` marks the privileged repairs as not part of this
    build (the Mac App Store edition may not ask for root). When it is set, those
    steps run nothing and return its text, which never reads as ok, failed or
    NEEDS_PRIVILEGE -- the grant hint would point at a button that build lacks.

    `store` supplies the scripts. The default is the built-ins only, so a caller
    that does not opt in (every test, the CLI) never runs a user's file.
    """
    store = store or ScriptStore()
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
            # returncode None means the command did not run to completion (timed
            # out, binary missing). A made-up exit status 1 read as "ran and was
            # refused", which sent a HUP timeout to the grant button. The class
            # name only: the exception text can carry paths.
            return SimpleNamespace(returncode=None, stdout="", stderr=type(exc).__name__)

    def did_not_complete(result: object) -> bool:
        return result.returncode is None

    def report_command(args: list[str]) -> str:
        """A check step's finding: the tool's output, or an explicit failure.

        A non-zero exit with empty stdout used to be reported as "" -- which the
        report, the LLM bundle and the alert all read as "the tool found nothing",
        when the truth was that the tool did not run.
        """
        result = run(args)
        if did_not_complete(result):
            return f"failed: {args[0]} did not complete ({result.stderr})"
        output = result.stdout.strip() or result.stderr.strip()
        if result.returncode != 0:
            return f"failed: {' '.join(args)} exited {result.returncode} -- {output or 'no output'}"
        return output or f"no output from {' '.join(args)}"

    def needs_privilege_stub(step_name: str) -> str:
        return (
            f"NEEDS_PRIVILEGE: {step_name} needs to run as root, and that has not "
            f"been granted. {GRANT_HINT}"
        )

    def unavailable(what: str) -> Optional[str]:
        return unavailable_fn(what) if unavailable_fn is not None else None

    def build_context(step_name: str, classification: Optional[str]) -> RemediationContext:
        # Read at build time, not import time, so a test that patches the
        # privilege constants sees the patch.
        tools = SimpleNamespace(
            DSCACHEUTIL=DSCACHEUTIL,
            SCUTIL=SCUTIL,
            NETSTAT=NETSTAT,
            SUDO=privileges.SUDO,
            IPCONFIG=privileges.IPCONFIG,
            KILLALL=privileges.KILLALL,
            MDNS_HUP=tuple(privileges.MDNS_HUP),
            ALL_INTERFACES_SENTINEL=tuple(privileges.ALL_INTERFACES_SENTINEL),
            RESOLVER_DIR=RESOLVER_DIR,
            GRANT_HINT=GRANT_HINT,
        )
        return RemediationContext(
            step_name=step_name,
            classification=classification,
            probe_domain=probe_domain,
            tools=tools,
            run=run,
            report_command=report_command,
            did_not_complete=did_not_complete,
            query_public_dns=query_fn,
            resolver_dir_exists=resolver_dir_exists_fn,
            listdir=resolver_listdir_fn,
            is_granted=is_granted_fn,
            primary_interface=primary_interface_fn,
            dhcp_granted=dhcp_granted_fn,
            covered_interfaces=covered_interfaces_fn,
            failover=failover_fn,
            unavailable=unavailable,
            needs_privilege=needs_privilege_stub,
        )

    def run_source(name: str, source: str, classification: Optional[str] = None) -> RunResult:
        """Run `source` as step `name` -- the editor's test run, unsaved text included."""
        return execute(name, source, build_context(name, classification), script_timeout)

    def executor(step: LadderStep, classification: Optional[str] = None) -> str:
        info = store.info(step.name)
        if info is None:
            return f"unknown step: {step.name}"
        if not info.enabled:
            return f"skipped: {step.name} is switched off in its script (ENABLED = False)"
        if info.problems:
            # Honest about the step not having run, rather than falling back to
            # the shipped logic: someone edited this on purpose, and a silent
            # fallback would report a repair their change was meant to replace.
            return (
                f"failed: the {step.name} script is invalid ({info.problems[0]}); "
                "fix or reset it in the remediation editor"
            )
        source = store.source(step.name)
        if source is None:
            return f"failed: the {step.name} script could not be read"
        return run_source(step.name, source, classification).outcome

    executor.run_source = run_source
    executor.store = store
    return executor
