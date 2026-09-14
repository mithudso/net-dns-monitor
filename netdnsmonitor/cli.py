"""The single command-line entry point.

    python3 -m netdnsmonitor.cli <command>

Every subcommand is a thin shell over a module that is already tested; the
value here is that there is now one place to look instead of a page of
`python3 -c` invocations. `docs/SCRIPTS.md` documented those one-shots because
there was no CLI -- this replaces them.

Output goes through `render_*` functions that take data and return text, so the
formatting is testable without capturing stdout and the menu bar window can
reuse it verbatim.
"""

import argparse
import json
import os
import subprocess
import sys
from typing import Callable, Optional

import yaml

from netdnsmonitor import privileges
from netdnsmonitor.classifier import classify
from netdnsmonitor.commands import BY_KEY, CATALOG, missing_placeholder, resolve
from netdnsmonitor.config import load_config
from netdnsmonitor.failover import (
    BACKUP,
    PREFERRED,
    apply_service_order,
    build_failover,
    default_run,
    failover_probe_targets,
    failover_probe_timeout,
)
from netdnsmonitor.interface_probe import make_interface_prober
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.prober import make_prober
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.service_order import parse_service_order, promote
from netdnsmonitor.status import REACHABILITY
from netdnsmonitor.throughput import make_throughput_meter

DEFAULT_CONFIG_PATH = "~/.config/net-dns-monitor/config.yaml"

# `enabled` is None for a service that is missing from the order. Rendering
# that as OFF names a different fault -- a disabled service -- and sends the
# reader to enable something that does not exist.
ENABLED_LABELS = {True: "on", False: "OFF"}

# Outcomes that mean a ladder step did not do what it is for. `cannot renew:`
# is a lease request that never happened, which is a failure however politely
# it is worded.
LADDER_FAILURE_PREFIXES = ("failed:", "NEEDS_PRIVILEGE:", "partial:", "cannot renew:")


# --- rendering (pure) -------------------------------------------------------


def render_interfaces(rows: list[dict]) -> str:
    """One line per network service. Columns are fixed-width so the output
    lines up in a terminal and in the console window.
    """
    if not rows:
        return "No network services found."
    header = f"{'#':>2}  {'SERVICE':<26} {'DEVICE':<9} {'SVC':<4} {'REACHABLE':<11} {'Mbps':>6}"
    lines = [header, "-" * len(header)]
    for index, row in enumerate(rows, 1):
        speed = row.get("throughput_mbps")
        device = "NOT FOUND" if row.get("found") is False else (row.get("device") or "-")
        lines.append(
            f"{index:>2}  {row['name'][:26]:<26} {device:<9} "
            f"{ENABLED_LABELS.get(row.get('enabled'), '?'):<4} "
            f"{REACHABILITY.get(row.get('reachable'), 'unknown'):<11} "
            f"{('-' if speed is None else format(speed, '.1f')):>6}"
        )
    return "\n".join(lines)


def render_catalog() -> str:
    lines = [f"{'#':>2}  {'KEY':<12} {'COMMAND':<44} ANSWERS", "-" * 100]
    for index, command in enumerate(CATALOG, 1):
        mark = "!" if command.mutates else " "
        admin = " (needs admin)" if command.needs_admin else ""
        lines.append(
            f"{index:>2}{mark} {command.key:<12} {' '.join(command.argv)[:44]:<44} "
            f"{command.answers}{admin}"
        )
        if command.notes:
            lines.append(f"{'':17}note: {command.notes}")
    lines.append("")
    lines.append("!  changes system state -- the console asks before running these.")
    return "\n".join(lines)


def render_usage_guide() -> str:
    return """\
NET/DNS CONSOLE -- what to do when the network breaks

  1. Is anything reachable at all?        run `nwi`, then `ping`
     Nothing reachable            -> a network-layer fault. Go to 3.
     Reachable but names fail     -> a DNS fault. Go to 2.

  2. DNS faults
     `dns`         what resolvers the system is using
     `resolvers`   split-DNS overrides that quietly beat that list
     `dig` vs `dig-direct`  if direct works and the normal one does not,
                   the local resolver is at fault, not the network.
     `flush-dns`   drops the cache (only half a flush -- the rest needs sudo)

  3. Network-layer faults
     `order`       the service priority list. A service marked (*) is
                   DISABLED and is skipped no matter where it sits.
     `routes`      which interface the default route actually points at
     `iface`       is the link up on the interface you expect
     `ping-gw`     if the gateway answers, the fault is upstream of you

  4. Moving to another network
     `i`           every service with live reachability
     `b`           measure throughput per interface before choosing
     `f`           move to the fastest reachable backup   (asks first)
     `p`           move back to the preferred link        (asks first)
     `priority`    show the service order
     `promote <service name>`  move one to the top        (asks first)

  Typing a number or a key from the command list RUNS that command. Anything
  that changes system state asks for confirmation first and shows you the
  exact command before it runs.

  `?` this guide · `c` the command list · `s` failover status · `q` quit."""


def render_failover_status(snapshot: Optional[dict]) -> str:
    if snapshot is None:
        return "Failover: not configured (set failover_preferred_service and at least one backup)."
    if snapshot.get("error"):
        return f"Failover: {snapshot['error']}"
    if snapshot.get("active_side") == BACKUP:
        where = "on the backup"
    elif snapshot.get("active_service") == snapshot["preferred"].get("name"):
        where = "on the preferred link"
    else:
        # `active_side` reports "preferred" for any head of the order that is
        # not a configured backup. Calling a Thunderbolt Bridge or a VPN
        # service "the preferred link" tells the reader a switch-back happened.
        where = "on neither the preferred link nor a backup"
    automatic = "yes" if snapshot["auto_enabled"] else "no (manual only)"
    if snapshot["auto_enabled"] and snapshot.get("failback_paused"):
        # Names the way out as well as the state: while the machine stays on
        # the backup, only a switch back to preferred ends the pause.
        automatic = (
            "yes (failback paused after a manual switch; `netdns failover preferred` ends it)"
        )
    lines = [
        f"Active service : {snapshot['active_service']} ({where})",
        f"Automatic      : {automatic}",
        "",
        render_interfaces([snapshot["preferred"]] + list(snapshot.get("backups") or [])),
    ]
    if snapshot.get("last_event"):
        lines += ["", f"Last switch attempt: {snapshot['last_event']}"]
    return "\n".join(lines)


# --- shared plumbing --------------------------------------------------------


def interface_probe_settings(config: dict) -> tuple[list[tuple], float]:
    """The interface prober's targets and deadline, from the helpers the app's
    own failover prober uses.

    The CLI used to aim this prober at `external_targets`. IP_BOUND_IF bypasses
    a VPN tunnel, so on a tunnelled machine every physical interface read
    unreachable against an internet target: `netdns interfaces` called every
    link dead while `netdns status` showed the preferred one reachable.
    """
    return failover_probe_targets(config), failover_probe_timeout(config)


def build_context(config: dict, run_fn: Callable = default_run):
    targets, timeout = interface_probe_settings(config)
    prober = make_interface_prober(targets=targets, timeout=timeout)
    meter = make_throughput_meter(
        host=config.get("failover_speedtest_host", ""),
        path=config["failover_speedtest_path"],
        port=int(config["failover_speedtest_port"]),
        timeout=float(config["failover_speedtest_timeout_seconds"]),
        max_bytes=int(config["failover_speedtest_max_bytes"]),
    )
    return prober, meter, build_failover(config), run_fn


def list_services(run_fn: Callable) -> list:
    result = run_fn(["networksetup", "-listnetworkserviceorder"])
    if getattr(result, "returncode", 1) != 0:
        return []
    return parse_service_order(getattr(result, "stdout", "") or "")


def run_catalog_command(key: str, values: dict, run_fn: Callable = subprocess.run) -> str:
    """Run one catalogue command and return its output as text.

    Every failure arrives as text rather than an exception: a missing binary, a
    permission error or a timeout are all ordinary results of a diagnostic, and
    a traceback out of the CLI (or out of the console REPL, which would end the
    session) is not a useful way to report one. Each command carries its own
    timeout because `traceroute` legitimately outlives the ladder's 5s ceiling.

    A failure is always the last line and starts `failed:`, which is what
    `cmd_run` turns into its exit code.
    """
    command = BY_KEY.get(key)
    argv = resolve(key, **values)
    if command is None or argv is None:
        return f"failed: cannot build a command for '{key}'"
    header = f"$ {' '.join(argv)}"
    try:
        # A strict decode raises UnicodeDecodeError on one non-UTF-8 byte and
        # loses the whole output. An SSID is arbitrary bytes, so `wdutil info`
        # can legitimately print one.
        result = run_fn(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=command.timeout,
        )
    except subprocess.TimeoutExpired:
        return f"{header}\nfailed: timed out after {command.timeout:.0f}s"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return f"{header}\nfailed: {type(exc).__name__}: {exc}"
    body = (result.stdout or "").rstrip() or (result.stderr or "").rstrip()
    if result.returncode != 0:
        # Output is not success. A mutating command that prints its error and
        # exits nonzero used to leave `netdns run` exiting 0, which reads as a
        # change that happened.
        return f"{header}\n{body or '(no output)'}\nfailed: exit {result.returncode}"
    return f"{header}\n{body or '(no output, exit 0)'}"


def promote_service(run_fn, services, name: str) -> str:
    """Move a service to the top of the order, refusing to claim a no-op.

    A disabled service is skipped by macOS wherever it sits, so promoting one
    changes the stored order and routes nothing. Reporting `ok:` for that is
    exactly the confident-wrong-answer this project forbids, so it is refused
    with the fix named.
    """
    target = next((s for s in services if s.name == name), None)
    if target is None:
        return f"failed: '{name}' not found; available: " + ", ".join(s.name for s in services)
    if not target.enabled:
        return (
            f"failed: '{name}' is DISABLED, so promoting it would change the order "
            "and route nothing. Enable it first: "
            f"netdns run enable --value service='{name}' --yes"
        )
    new_order = promote(services, name)
    if new_order is None:
        return f"failed: '{name}' disappeared mid-check"
    return apply_service_order(run_fn, services, new_order)


def interface_rows(run_fn, prober, meter=None, measure: bool = False) -> list[dict]:
    rows = []
    for service in list_services(run_fn):
        reachable = prober(service.device)
        rows.append(
            {
                "name": service.name,
                "device": service.device,
                "enabled": service.enabled,
                "reachable": reachable,
                # Benchmarking a path that carries nothing is seconds spent for no
                # information, so it is skipped unless the probe succeeded.
                "throughput_mbps": (
                    meter(service.device) if measure and meter and reachable is True else None
                ),
            }
        )
    return rows


# --- subcommands ------------------------------------------------------------


def cmd_interfaces(args, config, out) -> int:
    prober, meter, _, run_fn = build_context(config)
    rows = interface_rows(run_fn, prober, meter, measure=args.bench)
    out(json.dumps(rows, indent=2) if args.json else render_interfaces(rows))
    return 0


def cmd_bench(args, config, out) -> int:
    prober, meter, _, run_fn = build_context(config)
    rows = interface_rows(run_fn, prober, meter, measure=True)
    out(json.dumps(rows, indent=2) if args.json else render_interfaces(rows))
    return 0


def cmd_status(
    args,
    config,
    out,
    context: Optional[tuple] = None,
    probe_fn: Optional[Callable[[], dict]] = None,
) -> int:
    _, _, failover, _ = context or build_context(config)
    if probe_fn is None:
        probe_fn = make_prober(
            external_targets=[tuple(t) for t in config["external_targets"]],
            internal_targets=[tuple(t) for t in config["internal_targets"]],
            domains=list(config.get("domains") or [])
            + ([config["control_domain"]] if config.get("control_domain") else []),
            timeout=float(config.get("probe_timeout_seconds", 2.0)),
        )
    probe = probe_fn()
    classification = classify(probe.get("external_reachable"), probe.get("dns_ok"))
    # Decided before the output mode: `status --json` used to exit 0 through an
    # incident, so a script checking `$?` saw a healthy network.
    code = 0 if classification.value == "healthy" else 1
    if args.json:
        out(
            json.dumps(
                {
                    "classification": classification.value,
                    "probe": probe,
                    "failover": failover.snapshot() if failover else None,
                },
                indent=2,
            )
        )
        return code
    out(f"Classification : {classification.value}")
    out(f"External       : {probe.get('external_reachable')}")
    out(f"DNS            : {probe.get('dns_ok')}")
    for domain, ok in (probe.get("domain_results") or {}).items():
        out(f"  {domain:<28} {'ok' if ok else 'FAILED'}")
    out("")
    out(render_failover_status(failover.snapshot() if failover else None))
    return code


def cmd_failover(args, config, out, context: Optional[tuple] = None) -> int:
    _, _, failover, _ = context or build_context(config)
    if failover is None:
        out(render_failover_status(None))
        return 2
    if args.action == "status":
        out(render_failover_status(failover.snapshot()))
        return 0
    target = BACKUP if args.action == "backup" else PREFERRED
    outcome = failover.switch_now(target, service=args.service)
    out(outcome)
    # Only `no switch: already on` means the machine is where it was asked to
    # be, and that is not an error. Every other `no switch:` is a refusal (a
    # third service at the head of the order, a switch already in progress),
    # so `netdns failover preferred && ...` must not carry on as if it worked.
    return 0 if outcome.startswith(("ok:", "no switch: already on")) else 1


def cmd_priority(args, config, out) -> int:
    _, _, _, run_fn = build_context(config)
    services = list_services(run_fn)
    if not services:
        out("failed: could not read the network service order")
        return 1
    if not args.promote:
        out(
            render_interfaces(
                [
                    {
                        "name": s.name,
                        "device": s.device,
                        "enabled": s.enabled,
                        "reachable": None,
                        "throughput_mbps": None,
                    }
                    for s in services
                ]
            )
        )
        return 0
    outcome = promote_service(run_fn, services, args.promote)
    out(outcome)
    return 0 if outcome.startswith("ok:") else 1


def _dhcp_granted(interface: str) -> bool:
    return privileges.covers(
        privileges.granted_commands_now(), (privileges.IPCONFIG, "set", interface, "DHCP")
    )


def _ladder_does_not_switch(_classification: str) -> str:
    return "skipped: the CLI ladder does not switch networks; use `netdns failover backup`"


def cmd_ladder(
    args,
    config,
    out,
    executor_factory: Callable = make_repair_executor,
    failover_configured: Optional[bool] = None,
) -> int:
    if failover_configured is None:
        failover_configured = build_failover(config) is not None
    executor = executor_factory(
        # The same privilege probes app.py passes. The executor's defaults
        # describe an ungranted machine, so without these a user who had
        # installed the grant was told it "has not been granted".
        is_granted_fn=privileges.is_granted,
        primary_interface_fn=privileges.primary_interface,
        # Per interface, as app.py passes it: a grant made before a dock or USB
        # adapter appeared does not cover the interface that now holds the route.
        dhcp_granted_fn=_dhcp_granted,
        # A hand-run diagnostic does not move the machine to another network;
        # `netdns failover backup` is the command that does, and says so.
        failover_fn=_ladder_does_not_switch if failover_configured else None,
    )
    classification = classify(False, False) if args.layer == "network" else classify(True, False)
    failed = False
    for step in ladder_for(classification):
        if step.kind != "check" and not args.repair:
            out(f"{step.name}: SKIPPED (repair; pass --repair to run it)")
            continue
        outcome = executor(step, classification.value) or ""
        first = outcome.splitlines()
        out(f"{step.name}: {first[0] if first else outcome}")
        failed = failed or outcome.startswith(LADDER_FAILURE_PREFIXES)
    return 1 if failed else 0


def cmd_run(args, config, out, run_fn: Callable = subprocess.run) -> int:
    """Run one catalogue command by key."""
    command = BY_KEY.get(args.key)
    if command is None:
        out(f"unknown command '{args.key}'. Known: " + ", ".join(BY_KEY))
        return 2
    missing = missing_placeholder(args.key, **dict(args.value or []))
    if missing:
        out(f"'{args.key}' needs a {missing}: pass --value {missing}=<x>")
        return 2
    if command.mutates and not args.yes:
        out(
            f"'{args.key}' changes system state ({' '.join(command.argv)}). "
            "Re-run with --yes to confirm."
        )
        return 2
    text = run_catalog_command(args.key, dict(args.value or []), run_fn=run_fn)
    out(text)
    if command.notes:
        # The caveat belongs with the result: `flush-dns` exits 0 having done
        # half a flush, and the bare success reads as the whole repair.
        out(f"note: {command.notes}")
    return 1 if text.splitlines()[-1].startswith("failed:") else 0


def cmd_commands(args, config, out) -> int:
    out(render_catalog())
    return 0


def cmd_guide(args, config, out) -> int:
    out(render_usage_guide())
    return 0


def cmd_console(args, config, out) -> int:
    from netdnsmonitor.cli_console import run_console

    return run_console(config, out=out)


# --- parser -----------------------------------------------------------------


def _key_value(text: str):
    key, _, value = text.partition("=")
    return (key, value)


def build_parser() -> argparse.ArgumentParser:
    # Shared options work before and after the subcommand. Declared only on the
    # top-level parser, `netdns status --json` is an error, which is the
    # opposite of what anyone types. They are declared twice because argparse
    # copies every attribute a subparser sets onto the shared namespace: a real
    # default on the subparser overwrote the value typed before the subcommand,
    # so `netdns --config X status` loaded the default config. SUPPRESS on the
    # subparser copy sets nothing unless the option is given there.
    top_level = argparse.ArgumentParser(add_help=False)
    top_level.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    top_level.add_argument("--json", action="store_true", help="machine-readable output")

    after_subcommand = argparse.ArgumentParser(add_help=False)
    after_subcommand.add_argument("--config", default=argparse.SUPPRESS)
    after_subcommand.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="machine-readable output"
    )

    parser = argparse.ArgumentParser(
        prog="netdns",
        description="Network and DNS monitor: diagnose, benchmark, fail over.",
        parents=[top_level],
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add(name, **kwargs):
        return sub.add_parser(name, parents=[after_subcommand], **kwargs)

    p = add("status", help="classification, probe results and failover state")
    p.set_defaults(func=cmd_status)

    p = add("interfaces", help="every network service, live")
    p.add_argument("--bench", action="store_true", help="also measure throughput")
    p.set_defaults(func=cmd_interfaces)

    p = add("bench", help="measure throughput per interface")
    p.set_defaults(func=cmd_bench)

    p = add("failover", help="show or change which network is in use")
    p.add_argument("action", choices=["status", "backup", "preferred"])
    p.add_argument("--service", help="switch to this specific backup")
    p.set_defaults(func=cmd_failover)

    p = add("priority", help="show or change the service order")
    p.add_argument("--promote", help="move this service to the top")
    p.set_defaults(func=cmd_priority)

    p = add("ladder", help="run the troubleshooting ladder")
    p.add_argument("layer", choices=["network", "dns"])
    p.add_argument("--repair", action="store_true", help="also run repair steps")
    p.set_defaults(func=cmd_ladder)

    p = add("commands", help="list the diagnostic command catalogue")
    p.set_defaults(func=cmd_commands)

    p = add("run", help="run one catalogue command")
    p.add_argument("key")
    p.add_argument("--value", action="append", type=_key_value, metavar="NAME=VALUE")
    p.add_argument("--yes", action="store_true", help="confirm a state-changing command")
    p.set_defaults(func=cmd_run)

    p = add("guide", help="what to do when the network breaks")
    p.set_defaults(func=cmd_guide)

    p = add("console", help="interactive console")
    p.set_defaults(func=cmd_console)
    return parser


def main(
    argv: Optional[list[str]] = None,
    out: Callable[[str], None] = print,
    load_config_fn: Callable[[str], dict] = load_config,
) -> int:
    args = build_parser().parse_args(argv)
    # A config the loader refuses is the user's to fix, so it gets one line and
    # exit 2, not a traceback. ConfigError and a non-UTF-8 file are ValueErrors;
    # a YAML syntax error is not.
    try:
        config = load_config_fn(os.path.expanduser(args.config))
    except (ValueError, OSError, yaml.YAMLError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    try:
        return args.func(args, config, out)
    except KeyboardInterrupt:
        out("")
        return 130


if __name__ == "__main__":
    sys.exit(main())
