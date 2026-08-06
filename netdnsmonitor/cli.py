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

from netdnsmonitor.classifier import classify
from netdnsmonitor.commands import BY_KEY, CATALOG, missing_placeholder, resolve
from netdnsmonitor.config import load_config
from netdnsmonitor.failover import (
    BACKUP,
    PREFERRED,
    apply_service_order,
    default_run,
)
from netdnsmonitor.interface_probe import make_interface_prober
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.prober import make_prober
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.service_order import parse_service_order, promote
from netdnsmonitor.status import REACHABILITY
from netdnsmonitor.throughput import make_throughput_meter

DEFAULT_CONFIG_PATH = "~/.config/net-dns-monitor/config.yaml"


# --- rendering (pure) -------------------------------------------------------


def render_interfaces(rows: list[dict]) -> str:
    """One line per network service. Columns are fixed-width so the output
    lines up in a terminal and in the console window.
    """
    if not rows:
        return "No network services found."
    header = f"{'#':>2}  {'SERVICE':<26} {'DEVICE':<8} {'SVC':<4} {'REACHABLE':<11} {'Mbps':>6}"
    lines = [header, "-" * len(header)]
    for index, row in enumerate(rows, 1):
        speed = row.get("throughput_mbps")
        lines.append(
            f"{index:>2}  {row['name'][:26]:<26} {(row.get('device') or '-'):<8} "
            f"{('on' if row.get('enabled') else 'OFF'):<4} "
            f"{REACHABILITY.get(row.get('reachable'), 'unknown'):<11} "
            f"{('-' if speed is None else format(speed, '.1f')):>6}"
        )
    return "\n".join(lines)


def render_catalog() -> str:
    lines = [f"{'#':>2}  {'KEY':<12} {'COMMAND':<44} ANSWERS", "-" * 100]
    for index, command in enumerate(CATALOG, 1):
        mark = "!" if command.mutates else " "
        lines.append(
            f"{index:>2}{mark} {command.key:<12} {' '.join(command.argv)[:44]:<44} "
            f"{command.answers}"
        )
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
     `interfaces`  every service with live reachability and speed
     `bench`       measure throughput per interface before choosing
     `switch`      move to the fastest reachable backup
     `priority`    reorder services yourself

  Type a number from the command list, or a key like `dns`. `?` for this
  guide, `i` for interfaces, `c` for the command list, `q` to quit."""


def render_failover_status(snapshot: Optional[dict]) -> str:
    if snapshot is None:
        return "Failover: not configured (set failover_preferred_service and at least one backup)."
    if snapshot.get("error"):
        return f"Failover: {snapshot['error']}"
    lines = [
        f"Active service : {snapshot['active_service']} "
        f"({'on the backup' if snapshot['active_side'] == BACKUP else 'on the preferred link'})",
        f"Automatic      : {'yes' if snapshot['auto_enabled'] else 'no (manual only)'}",
        "",
        render_interfaces([snapshot["preferred"]] + list(snapshot.get("backups") or [])),
    ]
    if snapshot.get("last_event"):
        lines += ["", f"Last switch attempt: {snapshot['last_event']}"]
    return "\n".join(lines)


# --- shared plumbing --------------------------------------------------------


def build_context(config: dict, run_fn: Callable = default_run):
    from netdnsmonitor.app import build_failover  # local: avoids importing rumps early

    prober = make_interface_prober(
        targets=[tuple(t) for t in config["external_targets"]],
        timeout=float(config.get("probe_timeout_seconds", 2.0)),
    )
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


def interface_rows(run_fn, prober, meter=None, measure: bool = False) -> list[dict]:
    rows = []
    for service in list_services(run_fn):
        reachable = prober(service.device)
        rows.append({
            "name": service.name,
            "device": service.device,
            "enabled": service.enabled,
            "reachable": reachable,
            # Benchmarking a path that carries nothing is seconds spent for no
            # information, so it is skipped unless the probe succeeded.
            "throughput_mbps": (
                meter(service.device) if measure and meter and reachable is True else None
            ),
        })
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


def cmd_status(args, config, out) -> int:
    prober, meter, failover, run_fn = build_context(config)
    probe = make_prober(
        external_targets=[tuple(t) for t in config["external_targets"]],
        internal_targets=[tuple(t) for t in config["internal_targets"]],
        domains=list(config.get("domains") or []) + (
            [config["control_domain"]] if config.get("control_domain") else []
        ),
        timeout=float(config.get("probe_timeout_seconds", 2.0)),
    )()
    classification = classify(probe.get("external_reachable"), probe.get("dns_ok"))
    if args.json:
        out(json.dumps({
            "classification": classification.value,
            "probe": probe,
            "failover": failover.snapshot() if failover else None,
        }, indent=2))
        return 0
    out(f"Classification : {classification.value}")
    out(f"External       : {probe.get('external_reachable')}")
    out(f"DNS            : {probe.get('dns_ok')}")
    for domain, ok in (probe.get("domain_results") or {}).items():
        out(f"  {domain:<28} {'ok' if ok else 'FAILED'}")
    out("")
    out(render_failover_status(failover.snapshot() if failover else None))
    return 0 if classification.value == "healthy" else 1


def cmd_failover(args, config, out) -> int:
    _, _, failover, _ = build_context(config)
    if failover is None:
        out(render_failover_status(None))
        return 2
    if args.action == "status":
        out(render_failover_status(failover.snapshot()))
        return 0
    target = BACKUP if args.action == "backup" else PREFERRED
    outcome = failover.switch_now(target, service=args.service)
    out(outcome)
    return 0 if outcome.startswith("ok:") else 1


def cmd_priority(args, config, out) -> int:
    _, _, _, run_fn = build_context(config)
    services = list_services(run_fn)
    if not services:
        out("failed: could not read the network service order")
        return 1
    if not args.promote:
        out(render_interfaces([
            {"name": s.name, "device": s.device, "enabled": s.enabled,
             "reachable": None, "throughput_mbps": None}
            for s in services
        ]))
        return 0
    new_order = promote(services, args.promote)
    if new_order is None:
        out(f"failed: '{args.promote}' not found; available: "
            + ", ".join(s.name for s in services))
        return 1
    outcome = apply_service_order(run_fn, services, new_order)
    out(outcome)
    return 0 if outcome.startswith("ok:") else 1


def cmd_ladder(args, config, out) -> int:
    executor = make_repair_executor()
    classification = classify(False, False) if args.layer == "network" else classify(True, False)
    for step in ladder_for(classification):
        if step.kind != "check" and not args.repair:
            out(f"{step.name}: SKIPPED (repair; pass --repair to run it)")
            continue
        outcome = executor(step, classification.value)
        first = (outcome or "").splitlines()
        out(f"{step.name}: {first[0] if first else outcome}")
    return 0


def cmd_run(args, config, out) -> int:
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
        out(f"'{args.key}' changes system state ({' '.join(command.argv)}). "
            "Re-run with --yes to confirm.")
        return 2
    argv = resolve(args.key, **dict(args.value or []))
    out(f"$ {' '.join(argv)}")
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    out((result.stdout or "").rstrip() or (result.stderr or "").rstrip())
    return result.returncode


def cmd_commands(args, config, out) -> int:
    out(render_catalog())
    return 0


def cmd_guide(args, config, out) -> int:
    out(render_usage_guide())
    return 0


def cmd_console(args, config, out) -> int:
    from netdnsmonitor.console import run_console

    return run_console(config, out=out)


# --- parser -----------------------------------------------------------------


def _key_value(text: str):
    key, _, value = text.partition("=")
    return (key, value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netdns", description="Network and DNS monitor: diagnose, benchmark, fail over."
    )
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="classification, probe results and failover state")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("interfaces", help="every network service, live")
    p.add_argument("--bench", action="store_true", help="also measure throughput")
    p.set_defaults(func=cmd_interfaces)

    p = sub.add_parser("bench", help="measure throughput per interface")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("failover", help="show or change which network is in use")
    p.add_argument("action", choices=["status", "backup", "preferred"])
    p.add_argument("--service", help="switch to this specific backup")
    p.set_defaults(func=cmd_failover)

    p = sub.add_parser("priority", help="show or change the service order")
    p.add_argument("--promote", help="move this service to the top")
    p.set_defaults(func=cmd_priority)

    p = sub.add_parser("ladder", help="run the troubleshooting ladder")
    p.add_argument("layer", choices=["network", "dns"])
    p.add_argument("--repair", action="store_true", help="also run repair steps")
    p.set_defaults(func=cmd_ladder)

    p = sub.add_parser("commands", help="list the diagnostic command catalogue")
    p.set_defaults(func=cmd_commands)

    p = sub.add_parser("run", help="run one catalogue command")
    p.add_argument("key")
    p.add_argument("--value", action="append", type=_key_value, metavar="NAME=VALUE")
    p.add_argument("--yes", action="store_true", help="confirm a state-changing command")
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("guide", help="what to do when the network breaks")
    p.set_defaults(func=cmd_guide)

    p = sub.add_parser("console", help="interactive console")
    p.set_defaults(func=cmd_console)
    return parser


def main(argv: Optional[list[str]] = None, out: Callable[[str], None] = print) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(os.path.expanduser(args.config))
    try:
        return args.func(args, config, out)
    except KeyboardInterrupt:
        out("")
        return 130


if __name__ == "__main__":
    sys.exit(main())
