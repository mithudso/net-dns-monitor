"""The interactive console: `netdns console`.

A REPL over the same catalogue, interface model and renderers the CLI uses, so
nothing here reimplements a decision. The loop itself is one pure function --
`handle` takes an input line and the current state and returns text plus the
next state -- which is what makes a terminal REPL testable without a terminal,
and what will let the menu bar window drive the same logic later.

Two rules the loop enforces that a bare shell prompt would not:

* A command marked `mutates` is never run on a bare keypress. Picking `12` from
  a list should not silently disable a network service.
* A command with an unfilled placeholder is not run with a literal `{device}`
  in it -- it asks for the value instead.
"""

import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from netdnsmonitor.cli import (
    build_context,
    interface_rows,
    render_catalog,
    render_failover_status,
    render_interfaces,
    render_usage_guide,
)
from netdnsmonitor.commands import BY_KEY, CATALOG, missing_placeholder, resolve

PROMPT = "netdns> "

BANNER = """\
Net/DNS console. `?` guide · `i` interfaces · `b` benchmark · `c` commands
`s` failover status · `f` switch to fastest backup · `p` back to preferred
Pick a command by number or key. `q` to quit."""


@dataclass
class ConsoleState:
    """What the loop carries between lines. `pending` is a command waiting for
    a placeholder value or a confirmation.
    """
    pending_key: Optional[str] = None
    pending_needs: Optional[str] = None
    pending_confirm: bool = False
    # A named action (switch to backup / preferred) awaiting confirmation. Kept
    # separate from pending_key because these are not catalogue commands.
    pending_action: Optional[str] = None
    values: dict = field(default_factory=dict)
    quit: bool = False


def _run_argv(argv: Optional[list[str]], runner: Callable) -> str:
    if not argv:
        return "failed: could not build that command."
    result = runner(argv)
    stdout = (getattr(result, "stdout", "") or "").rstrip()
    stderr = (getattr(result, "stderr", "") or "").rstrip()
    body = stdout or stderr or f"(no output, exit {getattr(result, 'returncode', '?')})"
    return f"$ {' '.join(argv)}\n{body}"


def _lookup(token: str):
    """A catalogue entry by key, or by its 1-based position in the listing."""
    if token in BY_KEY:
        return BY_KEY[token]
    if token.isdigit():
        index = int(token) - 1
        if 0 <= index < len(CATALOG):
            return CATALOG[index]
    return None


def handle(line: str, state: ConsoleState, services, runner: Callable) -> tuple[str, ConsoleState]:
    """One input line in, text plus next state out. No I/O of its own."""
    text = line.strip()

    # A pending switch is waiting for confirmation.
    if state.pending_action:
        action = state.pending_action
        values = dict(state.values)
        if text.lower() not in ("y", "yes"):
            return "cancelled.", ConsoleState()
        # Carry the target through so the loop knows what to promote.
        return action, ConsoleState(values=values)

    # A pending command is waiting for something before it may run.
    if state.pending_key:
        command = BY_KEY[state.pending_key]
        if state.pending_needs:
            if not text:
                return "cancelled.", ConsoleState()
            state.values[state.pending_needs] = text
            state.pending_needs = None
            if command.mutates and not state.pending_confirm:
                state.pending_confirm = True
                return (
                    f"'{command.key}' CHANGES SYSTEM STATE:\n"
                    f"  $ {' '.join(resolve(command.key, **state.values))}\n"
                    "Type 'yes' to run it, anything else to cancel.",
                    state,
                )
        if state.pending_confirm:
            if text.lower() not in ("y", "yes"):
                return "cancelled.", ConsoleState()
        argv = resolve(state.pending_key, **state.values)
        return _run_argv(argv, runner), ConsoleState()

    if not text:
        return "", state
    lowered = text.lower()

    if lowered in ("q", "quit", "exit"):
        state.quit = True
        return "bye.", state
    if lowered in ("?", "h", "help", "guide"):
        return render_usage_guide(), state
    if lowered in ("c", "commands"):
        return render_catalog(), state
    if lowered in ("i", "interfaces"):
        return "__INTERFACES__", state
    if lowered in ("b", "bench", "benchmark"):
        return "__BENCH__", state
    if lowered in ("s", "status"):
        return "__STATUS__", state
    if lowered in ("priority", "order"):
        # `order` is also a catalogue key; both land here, which is what a user
        # typing either word means.
        return "__PRIORITY__", state
    if lowered.startswith("promote "):
        target = text.split(" ", 1)[1].strip()
        if not any(s.name == target for s in services or []):
            names = ", ".join(s.name for s in (services or []))
            return f"no service named '{target}'. Available: {names}", state
        return (
            f"Promote '{target}' to the top of the service order?\n"
            "This rewrites the system service order. Type 'yes' to confirm.",
            ConsoleState(
                pending_action="__PROMOTE__", pending_confirm=True,
                values={"service": target},
            ),
        )
    # Switching rewrites the service order and can enable a disabled service.
    # That is a bigger change than anything in the catalogue, so it goes
    # through the same confirmation `flush_dns_cache` does rather than firing
    # on one keypress -- especially since `p` sits next to `?` on a keyboard.
    if lowered in ("f", "fastest", "switch"):
        return (
            "Switch to the fastest reachable BACKUP network?\n"
            "This rewrites the system service order. Type 'yes' to confirm.",
            ConsoleState(pending_action="__SWITCH_BACKUP__", pending_confirm=True),
        )
    if lowered in ("p", "preferred"):
        return (
            "Switch back to the PREFERRED network?\n"
            "This rewrites the system service order. Type 'yes' to confirm.",
            ConsoleState(pending_action="__SWITCH_PREFERRED__", pending_confirm=True),
        )

    command = _lookup(text)
    if command is None:
        return (
            f"unknown: '{text}'. `c` lists commands, `?` for the guide.", state
        )

    values = {}
    # Offer the obvious default for a placeholder from the live service list
    # rather than making the user retype a device name they can see above.
    needs = missing_placeholder(command.key, **values)
    if needs:
        hint = ""
        if needs in ("device", "service") and services:
            sample = ", ".join(
                (s.device if needs == "device" else s.name) or "?" for s in services[:6]
            )
            hint = f" (one of: {sample})"
        return (
            f"'{command.key}' needs a {needs}{hint}. Type it, or blank to cancel.",
            ConsoleState(pending_key=command.key, pending_needs=needs, values=values),
        )
    if command.mutates:
        return (
            f"'{command.key}' CHANGES SYSTEM STATE:\n"
            f"  $ {' '.join(resolve(command.key, **values))}\n"
            "Type 'yes' to run it, anything else to cancel.",
            ConsoleState(pending_key=command.key, pending_confirm=True, values=values),
        )
    return _run_argv(resolve(command.key, **values), runner), state


def run_console(config: dict, out: Callable[[str], None] = print, input_fn=input) -> int:
    """The I/O shell around `handle`. Everything decision-shaped lives above."""
    from netdnsmonitor.cli import list_services

    prober, meter, failover, run_fn = build_context(config)

    # Read once and refresh only when something could have changed it. Calling
    # networksetup on every input line -- blank lines and `?` included -- costs
    # a subprocess each time, and in the menu bar window that runs on the main
    # thread and can stall it for the full 5s ceiling per keystroke.
    cached = {"services": list_services(run_fn)}

    def refresh_services():
        cached["services"] = list_services(run_fn)
        return cached["services"]

    out(BANNER)
    out("")
    out(render_interfaces(interface_rows(run_fn, prober)))
    state = ConsoleState()
    while not state.quit:
        try:
            line = input_fn(PROMPT)
        except (EOFError, KeyboardInterrupt):
            out("")
            return 0
        text, state = handle(line, state, cached["services"], run_fn)

        # The loop owns the handful of actions that need live context; `handle`
        # stays pure and names them instead of performing them.
        if text == "__INTERFACES__":
            refresh_services()
            text = render_interfaces(interface_rows(run_fn, prober))
        elif text == "__BENCH__":
            out("benchmarking reachable interfaces, this takes a few seconds...")
            refresh_services()
            text = render_interfaces(interface_rows(run_fn, prober, meter, measure=True))
        elif text == "__STATUS__":
            text = render_failover_status(failover.snapshot() if failover else None)
        elif text == "__PRIORITY__":
            text = render_interfaces([
                {"name": s.name, "device": s.device, "enabled": s.enabled,
                 "reachable": None, "throughput_mbps": None}
                for s in refresh_services()
            ]) + "\n\nType `promote <service name>` to move one to the top."
        elif text == "__PROMOTE__":
            text = _promote(run_fn, refresh_services(), state.values.get("service"))
            refresh_services()
        elif text in ("__SWITCH_BACKUP__", "__SWITCH_PREFERRED__"):
            side = "backup" if text == "__SWITCH_BACKUP__" else "preferred"
            text = (
                failover.switch_now(side) if failover
                else "failover is not configured."
            )
            refresh_services()
        if text:
            out(text)
    return 0


def _promote(run_fn, services, name: Optional[str]) -> str:
    """Reorder from the console, through the same guarded path the CLI uses."""
    from netdnsmonitor.cli import promote_service

    if not name:
        return "failed: no service named."
    return promote_service(run_fn, services, name)
