"""The console's decisions, with no window and no terminal attached.

`handle` takes one input line plus the current state and returns text plus the
next state. That signature is the whole point: an AppKit window cannot be
automated-tested any more than the menu bar can, so anything decided in the
window is decided somewhere untestable. Everything below is exercised by
`tests/test_console.py` with a fake runner and no subprocess at all.

This console runs *arbitrary* shell, deliberately. That is the feature: during
a network incident the useful next command is whatever the person watching
thinks of, not whatever a catalogue anticipated. It runs as your user with your
environment -- the same reach as Terminal.app, no more and no less. There is no
blocklist, because a pattern match over arbitrary shell is theater: it would
miss the dangerous command spelled slightly differently and refuse the safe one
that happens to contain `rm`. The real guards are the ones that hold regardless
of what gets typed: a timeout, a process-group kill so the timeout means
something, no stdin so nothing can hang on a prompt, and an output cap.
"""

import contextlib
import os
import signal
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

PROMPT = "netdns> "

# Long enough for `ping -c 5` or a slow `dig`, short enough that a typo like a
# bare `ping` (which never exits on its own) does not tie up the console.
DEFAULT_TIMEOUT_SECONDS = 20.0

# Bytes, not lines: one `log show` or `cat` of a binary produces a few enormous
# lines, and it is the byte count that wedges the text view.
MAX_OUTPUT_BYTES = 64 * 1024

# The window clears its own text storage; `handle` only says that it should.
CLEAR = "__CLEAR__"

BANNER = """\
Net/DNS console -- arbitrary shell, run as your user in your environment.
`:help` for the built-ins, `:status` for what the monitor currently thinks,
`q` to close this window (the monitor keeps running)."""

SUGGESTED_HELP = """\
Suggested commands and quick usage examples:

  DNS & Resolution:
    scutil --dns                              Show system DNS configuration and resolvers
    dig @8.8.8.8 example.com                  Query Google DNS directly, bypassing local cache
    dig +trace example.com                    Trace DNS resolution from root servers
    dscacheutil -statistics                   View DNS responder cache statistics
    dscacheutil -flushcache                   Flush DNS cache (partial unprivileged)

  Interfaces & Routing:
    scutil --nwi                              Show active network interfaces & default routes
    ifconfig                                  Display network adapter details, IPs, and flags
    netstat -rn -f inet                       Display IPv4 kernel routing table
    route get default                         Show default gateway route details
    networksetup -listallnetworkservices      List all configured macOS network services

  Reachability & Sockets:
    ping -c 4 1.1.1.1                         Ping Cloudflare DNS (4 ICMP packets)
    traceroute 8.8.8.8                        Trace network hops to destination
    curl -Iv https://api.anthropic.com        Test TLS handshake & HTTP response headers
    nc -zv 1.1.1.1 443                        Check TCP socket connection to port 443
    lsof -i -P -n                             List open network sockets and listening ports"""

TOOLS_HELP = """\
Helpful Troubleshooting and Diagnostic Network Tools:

  1. DNS Diagnostic Tools:
     - scutil --dns                         Inspect macOS resolver configuration & search domains.
     - dig @<server> <domain>               Query specific DNS server (e.g. 1.1.1.1 or 8.8.8.8).
     - dig +trace <domain>                  Walk DNS hierarchy from root servers to authoritative name server.
     - nslookup <domain>                    Simple host name lookup tool.
     - dscacheutil -statistics              Check DNS cache hit/miss statistics.
     - dscacheutil -flushcache              Flush local DNS directory service cache.

  2. Interface & Routing Tools:
     - scutil --nwi                         Show Network Information (active interfaces and default IPv4/IPv6 gateways).
     - netstat -rn -f inet                  Print IPv4 routing table.
     - route get default                    Show default route details (interface and gateway address).
     - ifconfig                             Inspect status, MAC address, IP address, and MTU of network interfaces.
     - networksetup -listallnetworkservices List all hardware network interfaces on macOS.

  3. Reachability & Path Diagnostics:
     - ping -c 4 <ip_or_host>               Test ICMP echo reachability (use -c to avoid hanging).
     - traceroute <ip_or_host>              Trace hop-by-hop packet path to isolate network drops.
     - curl -Iv <url>                       Detailed HTTP/HTTPS request, TLS certificate check, and response headers.
     - nc -zv <host> <port>                 Netcat TCP port connectivity test.

  4. Socket & Traffic Monitoring Tools:
     - lsof -i -P -n                        List processes holding open network sockets (numeric ports/IPs).
     - netstat -an                          Display active sockets and listening ports.
     - tcpdump -n -i en0 -c 20              Capture live packets on interface en0 (first 20 packets)."""

SCRIPTS_HELP = """\
Scripts Catalog & Module Entry Points (from SCRIPTS.md):

  1. Menu Bar Application (`app.py`):
     python3 -m netdnsmonitor.app
     - Description: Runs the menu bar app. Polls targets, classifies failures, runs triage ladder, escalates to Claude, writes reports, and sends alerts. Blocks forever.

  2. Test Suite (`pytest`):
     python3 -m pytest -q
     - Description: Runs the 187-test offline test suite covering the entire decision surface.

  3. One-shot Prober (`prober.py`):
     python3 -c "from netdnsmonitor.prober import make_prober; p = make_prober(external_targets=[('1.1.1.1',443)], internal_targets=[], domains=['api.anthropic.com']); print(p())"
     - Description: Scriptable instant reachability & DNS probe. Returns aggregated boolean status dictionary.

  4. One-shot Ladder & Repair (`ladder.py` / `repair_executor.py`):
     python3 -c "from netdnsmonitor.classifier import classify; from netdnsmonitor.ladder import ladder_for; from netdnsmonitor.repair_executor import make_repair_executor; ex = make_repair_executor(); c = classify(True, False); print([f'{s.name}: {ex(s)[:40]}' for s in ladder_for(c) if s.kind == 'check'])"
     - Description: Runs offline diagnostic ladder steps for a given classification by hand.

  5. One-shot Log Watcher (`log_watcher.py`):
     python3 -c "from netdnsmonitor.log_watcher import make_log_watcher; print(len(make_log_watcher(lookback='5m')()))"
     - Description: Tails macOS `log show` for DNS/network subsystem entries and extracts error-like lines.

  6. One-shot Failed Domain Extractor (`domain_learner.py`):
     python3 -c "from netdnsmonitor.log_watcher import make_log_watcher; from netdnsmonitor.domain_learner import extract_failed_domains; print(extract_failed_domains(make_log_watcher(lookback='5m')()))"
     - Description: Extracts failed hostnames from unified log entries for auto-learning.

  7. One-shot Public DNS Query (`dns_query.py`):
     python3 -c "from netdnsmonitor.dns_query import query_public_dns; print(query_public_dns('api.anthropic.com', server='1.1.1.1'))"
     - Description: Bypasses system resolver to perform raw UDP DNS query to a public resolver (e.g. 1.1.1.1 or 8.8.8.8).

  8. One-shot Notification Formatter (`notifications.py`):
     python3 -c "from netdnsmonitor.notifications import format_notification; r = {'classification': 'dns', 'started_at': '2026-08-05T20:31:00+00:00', 'duration_seconds': 12.0, 'resolved': False, 'summary': 'DNS issue', 'repair_outcome': 'partial', 'escalation': None}; print(format_notification(r, '/tmp/report.md'))"
     - Description: Renders exact notification text without sending Slack/email alerts.

  9. Offline State Machine (`state_machine.py`):
     python3 -c "from netdnsmonitor.state_machine import StateMachine; m = StateMachine(prober=lambda: {'external_reachable': True, 'dns_ok': False, 'domain_results': {'api.anthropic.com': False}}, repair_executor=lambda s: 'simulated', escalator=lambda b: {}, log_watcher=lambda: [], failure_threshold=1, success_threshold=1, sensitive_strings=[]); print(m.tick())"
     - Description: Runs the full detect -> classify -> ladder -> recheck -> escalate -> report pipeline offline with fakes."""

HELP = f"""\
Type any shell command and press Return. Pipes, redirects and quoting all work;
the line goes to /bin/sh exactly as typed.

  :help | ?          this text
  :suggested         suggested commands & quick usage examples
  :scripts           description and list of all scripts & usage from SCRIPTS.md
  :tools             list of helpful troubleshooting and diagnostic network tools
  :status            live monitor state (flap gate, last incident, last report)
  :history           lines you have run this session
  :pwd               current directory
  :clear             empty the transcript
  cd <dir>           change directory (a built-in -- a subprocess cannot do it)
  q | :q | :close    close the window; the monitor keeps running

Limits that apply to every command, so that a mistyped one cannot wedge the app:

  * {DEFAULT_TIMEOUT_SECONDS:.0f}s timeout, then the whole process group is killed. A bare
    `ping google.com` never exits on its own; this is what stops it.
  * stdin is /dev/null. Anything that would prompt -- `sudo`, `ssh` -- fails
    with a readable error instead of hanging until the timeout.
  * output is capped at {MAX_OUTPUT_BYTES // 1024} KB. Redirect to a file for more.

Useful commands: `:suggested` lists commands, `:tools` lists diagnostic tools,
`:scripts` lists module entry points from SCRIPTS.md."""


@dataclass
class CommandResult:
    """What a runner returns. Deliberately duck-typed so a test can hand in a
    `SimpleNamespace` the way the rest of this repo's suites do.
    """

    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False


@dataclass
class ConsoleState:
    """What the loop carries between lines."""

    cwd: str = field(default_factory=lambda: os.path.expanduser("~"))
    history: list = field(default_factory=list)
    closed: bool = False


def _kill_process_group(process) -> None:
    """`shell=True` plus a timeout kills the shell and leaves its child running.

    `subprocess.run(..., timeout=...)` kills only the process it spawned, which
    for `shell=True` is /bin/sh -- the `ping` underneath survives, detached and
    invisible, one orphan per attempt. Killing the group closes that hole, which
    is why the process is started with `start_new_session=True` in the first
    place: it gives the child a process group of its own to kill, so a stray
    signal cannot reach the menu bar app that spawned it.
    """
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(OSError):
            process.kill()


def _drain(stream, sink: dict, cap: int) -> None:
    """Read a pipe to the end, keeping only the first `cap` bytes.

    `communicate()` would accumulate the whole stream in memory: `yes` run for
    the full timeout is a couple of gigabytes, in the address space of a menu
    bar app that is supposed to survive the incident. Draining and discarding
    past the cap keeps memory flat regardless of how much the child produces.

    Discarding rather than simply stopping is deliberate. Stopping would leave
    the child blocked on a full pipe until the timeout killed it, which turns
    every over-long command into a 20-second wait instead of finishing when it
    would have.

    `cap` counts characters here, not bytes -- the stream is in text mode. It is
    a coarse ceiling to keep memory flat, not the reported limit; `truncate`
    applies the exact byte cap afterwards.
    """
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            if sink["size"] < cap:
                sink["parts"].append(chunk[: cap - sink["size"]])
            sink["size"] += len(chunk)
    except (ValueError, OSError):
        # The pipe was closed under us by the kill path; whatever was collected
        # before that is still worth showing.
        pass
    finally:
        with contextlib.suppress(ValueError, OSError):
            stream.close()


def run_command(command: str, cwd: str, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> CommandResult:
    """The real runner. The only function here that touches a process."""
    try:
        process = subprocess.Popen(  # noqa: S602 - a shell is the stated feature
            command,
            shell=True,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        # A deleted cwd is the common one: the directory `cd` accepted can be
        # gone by the time the next command runs.
        return CommandResult(stderr=f"{type(exc).__name__}: {exc}", returncode=127)

    sinks = {
        "stdout": {"parts": [], "size": 0},
        "stderr": {"parts": [], "size": 0},
    }
    readers = [
        threading.Thread(
            target=_drain,
            args=(process.stdout, sinks["stdout"], MAX_OUTPUT_BYTES),
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(process.stderr, sinks["stderr"], MAX_OUTPUT_BYTES),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
        try:
            returncode = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Unkillable (uninterruptible I/O). Report rather than block: this
            # runs on a worker thread the window is waiting on.
            returncode = -signal.SIGKILL

    # `wait` reaps the child; joining the readers is what stops a half-read
    # pipe from being reported as empty output on a command that did produce
    # some before it was killed.
    for reader in readers:
        reader.join(timeout=5)

    return CommandResult(
        stdout="".join(sinks["stdout"]["parts"]),
        stderr="".join(sinks["stderr"]["parts"]),
        returncode=returncode,
        timed_out=timed_out,
    )


def truncate(text: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return text
    kept = encoded[:limit].decode("utf-8", "ignore")
    dropped = len(encoded) - limit
    return f"{kept}\n... [truncated {dropped} more bytes -- redirect to a file to see all of it]"


def format_result(result, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Render a finished command. Both streams are shown: a failing `dig` puts
    the useful part on stdout and the reason on stderr, and showing only one of
    them is how a console starts lying about what happened.
    """
    stdout = (getattr(result, "stdout", "") or "").rstrip()
    stderr = (getattr(result, "stderr", "") or "").rstrip()
    returncode = getattr(result, "returncode", 0)

    streams = [stream for stream in (stdout, stderr) if stream]
    body = truncate("\n".join(streams)) if streams else "(no output)"

    # The marker is appended *after* truncation, never inside it. Both streams
    # are capped independently upstream, so a command that floods stdout and
    # stderr hands this twice the cap -- and a marker added before truncating
    # would be the part cut off, losing the exit status on exactly the noisiest
    # failures, which are the ones where it matters most.
    if getattr(result, "timed_out", False):
        return f"{body}\n[timed out after {timeout:.0f}s -- process group killed]"
    if returncode:
        return f"{body}\n[exit {returncode}]"
    return body


# A `cd` line containing any of these is a compound command, not a directory.
SHELL_METACHARACTERS = (";", "&", "|", ">", "<", "`", "$(", "\n")


def _change_directory(argument: str, state: ConsoleState) -> str:
    """`cd` cannot be a subprocess: the child's directory dies with the child.

    Resolved against the console's own cwd rather than the app's, so `cd ..`
    means what it looks like on the second use as well as the first.
    """
    argument = argument.strip()

    # `cd /tmp && ls` is a normal thing to type, and the built-in cannot honour
    # it: handing the whole tail to the directory check reports `no such
    # directory: /tmp && ls`, which reads as "that directory is missing" rather
    # than "this console did not run your second command". Say which it is.
    if any(token in argument for token in SHELL_METACHARACTERS):
        return (
            "cd: this is a built-in and cannot chain -- run the `cd` on its own "
            "line, then the rest."
        )

    target = os.path.expanduser(argument or "~")
    if not os.path.isabs(target):
        target = os.path.join(state.cwd, target)
    target = os.path.normpath(target)
    if not os.path.isdir(target):
        return f"cd: no such directory: {target}"
    state.cwd = target
    return target


def handle(
    line: str,
    state: ConsoleState,
    runner: Callable[..., object] = run_command,
    status: Optional[Callable[[], str]] = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> tuple[str, ConsoleState]:
    """One input line in, text plus next state out. No I/O of its own beyond
    the injected runner, which is what makes every branch below testable.
    """
    text = line.strip()
    if not text:
        return "", state

    lowered = text.lower()

    # `q` closes the window and leaves the timer running. Quitting the whole
    # app on a keystroke would mean losing the monitoring you opened the
    # console to investigate -- the opposite of what the person wants.
    if lowered in ("q", ":q", "quit", ":quit", "exit", ":exit", ":close"):
        state.closed = True
        return "", state
    if lowered in (":help", ":h", "?", ":?"):
        return HELP, state
    if lowered in (":scripts", ":script"):
        return SCRIPTS_HELP, state
    if lowered in (":tools", ":tool"):
        return TOOLS_HELP, state
    if lowered in (":suggested", ":suggest", ":commands", ":cmd", ":cmds"):
        return SUGGESTED_HELP, state
    if lowered == ":clear":
        return CLEAR, state
    if lowered == ":pwd":
        return state.cwd, state
    if lowered == ":history":
        if not state.history:
            return "(nothing yet)", state
        width = len(str(len(state.history)))
        return "\n".join(
            f"{i:>{width}}  {entry}" for i, entry in enumerate(state.history, 1)
        ), state
    if lowered == ":status":
        if status is None:
            return "monitor state is not available from here.", state
        try:
            # Capped like any other output: the domain list it prints is
            # learned from the log at runtime and has no fixed length.
            return truncate(status()), state
        except Exception as exc:  # noqa: BLE001 - a console must not die on a report
            return f"failed to read monitor state: {type(exc).__name__}: {exc}", state
    if lowered.startswith(":"):
        return f"unknown built-in: '{text}'. `:help` lists them.", state

    state.history.append(text)

    # Split on any whitespace rather than testing for `"cd "`: `cd<tab>/etc` is
    # a real thing to type, and a prefix test that only knows about spaces sends
    # it to the shell, where the `cd` succeeds in the child and is lost when the
    # child exits -- a built-in that silently does nothing.
    parts = text.split(None, 1)
    if parts[0].lower() == "cd":
        return _change_directory(parts[1] if len(parts) > 1 else "", state), state

    result = runner(text, state.cwd, timeout)
    return format_result(result, timeout), state
