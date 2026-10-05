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

import codecs
import contextlib
import os
import select
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Callable, Optional

PROMPT = "netdns> "

# Long enough for `ping -c 5` or a slow `dig`, short enough that a typo like a
# bare `ping` (which never exits on its own) does not tie up the console.
DEFAULT_TIMEOUT_SECONDS = 20.0

# Bytes, not lines: one `log show` or `cat` of a binary produces a few enormous
# lines, and it is the byte count that wedges the text view.
MAX_OUTPUT_BYTES = 64 * 1024

# A command's shell can exit while a child it started in the background still
# holds the output pipe. Waiting for that child would hold the console line --
# and the worker thread the window is waiting on -- until the child ends on its
# own, so after this short grace the whole process group is killed. The
# consequence is deliberate: a `&` job does not outlive its console line, which
# is the same contract the timeout already states.
ORPHAN_GRACE_SECONDS = 0.5
# After the group kill, readers still alive are held by a child that left the
# session (setsid) and so survived it. They get this long to see EOF, then a stop
# event ends them; each bound is shared by both readers, not paid per reader.
READER_JOIN_SECONDS = 0.5
READER_STOP_SECONDS = 0.5
# How often a reader wakes to look at the stop event while its pipe is quiet.
READER_POLL_SECONDS = 0.1


class ClearSignal(str):
    """The "empty the transcript" instruction from `handle`.

    A str subclass, checked with `isinstance`, because a plain string sentinel
    is indistinguishable from a command that happens to print the same text: a
    `curl` of a page whose body is "__CLEAR__" would wipe the transcript.
    """


# The window clears its own text storage; `handle` only says that it should.
CLEAR = ClearSignal("__CLEAR__")

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
     - Description: Runs the offline test suite covering the entire decision surface.

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
  * a background job (`&`) still holding the output when the shell exits is
    killed with it. Redirect its output (`cmd > file 2>&1 &`) to keep it running.
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
    # Bytes the runner read and discarded past its per-stream cap, so the
    # rendering can say the output is incomplete.
    dropped_stdout: int = 0
    dropped_stderr: int = 0


@dataclass
class ConsoleState:
    """What the loop carries between lines."""

    cwd: str = field(default_factory=lambda: os.path.expanduser("~"))
    history: list = field(default_factory=list)
    closed: bool = False


# Process groups of commands still running, so quitting the app can end them.
# `start_new_session=True` detaches each one from the app's own group, which is
# what stops a stray signal reaching the app -- and also why nothing kills them
# when the app exits unless something is told to.
_LIVE: set[int] = set()
_LIVE_LOCK = threading.Lock()

# What py2app's launcher sets for the bundled interpreter (apptemplate
# src/main.c). A child inheriting PYTHONHOME points the user's `python3`, `pip`
# or `aws` at the app bundle's resources and fails with "No module named
# encodings".
FROZEN_ONLY_ENVIRONMENT = (
    "PYTHONHOME",
    "PYTHONPATH",
    "RESOURCEPATH",
    "ARGVZERO",
    "EXECUTABLEPATH",
    "PYTHONOPTIMIZE",
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "_PY2APP_LAUNCHED_",
)


def child_env(environ: Mapping[str, str], frozen: Optional[str]) -> dict:
    """The environment a console command runs with.

    Unchanged when running from source. Inside the built app, the variables the
    launcher set for its own interpreter are removed, so a command gets the
    user's environment and not the bundle's.
    """
    env = dict(environ)
    if frozen:
        for name in FROZEN_ONLY_ENVIRONMENT:
            env.pop(name, None)
    return env


def kill_running() -> None:
    """Kill every console command still running. Registered for app quit.

    Never raises: it runs while the app is shutting down, where an exception
    has nowhere useful to go.
    """
    with _LIVE_LOCK:
        groups = list(_LIVE)
    for pgid in groups:
        with contextlib.suppress(OSError):
            os.killpg(pgid, signal.SIGKILL)


def _kill_process_group(process) -> None:
    """`shell=True` plus a timeout kills the shell and leaves its child running.

    `subprocess.run(..., timeout=...)` kills only the process it spawned, which
    for `shell=True` is /bin/sh -- the `ping` underneath survives, detached and
    invisible, one orphan per attempt. Killing the group closes that hole, which
    is why the process is started with `start_new_session=True` in the first
    place: it gives the child a process group of its own to kill, so a stray
    signal cannot reach the menu bar app that spawned it.

    The group id is the shell's pid, not looked up with `getpgid`: once `wait`
    has reaped the shell, `getpgid` on it raises ProcessLookupError even though
    the group still exists and still holds the orphan. The pid cannot be reused
    while the group it names is alive, so it stays the right target.
    """
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        with contextlib.suppress(OSError):
            process.kill()


def _drain(stream, sink: dict, cap: int, stop: threading.Event) -> None:
    """Read a pipe until EOF or `stop`, keeping only the first `cap` characters.

    `communicate()` would accumulate the whole stream in memory: `yes` run for
    the full timeout is a couple of gigabytes, in the address space of a menu
    bar app that is supposed to survive the incident. Draining and discarding
    past the cap keeps memory flat regardless of how much the child produces.

    Discarding rather than simply stopping is deliberate. Stopping would leave
    the child blocked on a full pipe until the timeout killed it, which turns
    every over-long command into a 20-second wait instead of finishing when it
    would have. What was discarded is counted in `sink["raw"]` so the result can
    say so.

    The fd is read with `select` and `os.read`, which return whatever is there
    now. A blocking buffered read waits for EOF, and EOF on this pipe comes only
    when every process holding its write end has gone -- so `sh -c 'sleep 60' &
    echo started` would park the reader on the grandchild's copy of the pipe and
    the `started` that was printed is reported as no output. A child that left
    the session (`setsid`) survives the group kill and holds the pipe open for
    good; the poll is what lets `stop` end this reader anyway. The reader closes
    its own pipe, so nothing closes an fd another thread is reading. The
    incremental decoder keeps a multibyte character split across two reads from
    becoming two replacement characters.

    `cap` counts decoded characters, not bytes. It is a coarse ceiling to keep
    memory flat; `truncate` applies the exact byte cap afterwards.
    """
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        fd = stream.fileno()
        while not stop.is_set():
            ready, _, _ = select.select([fd], [], [], READER_POLL_SECONDS)
            if not ready:
                continue
            raw = os.read(fd, 65536)
            chunk = decoder.decode(raw, not raw)
            if chunk and sink["size"] < cap:
                sink["parts"].append(chunk[: cap - sink["size"]])
            sink["size"] += len(chunk)
            sink["raw"] += len(raw)
            if not raw:
                break
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
            env=child_env(os.environ, getattr(sys, "frozen", None)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        # A deleted cwd is the common one: the directory `cd` accepted can be
        # gone by the time the next command runs.
        return CommandResult(stderr=f"{type(exc).__name__}: {exc}", returncode=127)

    # The session leader's pid is the group id, so the group is killable by it
    # even after the shell itself has exited and been reaped.
    with _LIVE_LOCK:
        _LIVE.add(process.pid)
    try:
        return _collect(process, timeout)
    finally:
        with _LIVE_LOCK:
            _LIVE.discard(process.pid)


def _join_all(readers: list, seconds: float) -> None:
    """Join every reader against one shared deadline, not `seconds` apiece."""
    deadline = time.monotonic() + seconds
    for reader in readers:
        reader.join(timeout=max(0.0, deadline - time.monotonic()))


def _collect(process, timeout: float) -> CommandResult:
    stop = threading.Event()
    sinks = {
        "stdout": {"parts": [], "size": 0, "raw": 0},
        "stderr": {"parts": [], "size": 0, "raw": 0},
    }
    streams = {"stdout": process.stdout, "stderr": process.stderr}
    readers = [
        threading.Thread(
            target=_drain, args=(streams[name], sinks[name], MAX_OUTPUT_BYTES, stop), daemon=True
        )
        for name in ("stdout", "stderr")
    ]
    started = []
    try:
        for reader in readers:
            reader.start()
            started.append(reader)
    except BaseException as exc:
        # Without readers nothing drains the pipes, and the child would run on
        # unobserved after this frame is gone. Kill it before anything propagates;
        # the caller's `finally` then drops it from _LIVE, which is only true once
        # it is dead.
        _kill_process_group(process)
        with contextlib.suppress(subprocess.TimeoutExpired, OSError):
            process.wait(timeout=5)
        stop.set()
        for name, reader in zip(("stdout", "stderr"), readers, strict=True):
            if reader not in started:
                with contextlib.suppress(ValueError, OSError):
                    streams[name].close()
        if not isinstance(exc, Exception):
            raise
        return CommandResult(
            stderr=f"could not start output readers: {type(exc).__name__}", returncode=127
        )

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
    # some before it was killed. A reader still alive after the grace is held
    # open by a background child of the shell, and killing the group releases it.
    # One that is still alive after that was started in another session; the
    # stop event ends it, and it winds down on its own schedule after this
    # returns.
    _join_all(readers, ORPHAN_GRACE_SECONDS)
    if any(reader.is_alive() for reader in readers):
        _kill_process_group(process)
        _join_all(readers, READER_JOIN_SECONDS)
    if any(reader.is_alive() for reader in readers):
        stop.set()
        _join_all(readers, READER_STOP_SECONDS)

    def dropped(name: str) -> int:
        kept = len("".join(sinks[name]["parts"]).encode("utf-8", "replace"))
        return max(0, sinks[name]["raw"] - kept)

    return CommandResult(
        stdout="".join(sinks["stdout"]["parts"]),
        stderr="".join(sinks["stderr"]["parts"]),
        returncode=returncode,
        timed_out=timed_out,
        dropped_stdout=dropped("stdout"),
        dropped_stderr=dropped("stderr"),
    )


def truncate(text: str, limit: int = MAX_OUTPUT_BYTES, already_dropped: int = 0) -> str:
    """Cap `text` at `limit` bytes. `already_dropped` is what an earlier stage
    discarded; it is added to the marker so the count is of the whole stream.
    """
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit and not already_dropped:
        return text
    kept = encoded[:limit].decode("utf-8", "ignore")
    dropped = max(0, len(encoded) - limit) + already_dropped
    return f"{kept}\n... [truncated {dropped} more bytes -- redirect to a file to see all of it]"


def format_result(result, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Render a finished command. Both streams are shown: a failing `dig` puts
    the useful part on stdout and the reason on stderr, and showing only one of
    them is how a console starts lying about what happened.
    """
    stdout = (getattr(result, "stdout", "") or "").rstrip()
    stderr = (getattr(result, "stderr", "") or "").rstrip()
    returncode = getattr(result, "returncode", 0)

    # Each stream is capped on its own. A joint cap kept the first 64 KB of
    # "stdout then stderr", so a command that filled stdout lost the stderr line
    # that said why -- the one part worth reading. Whatever one stream does not
    # use goes to the other.
    out_bytes = len(stdout.encode("utf-8", "replace"))
    err_bytes = len(stderr.encode("utf-8", "replace"))
    half = MAX_OUTPUT_BYTES // 2
    streams = []
    if stdout or getattr(result, "dropped_stdout", 0):
        streams.append(
            truncate(
                stdout,
                max(half, MAX_OUTPUT_BYTES - err_bytes),
                _dropped(result, "dropped_stdout"),
            )
        )
    if stderr or getattr(result, "dropped_stderr", 0):
        streams.append(
            truncate(
                stderr,
                max(half, MAX_OUTPUT_BYTES - out_bytes),
                _dropped(result, "dropped_stderr"),
            )
        )
    body = "\n".join(streams) if streams else "(no output)"

    # The marker is appended *after* truncation, never inside it, so the exit
    # status survives on exactly the noisiest failures, where it matters most.
    if getattr(result, "timed_out", False):
        return f"{body}\n[timed out after {timeout:.0f}s -- process group killed]"
    if returncode:
        return f"{body}\n[exit {returncode}]"
    return body


def _dropped(result, name: str) -> int:
    value = getattr(result, name, 0)
    return value if isinstance(value, int) and value > 0 else 0


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

    # Unquoted the way the shell would, since HELP promises quoting works:
    # `cd "My Folder"` used to look for a directory with quotes in its name.
    # An unbalanced quote, or several words, falls back to the raw text.
    try:
        tokens = shlex.split(argument)
    except ValueError:
        tokens = [argument]
    path = tokens[0] if len(tokens) == 1 else argument
    target = os.path.expanduser(os.path.expandvars(path or "~"))
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
        return truncate(
            "\n".join(f"{i:>{width}}  {entry}" for i, entry in enumerate(state.history, 1))
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
