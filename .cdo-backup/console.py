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

import os
import signal
import subprocess
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

HELP = f"""\
Type any shell command and press Return. Pipes, redirects and quoting all work;
the line goes to /bin/sh exactly as typed.

  :help              this text
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

Useful here: `scutil --dns`, `scutil --nwi`, `dig @8.8.8.8 example.com`,
`networksetup -listallnetworkservices`, `ifconfig`, `netstat -rn`,
`dscacheutil -statistics`, `route get default`."""


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
        try:
            process.kill()
        except OSError:
            pass


def run_command(
    command: str, cwd: str, timeout: float = DEFAULT_TIMEOUT_SECONDS
) -> CommandResult:
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

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        try:
            stdout, stderr = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            # Unkillable (uninterruptible I/O). Report rather than block here:
            # this runs on a worker thread that the window is waiting on.
            stdout, stderr = "", ""
        return CommandResult(stdout, stderr, returncode=-signal.SIGKILL, timed_out=True)

    return CommandResult(stdout, stderr, process.returncode)


def truncate(text: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return text
    kept = encoded[:limit].decode("utf-8", "ignore")
    dropped = len(encoded) - limit
    return (
        f"{kept}\n... [truncated {dropped} more bytes -- redirect to a file "
        "to see all of it]"
    )


def format_result(result, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> str:
    """Render a finished command. Both streams are shown: a failing `dig` puts
    the useful part on stdout and the reason on stderr, and showing only one of
    them is how a console starts lying about what happened.
    """
    stdout = (getattr(result, "stdout", "") or "").rstrip()
    stderr = (getattr(result, "stderr", "") or "").rstrip()
    returncode = getattr(result, "returncode", 0)

    parts = []
    if stdout:
        parts.append(stdout)
    if stderr:
        parts.append(stderr)
    if getattr(result, "timed_out", False):
        parts.append(
            f"[timed out after {timeout:.0f}s -- process group killed]"
        )
    elif returncode:
        parts.append(f"[exit {returncode}]")
    if not parts:
        parts.append("(no output)")
    return truncate("\n".join(parts))


def _change_directory(argument: str, state: ConsoleState) -> str:
    """`cd` cannot be a subprocess: the child's directory dies with the child.

    Resolved against the console's own cwd rather than the app's, so `cd ..`
    means what it looks like on the second use as well as the first.
    """
    target = os.path.expanduser(argument.strip() or "~")
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
            return status(), state
        except Exception as exc:  # noqa: BLE001 - a console must not die on a report
            return f"failed to read monitor state: {type(exc).__name__}: {exc}", state
    if lowered.startswith(":"):
        return f"unknown built-in: '{text}'. `:help` lists them.", state

    state.history.append(text)

    if lowered == "cd" or lowered.startswith("cd "):
        return _change_directory(text[2:], state), state

    result = runner(text, state.cwd, timeout)
    return format_result(result, timeout), state
