"""One-shot ICMP ping. This is the 5-second heartbeat that drives the menu bar
stats, the Dock tile, and the network-failed alert.

Deliberately ICMP, even though prober.py avoids ICMP on purpose (widely
filtered and rate-limited, so a filtered target reads as a false "down").
The two answer different questions and a false positive costs different
amounts in each:

  prober.py   decides whether to declare an incident, run the repair ladder,
              and escalate to an LLM. A false positive there flushes DNS
              caches and spends API calls, so it uses TCP-connect against
              *any of several* targets and is debounced by the anti-flap gate.
  this module  is a fast liveness reading of one operator-named target that
              does answer ICMP (8.8.8.8, measured 61ms from this machine). It
              never touches the flap gate, the ladder, or escalation -- it
              only paints the indicators and raises the alert.

So a filtered ICMP path degrades the heartbeat display and can raise a
spurious alert; it cannot trigger a repair. `ping_host` is configurable for
exactly that case.

`/sbin/ping` by absolute path.
The rationale is *not* that a bare name would fail: launchd hands this job
PATH=/usr/bin:/bin:/usr/sbin:/sbin (measured on the running agent), so `ping`,
`netstat`, `ifconfig`, `log`, `open` and `osascript` all resolve there perfectly
well. It is that the path is then explicit and cannot be changed underneath the
app by a login file, a wrapper, or a future launchd default -- and for a tool
whose whole job is diagnosing a broken machine, "which binary did it actually
run" should not be a question.

Flags, and what each one is load-bearing for:
  -c 1     one echo request, then exit. This is polled every few seconds, not
           streamed; without it ping never returns and the worker thread leaks.
  -W <ms>  how long to wait for the reply, in milliseconds on BSD ping.
  -t <s>   ceiling on the whole run, in seconds. This is the flag that
           actually bounds the call -- measured 3.08s against an unroutable
           address with `-t 3` -- which is what keeps a failed ping inside its
           own 5s cadence.

Exit codes are the success signal, measured on this machine: 0 with a reply,
2 when nothing replied, 68 when the name will not resolve.

**IPv6 literals go to `/sbin/ping6`.** `/sbin/ping` on macOS rejects `-6`, and
`ping6` takes neither `-W` nor `-t`: measured against the unroutable
2001:db8::1 it waits 11s before exiting 2. The subprocess timeout is therefore
the only bound on an IPv6 ping, and it is set to the ping timeout itself.
"""

import math
import re
import subprocess
from typing import Callable, Optional

RunFn = Callable[..., object]

PING_BIN = "/sbin/ping"
PING6_BIN = "/sbin/ping6"

# `time<1 ms` is what a sub-millisecond LAN reply prints, so the separator has
# to admit `<` as well as `=`; an `=`-only pattern silently drops those.
RTT_PATTERN = re.compile(r"time[=<]\s*([0-9.]+)\s*ms")


def _parse_rtt_ms(stdout: str) -> Optional[float]:
    match = RTT_PATTERN.search(stdout or "")
    if match is None:
        return None
    try:
        return float(match.group(1))
    except ValueError:  # pragma: no cover - [0-9.]+ admits "." and "1..2"; ping prints %.3f
        return None


def ping_once(
    host: str,
    timeout_seconds: float = 2.0,
    run_fn: RunFn = subprocess.run,
) -> dict:
    """Send a single echo request and report the outcome.

    Returns {"ok": bool, "rtt_ms": float|None, "error": str|None}. Never
    raises for a network outcome: the heartbeat caller is a worker thread
    started from a rumps timer, and an escaping exception there kills the
    heartbeat for the rest of the process's life while the menu bar keeps
    showing the last good reading. A host or timeout that cannot be turned
    into an argv at all raises ValueError instead -- that is a configuration
    fault, not a network reading, and reporting it as "no reply" would send
    someone after a network that was never asked. Both callers (the heartbeat
    worker's guard and the console's ping_now) print it and carry on.

    A reply whose time can't be parsed is still a success -- rtt is display
    only, and treating it as a failure would fire the network-failed alert on a
    network that answered.
    """
    # `ping_host` is user-settable YAML that lands in argv unquoted. A value
    # starting with "-" is consumed by ping as a flag; an embedded NUL raises
    # from subprocess; anything unprintable is not a name. `--` is not the
    # answer here because BSD ping does not honour it consistently.
    if (
        not isinstance(host, str)
        or not host
        or host[0] == "-"
        or " " in host
        or not host.isprintable()
    ):
        raise ValueError(f"ping_host must be a host name or address, got {host!r}")
    # BSD ping reads `-t 0` as "no timeout", the opposite of a short one, so
    # round up rather than truncate. NaN, inf, a string and None all fail
    # here rather than inside the argv build, where the message would name
    # math.ceil instead of the config key.
    try:
        if not timeout_seconds > 0:
            raise ValueError
        hard_timeout = max(1, math.ceil(timeout_seconds))
        wait_ms = int(timeout_seconds * 1000)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(
            f"ping_timeout_seconds must be a positive finite number, got {timeout_seconds!r}"
        ) from None
    if ":" in host:
        # An IPv6 literal (a host name never contains a colon). See the module
        # docstring: ping6 has no timeout flag, so the subprocess timeout is it.
        args = [PING6_BIN, "-c", "1", host]
        run_timeout = timeout_seconds
    else:
        args = [
            PING_BIN,
            "-c",
            "1",
            "-W",
            str(wait_ms),
            "-t",
            str(hard_timeout),
            host,
        ]
        # -t already bounds ping itself; this only covers a ping that
        # ignores it or wedges before it arms.
        run_timeout = hard_timeout + 2

    try:
        result = run_fn(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=run_timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "rtt_ms": None,
            "error": f"no reply from {host} within {timeout_seconds:g}s",
        }
    except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
        return {"ok": False, "rtt_ms": None, "error": str(exc)}

    if result.returncode == 0:
        return {"ok": True, "rtt_ms": _parse_rtt_ms(result.stdout), "error": None}

    stderr = (result.stderr or "").strip()
    return {
        "ok": False,
        "rtt_ms": None,
        "error": stderr.splitlines()[0] if stderr else f"no reply from {host}",
    }
