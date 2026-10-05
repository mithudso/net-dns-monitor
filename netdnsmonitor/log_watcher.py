"""Tail macOS's unified log (`log show`) for DNS/network subsystem entries
and filter down to error-like lines, so an incident report carries the log
evidence a human would otherwise have to go dig up themselves.

An empty list means `log show` ran and no line matched. When the log could not
be read at all -- a timeout, a nonzero exit, a missing binary, a decode error --
the watcher returns one line starting with `NO_EVIDENCE_PREFIX` instead. It used
to return `[]` for those too, and a 30m lookback measured 10.15s against the
10s limit: the report then showed an empty excerpt section that read as a quiet
network. The line carries the exception class name only, never its message,
because the excerpts go into the LLM bundle.
"""

import subprocess
from typing import Callable

ERROR_MARKERS = ("error", "fail", "timed out", "timeout", "unreachable", "refused")

# Starts every line this module writes itself, so no reader mistakes it for a
# line the unified log produced. domain_learner skips lines with this prefix.
NO_EVIDENCE_PREFIX = "[net-dns-monitor]"

# A 30m `log_lookback` measured 10.15s on this machine; 5m measured 2.25s.
LOG_SHOW_TIMEOUT_SECONDS = 10
TIMEOUT_SECONDS = LOG_SHOW_TIMEOUT_SECONDS

# 424 error-like lines at 5m, 3,942 at 30m -- and the whole list goes into the
# escalation prompt, where it overflows the context and the reply comes back as
# an error nobody reads. Keep the newest.
MAX_LINES = 500

RunFn = Callable[..., object]


def make_log_watcher(
    run_fn: RunFn = subprocess.run,
    lookback: str = "5m",
    timeout: float = TIMEOUT_SECONDS,
    max_lines: int = MAX_LINES,
):
    predicate = (
        'process == "mDNSResponder" OR eventMessage CONTAINS "DNS" '
        'OR eventMessage CONTAINS "network"'
    )

    def no_evidence(reason: str) -> list[str]:
        return [f"{NO_EVIDENCE_PREFIX} no log evidence: log show {reason}"]

    def watcher() -> list[str]:
        try:
            result = run_fn(
                # Absolute path, as in system_log.py: a frozen .app launched via
                # `open` does not inherit the shell's PATH.
                [
                    "/usr/bin/log",
                    "show",
                    "--style",
                    "compact",
                    "--last",
                    lookback,
                    "--predicate",
                    predicate,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return no_evidence(f"timed out after {timeout}s (lookback {lookback})")
        except (subprocess.SubprocessError, OSError, ValueError, TypeError) as exc:
            return no_evidence(f"failed: {type(exc).__name__}")
        # getattr: this runs inside an incident tick, and a result object without
        # these attributes must not raise there.
        if getattr(result, "returncode", 1) != 0:
            return no_evidence(f"exited {getattr(result, 'returncode', '?')}")
        stdout = getattr(result, "stdout", "") or ""
        lines = [
            line
            for line in stdout.splitlines()
            if any(marker in line.lower() for marker in ERROR_MARKERS)
        ]
        if len(lines) > max_lines:
            return [
                f"[net-dns-monitor] {len(lines) - max_lines} earlier error-like lines "
                "omitted; narrow log_lookback for the full set"
            ] + lines[-max_lines:]
        return lines

    return watcher
