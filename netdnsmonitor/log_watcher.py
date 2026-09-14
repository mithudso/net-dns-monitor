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

LOG_SHOW_TIMEOUT_SECONDS = 10

RunFn = Callable[..., object]


def make_log_watcher(
    run_fn: RunFn = subprocess.run,
    lookback: str = "5m",
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
                timeout=LOG_SHOW_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return no_evidence(f"timed out after {LOG_SHOW_TIMEOUT_SECONDS}s (lookback {lookback})")
        except (subprocess.SubprocessError, OSError, UnicodeError) as exc:
            return no_evidence(f"failed: {type(exc).__name__}")
        if result.returncode != 0:
            return no_evidence(f"exited {result.returncode}")
        return [
            line
            for line in result.stdout.splitlines()
            if any(marker in line.lower() for marker in ERROR_MARKERS)
        ]

    return watcher
