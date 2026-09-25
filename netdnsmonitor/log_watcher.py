"""Tail macOS's unified log (`log show`) for DNS/network subsystem entries
and filter down to error-like lines, so an incident report carries the log
evidence a human would otherwise have to go dig up themselves.

Failure is never an empty list. A timeout returns a marker line saying so,
because [] here reads as "no errors found" and an incident report that
silently carries no log evidence is worse than one that says the read failed.
The marker is bracket-prefixed so `domain_learner` strips it before looking
for hostnames.
"""

import subprocess
from typing import Callable

ERROR_MARKERS = ("error", "fail", "timed out", "timeout", "unreachable", "refused")

# A 30m `log_lookback` measured 10.15s on this machine; 5m measured 2.25s.
TIMEOUT_SECONDS = 10

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

    def watcher() -> list[str]:
        try:
            result = run_fn(
                # Absolute path: a frozen .app does not inherit the shell's
                # PATH, and a bare `log` there is FileNotFoundError.
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
            return [
                "[net-dns-monitor] system log read timed out; no log evidence was "
                "collected for this incident"
            ]
        except (subprocess.SubprocessError, OSError, UnicodeError):
            return []
        # getattr: this runs inside an incident tick, and a result object
        # without these attributes must not raise there.
        if getattr(result, "returncode", 1) != 0:
            return []
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
