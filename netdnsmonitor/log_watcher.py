"""Tail macOS's unified log (`log show`) for DNS/network subsystem entries
and filter down to error-like lines, so an incident report carries the log
evidence a human would otherwise have to go dig up themselves.
"""

import subprocess
from typing import Callable

ERROR_MARKERS = ("error", "fail", "timed out", "timeout", "unreachable", "refused")

RunFn = Callable[..., object]


def make_log_watcher(
    run_fn: RunFn = subprocess.run,
    lookback: str = "5m",
):
    predicate = (
        'process == "mDNSResponder" OR eventMessage CONTAINS "DNS" '
        'OR eventMessage CONTAINS "network"'
    )

    def watcher() -> list[str]:
        try:
            result = run_fn(
                ["log", "show", "--style", "compact", "--last", lookback, "--predicate", predicate],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError, UnicodeError):
            return []
        if result.returncode != 0:
            return []
        return [
            line
            for line in result.stdout.splitlines()
            if any(marker in line.lower() for marker in ERROR_MARKERS)
        ]

    return watcher
