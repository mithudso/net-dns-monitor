"""Mine the macOS unified log for the domains actually being queried, so the
resolution monitor can check the sites this machine cares about instead of a
hand-maintained list. Reuses `log show`'s raw text output (same command
`log_watcher.py` uses for error excerpts) but with a broader predicate --
here we want every DNS query line, not just the failures.

Domain extraction is a regex over raw log text, not a parse of mDNSResponder's
internal log format (which isn't stable across macOS versions and isn't
something we can verify from outside Apple). The regex is deliberately
conservative: it requires a dotted hostname and rejects an all-numeric final
label so IPv4 addresses in "reply from 10.0.0.1 for corp.local" don't get
counted as queried domains.
"""

import re
import subprocess
from collections import Counter
from typing import Callable

RunFn = Callable[..., object]

_DOMAIN_RE = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63})\b"
)


def extract_top_domains(lines: list[str], limit: int = 50) -> list[str]:
    counts: Counter = Counter()
    for line in lines:
        for match in _DOMAIN_RE.finditer(line):
            counts[match.group(1).rstrip(".")] += 1
    return [domain for domain, _ in counts.most_common(limit)]


def make_query_log_reader(
    run_fn: RunFn = subprocess.run,
    lookback: str = "1h",
):
    predicate = 'process == "mDNSResponder" OR eventMessage CONTAINS "DNS"'

    def reader() -> list[str]:
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
                timeout=10,
            )
        except (subprocess.SubprocessError, OSError, UnicodeError):
            return []
        if result.returncode != 0:
            return []
        return result.stdout.splitlines()

    return reader
