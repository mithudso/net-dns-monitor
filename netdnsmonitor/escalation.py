"""Gate and sanitize the hand-off to the Anthropic API. Escalation only fires
after the offline ladder has run its course and a repair attempt (or an
explicit N/A) still leaves the incident unresolved — never on first failure,
which would escalate transient blips.

Whatever is sent is redacted first by exact, case-sensitive string replacement
against the caller-supplied ``sensitive_strings`` list (see ``redact``): only
strings the operator has explicitly configured are stripped. That list ships
empty (config.py), so **by default nothing is removed** — an operator who
needs internal hostnames/IPs or the visited-domain list kept off the wire must
populate ``sensitive_strings``. The previous wording here promised those
"should never leave the machine" unconditionally, which the mechanism does not
deliver: with the shipped default, unified-log excerpts and ``scutil --dns``
output go to the API verbatim.
"""

import re
from typing import Any, Optional

REDACTED = "[REDACTED]"


def redact(value: Any, sensitive_strings: Optional[list[str]]) -> Any:
    # One alternation, longest needle first, instead of sequential
    # str.replace: replacing "internal" before "internal-db.acme.com" left
    # "[REDACTED]-db.acme.com" on the wire. The empty string is dropped because
    # replace("", x) inserts x between every character, and entries are str()'d
    # because a YAML list such as [8443] yields ints, whose TypeError escaped the
    # incident pipeline and lost the report.
    needles = sorted(
        {str(s) for s in (sensitive_strings or ()) if s is not None and str(s) != ""},
        key=len,
        reverse=True,
    )
    pattern = re.compile("|".join(map(re.escape, needles))) if needles else None
    return _redact(value, pattern)


def _redact(value: Any, pattern: Optional["re.Pattern[str]"]) -> Any:
    if isinstance(value, str):
        return pattern.sub(REDACTED, value) if pattern is not None else value
    if isinstance(value, dict):
        # Keys are redacted too: probe_results.domain_results is keyed by
        # domain, so value-only redaction sent every configured hostname as a
        # key. Two sensitive keys can collapse to the same placeholder, and a
        # plain comprehension would then drop one entry's evidence silently.
        out = {}
        for k, v in value.items():
            key = _redact(k, pattern) if isinstance(k, str) else k
            if key in out:
                n = 2
                while f"{key} ({n})" in out:
                    n += 1
                key = f"{key} ({n})"
            out[key] = _redact(v, pattern)
        return out
    if isinstance(value, list):
        return [_redact(item, pattern) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact(item, pattern) for item in value)
    return value


def should_escalate(
    *, ladder_completed: bool, repair_attempted_or_na: bool, recheck_ok: bool
) -> bool:
    return ladder_completed and repair_attempted_or_na and not recheck_ok
