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

from typing import Any


def redact(value: Any, sensitive_strings: list[str]) -> Any:
    if isinstance(value, str):
        redacted = value
        for needle in sensitive_strings:
            redacted = redacted.replace(needle, "[REDACTED]")
        return redacted
    if isinstance(value, dict):
        return {k: redact(v, sensitive_strings) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, sensitive_strings) for item in value]
    return value


def should_escalate(
    *, ladder_completed: bool, repair_attempted_or_na: bool, recheck_ok: bool
) -> bool:
    return ladder_completed and repair_attempted_or_na and not recheck_ok
