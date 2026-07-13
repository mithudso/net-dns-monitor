"""Gate and sanitize the hand-off to the Anthropic API. Escalation only fires
after the offline ladder has run its course and a repair attempt (or an
explicit N/A) still leaves the incident unresolved — never on first failure,
which would escalate transient blips. Whatever is sent is redacted first:
internal hostnames/IPs and the configured visited-domain list should never
leave the machine.
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
