"""Send an already-redacted diagnostic bundle to Claude for a second-pass
root-cause analysis, only reached when the offline ladder + repair + recheck
still leaves the incident unresolved (see escalation.should_escalate).

Uses Haiku 4.5 by default -- this is a bounded-text classification/diagnosis
task, not one needing maximum reasoning depth -- and falls back to Sonnet 5
for the unclassified case, where the offline ladder itself couldn't produce
a clean signal and the harder case likely benefits from stronger reasoning.

Note this escalation only helps for *partial* degradation: it needs enough
working connectivity to reach the Anthropic API at all, so it can never help
during a genuine full outage. That's why the report (report.py) is built
whether or not this succeeds.
"""

from typing import Callable

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
FALLBACK_MODEL = "claude-sonnet-5"

# This call runs on the rumps run loop (app.tick -> state_machine.tick ->
# escalator), so an unbounded request would freeze the menu bar -- the same
# hazard the resolution batch was moved off the run loop to avoid. The SDK's
# own default is on the order of minutes, which is far too long to block a UI.
DEFAULT_TIMEOUT_SECONDS = 30.0


def build_prompt(bundle: dict) -> str:
    return (
        "You are assisting with a macOS network/DNS incident that local, offline "
        "troubleshooting could not resolve. All internal hostnames, IPs, and the "
        "visited-domain list have already been redacted before reaching you.\n\n"
        f"Classification from local triage: {bundle.get('classification')}\n"
        f"Probe results: {bundle.get('probe_results')}\n"
        f"Ladder steps already attempted: {bundle.get('ladder_results')}\n"
        f"Relevant log excerpts: {bundle.get('log_excerpts')}\n\n"
        "Given only this evidence, suggest the most likely root cause and any "
        "next diagnostic step a human could try. Be concise."
    )


def make_escalator(
    client,
    default_model: str = DEFAULT_MODEL,
    fallback_model: str = FALLBACK_MODEL,
    max_tokens: int = 512,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Callable[[dict], dict]:
    def escalator(bundle: dict) -> dict:
        model = fallback_model if bundle.get("classification") == "unclassified" else default_model
        prompt = build_prompt(bundle)
        try:
            response = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                timeout=timeout,
            )
            # Inside the try on purpose. This indexing can raise on its own --
            # an empty `content` list gives IndexError, a non-text first block
            # gives AttributeError -- and outside the guard that propagated
            # through state_machine (which has no per-step guard) and aborted
            # the whole tick, so no incident report was written at all. That
            # directly contradicted this function's contract below.
            analysis = response.content[0].text
        except Exception as exc:  # noqa: BLE001 - report the failure, never crash the pipeline
            return {"error": str(exc), "model": model}
        return {"model": model, "analysis": analysis}

    return escalator


def default_client():
    import anthropic

    return anthropic.Anthropic()
