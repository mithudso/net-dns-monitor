from datetime import datetime, timezone

from netdnsmonitor.classifier import Classification
from netdnsmonitor.report import build_report, render_markdown


def _base_kwargs(**overrides):
    kwargs = dict(
        started_at=datetime(2026, 7, 13, 9, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 7, 13, 9, 2, tzinfo=timezone.utc),
        classification=Classification.DNS,
        probe_results={"external_reachable": True, "dns_ok": False},
        log_excerpts=["mDNSResponder: query timed out"],
        ladder_results=[{"name": "flush_dns_cache", "outcome": "ok"}],
        repair_outcome="flush_dns_cache succeeded",
        recheck_ok=True,
        escalation=None,
    )
    kwargs.update(overrides)
    return kwargs


def test_classification_is_serialized_as_plain_string():
    report = build_report(**_base_kwargs())
    assert report["classification"] == "dns"


def test_resolved_reflects_recheck_result():
    resolved = build_report(**_base_kwargs(recheck_ok=True))
    unresolved = build_report(**_base_kwargs(recheck_ok=False))
    assert resolved["resolved"] is True
    assert unresolved["resolved"] is False


def test_duration_seconds_computed_from_started_and_ended():
    report = build_report(**_base_kwargs())
    assert report["duration_seconds"] == 120


def test_summary_mentions_classification_and_resolution():
    resolved = build_report(**_base_kwargs(recheck_ok=True))
    unresolved = build_report(**_base_kwargs(recheck_ok=False))
    assert "dns" in resolved["summary"].lower()
    assert "resolved" in resolved["summary"].lower()
    # "unresolved" contains "resolved", so the line above alone holds for a
    # summary that says the exact opposite of what happened -- hardcoding
    # `resolution_word = "unresolved"` kept the whole suite green while every
    # incident report claimed the incident was never fixed.
    assert "unresolved" not in resolved["summary"].lower()
    assert "unresolved" in unresolved["summary"].lower()


def test_render_markdown_includes_key_sections():
    report = build_report(**_base_kwargs())
    md = render_markdown(report)
    assert "# Network/DNS Incident Report" in md
    assert "## Classification" in md
    assert "## Ladder Steps" in md
    assert "## Log Excerpts" in md
    assert "flush_dns_cache" in md


def test_summary_does_not_claim_a_ladder_ran_when_none_did():
    """UNCLASSIFIED has no ladder (ladder_for returns []), so "after the offline
    troubleshooting ladder ran" described steps that never happened.
    """
    report = build_report(
        **_base_kwargs(
            classification=Classification.UNCLASSIFIED,
            ladder_results=[],
            repair_outcome=None,
        )
    )
    assert "ladder ran" not in report["summary"]
    assert "no offline troubleshooting ladder steps ran" in report["summary"]


def test_summary_still_says_the_ladder_ran_when_steps_ran():
    report = build_report(**_base_kwargs())
    assert "after the offline troubleshooting ladder ran" in report["summary"]
