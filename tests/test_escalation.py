from netdnsmonitor.escalation import redact, should_escalate


def test_redact_replaces_sensitive_substrings_in_flat_strings():
    bundle = {"note": "lookup failed for internal-db.corp.local"}
    redacted = redact(bundle, sensitive_strings=["internal-db.corp.local"])
    assert "internal-db.corp.local" not in redacted["note"]
    assert "[REDACTED]" in redacted["note"]


def test_redact_walks_nested_lists_and_dicts():
    bundle = {
        "log_excerpts": ["mDNSResponder: query for mail.corp.local timed out"],
        "probe_results": {"internal_target": "mail.corp.local"},
    }
    redacted = redact(bundle, sensitive_strings=["mail.corp.local"])
    assert "mail.corp.local" not in redacted["log_excerpts"][0]
    assert "mail.corp.local" not in redacted["probe_results"]["internal_target"]


def test_redact_leaves_unrelated_values_untouched():
    bundle = {"external_target": "1.1.1.1"}
    redacted = redact(bundle, sensitive_strings=["mail.corp.local"])
    assert redacted["external_target"] == "1.1.1.1"


def test_should_not_escalate_before_ladder_completes():
    assert should_escalate(ladder_completed=False, repair_attempted_or_na=True, recheck_ok=False) is False


def test_should_not_escalate_without_a_repair_attempt_or_na():
    assert should_escalate(ladder_completed=True, repair_attempted_or_na=False, recheck_ok=False) is False


def test_should_not_escalate_when_recheck_resolved_it():
    assert should_escalate(ladder_completed=True, repair_attempted_or_na=True, recheck_ok=True) is False


def test_should_escalate_when_ladder_and_repair_done_but_still_failing():
    assert should_escalate(ladder_completed=True, repair_attempted_or_na=True, recheck_ok=False) is True
