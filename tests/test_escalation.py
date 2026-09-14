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
    assert (
        should_escalate(ladder_completed=False, repair_attempted_or_na=True, recheck_ok=False)
        is False
    )


def test_should_not_escalate_without_a_repair_attempt_or_na():
    assert (
        should_escalate(ladder_completed=True, repair_attempted_or_na=False, recheck_ok=False)
        is False
    )


def test_should_not_escalate_when_recheck_resolved_it():
    assert (
        should_escalate(ladder_completed=True, repair_attempted_or_na=True, recheck_ok=True)
        is False
    )


def test_should_escalate_when_ladder_and_repair_done_but_still_failing():
    assert (
        should_escalate(ladder_completed=True, repair_attempted_or_na=True, recheck_ok=False)
        is True
    )


def test_redact_removes_a_sensitive_name_used_as_a_dict_key():
    """probe_results.domain_results is keyed by domain, so redacting values
    alone sent every configured hostname to the API as a key.
    """
    bundle = {"probe_results": {"domain_results": {"mail.corp.local": False}}}
    redacted = redact(bundle, sensitive_strings=["mail.corp.local"])
    assert "mail.corp.local" not in str(redacted)
    assert redacted["probe_results"]["domain_results"] == {"[REDACTED]": False}


def test_redact_keeps_every_entry_when_two_keys_collapse_to_one_placeholder():
    """Two sensitive keys both become "[REDACTED]"; a plain dict comprehension
    would silently drop one, and the model would reason over half the evidence.
    """
    bundle = {"a.corp.local": False, "b.corp.local": True}
    redacted = redact(bundle, sensitive_strings=["a.corp.local", "b.corp.local"])
    assert "corp.local" not in str(redacted)
    assert sorted(redacted.values()) == [False, True]


def test_redact_walks_tuples_like_lists():
    redacted = redact({"pair": ("mail.corp.local", 53)}, sensitive_strings=["mail.corp.local"])
    assert redacted["pair"] == ("[REDACTED]", 53)


def test_redact_applies_the_longer_of_two_overlapping_needles():
    """Replacing "internal" first leaves "[REDACTED]-db.acme.com", which leaks
    the rest of the longer secret.
    """
    redacted = redact(
        "lookup internal-db.acme.com failed",
        sensitive_strings=["internal", "internal-db.acme.com"],
    )
    assert redacted == "lookup [REDACTED] failed"


def test_redact_ignores_an_empty_needle():
    """str.replace("", x) inserts x between every character."""
    assert redact("dns ok", sensitive_strings=["", "corp"]) == "dns ok"


def test_redact_accepts_a_non_string_needle():
    """A YAML list such as [8443] yields an int; the TypeError it raised
    escaped the incident pipeline and lost the report.
    """
    assert redact("proxy on port 8443", sensitive_strings=[8443]) == "proxy on port [REDACTED]"
