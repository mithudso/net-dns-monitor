import json
from datetime import datetime, timezone

from netdnsmonitor import ai_consent
from netdnsmonitor.ai_consent import CONSENT_VERSION, ConsentStore, gate_escalator

FIXED = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


def read_record(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def write_raw(path, text):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)


def consent(tmp_path):
    return ConsentStore(path=str(tmp_path / "support" / "ai-consent.json"), clock=lambda: FIXED)


def test_no_record_means_no_permission(tmp_path):
    assert consent(tmp_path).granted() is False


def test_granting_is_recorded_with_version_recipient_and_time(tmp_path):
    store = consent(tmp_path)
    assert store.grant() == "ok: permission granted"
    assert store.granted() is True
    record = read_record(store.path)
    assert record == {
        "granted": True,
        "version": CONSENT_VERSION,
        "recipient": ai_consent.RECIPIENT,
        "at": FIXED.isoformat(),
    }


def test_withdrawing_takes_effect_immediately(tmp_path):
    store = consent(tmp_path)
    store.grant()
    assert store.revoke() == "ok: permission withdrawn"
    assert store.granted() is False


def test_a_grant_for_an_older_version_does_not_count(tmp_path):
    store = consent(tmp_path)
    store.grant()
    record = read_record(store.path)
    record["version"] = CONSENT_VERSION - 1
    write_raw(store.path, json.dumps(record))
    assert store.granted() is False


def test_a_corrupt_record_is_not_permission(tmp_path):
    store = consent(tmp_path)
    store.grant()
    write_raw(store.path, "{not json")
    assert store.granted() is False


def test_a_non_boolean_grant_is_not_permission(tmp_path):
    store = consent(tmp_path)
    store.grant()
    record = read_record(store.path)
    record["granted"] = "yes"
    write_raw(store.path, json.dumps(record))
    assert store.granted() is False


def test_an_unwritable_location_reports_failure_by_class_name(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    store = ConsentStore(path=str(blocker / "nested" / "ai-consent.json"), clock=lambda: FIXED)
    outcome = store.grant()
    assert outcome.startswith("failed:")
    assert store.granted() is False


def test_the_gate_sends_nothing_without_permission():
    sent = []
    gated = gate_escalator(lambda bundle: sent.append(bundle) or {"analysis": "x"}, lambda: False)
    result = gated({"classification": "dns"})
    assert sent == []
    assert result["error"].startswith("skipped:")


def test_the_gate_checks_on_every_call():
    state = {"granted": True}
    sent = []
    gated = gate_escalator(lambda b: sent.append(b) or {"analysis": "ok"}, lambda: state["granted"])
    assert gated({"n": 1}) == {"analysis": "ok"}
    state["granted"] = False
    assert "error" in gated({"n": 2})
    assert sent == [{"n": 1}]


def test_the_disclosure_names_the_recipient_and_every_part_of_the_bundle():
    text = ai_consent.DISCLOSURE
    assert "Anthropic" in text
    for part in ("classification", "probe results", "troubleshooting step", "system log"):
        assert part in text
    assert "withdraw" in text
