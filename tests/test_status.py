from netdnsmonitor.status import build_title


def test_healthy_state_shows_healthy_regardless_of_past_classification():
    assert "healthy" in build_title("healthy", None).lower()
    assert "healthy" in build_title("healthy", "dns").lower()


def test_healthy_state_never_mentions_issue():
    assert "issue" not in build_title("healthy", "dns").lower()


def test_incident_state_includes_last_classification():
    title = build_title("incident", "dns")
    assert "dns" in title.lower()
    assert "issue" in title.lower()


def test_incident_state_with_no_classification_yet_says_unknown():
    title = build_title("incident", None)
    assert "unknown" in title.lower()
