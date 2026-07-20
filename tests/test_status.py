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


def test_zero_consecutive_failures_still_shows_healthy():
    assert "healthy" in build_title("healthy", None, consecutive_failures=0).lower()


def test_nonzero_consecutive_failures_below_threshold_shows_flaky():
    title = build_title("healthy", None, consecutive_failures=1)
    assert "flaky" in title.lower()
    assert "healthy" not in title.lower()
    assert "issue" not in title.lower()


def test_incident_takes_priority_over_consecutive_failures():
    title = build_title("incident", "dns", consecutive_failures=5)
    assert "issue" in title.lower()
    assert "flaky" not in title.lower()


def test_resolution_failures_appended_when_present():
    title = build_title("healthy", None, resolution_failed=3, resolution_total=50)
    assert "3/50" in title


def test_no_resolution_suffix_when_nothing_failed():
    title = build_title("healthy", None, resolution_failed=0, resolution_total=50)
    assert "50" not in title


def test_no_resolution_suffix_when_no_data_yet():
    title = build_title("healthy", None)
    assert "resolution fails" not in title
