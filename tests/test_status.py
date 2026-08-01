from netdnsmonitor.status import build_title, status_state


def test_status_state_incident_takes_priority():
    assert status_state("incident", consecutive_failures=0) == "incident"
    assert status_state("incident", consecutive_failures=5) == "incident"


def test_status_state_flaky_on_nonzero_failures_below_threshold():
    assert status_state("healthy", consecutive_failures=1) == "flaky"


def test_status_state_healthy_when_no_failures():
    assert status_state("healthy", consecutive_failures=0) == "healthy"


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


# Literals on purpose: asserting `ICONS["healthy"] in title` would read the
# same dict the code reads, so it holds even when the mapping is inverted.
GREEN, YELLOW, RED = "\U0001f7e2", "\U0001f7e1", "\U0001f534"


def test_title_glyph_colour_matches_the_state_it_reports():
    """The coloured circle is the signal; the word beside it is secondary --
    and no test in the repo asserted ICONS at all. Swapping the healthy and
    incident entries ships a red dot on a healthy network with the whole suite
    green. test_dock_icon.py already pins this same property for the Dock by
    sampling pixels, so the project treats it as worth testing.
    """
    healthy = build_title("healthy", None)
    assert GREEN in healthy
    assert RED not in healthy and YELLOW not in healthy

    incident = build_title("incident", "dns")
    assert RED in incident
    assert GREEN not in incident

    flaky = build_title("healthy", None, consecutive_failures=1)
    assert YELLOW in flaky
    assert GREEN not in flaky and RED not in flaky

    assert len({GREEN, YELLOW, RED}) == 3


def test_unknown_flap_state_is_treated_as_healthy_not_as_an_incident():
    """flap_state is a bare string, not an enum, so any renamed or future
    state lands here. Falling through to healthy is the deliberate fail-open
    choice, matching dock_icon's default, and nothing pinned it: replacing
    `== "incident"` with `!= "healthy"` passes the rest of this file.
    """
    assert status_state("degraded", consecutive_failures=0) == "healthy"
    assert status_state("", consecutive_failures=0) == "healthy"
    assert status_state("degraded", consecutive_failures=1) == "flaky"
    assert "issue" not in build_title("degraded", "dns").lower()
