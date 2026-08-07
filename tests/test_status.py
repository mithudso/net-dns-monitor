from netdnsmonitor.status import build_status_report, build_title


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


# --- the console's `:status` ------------------------------------------------


def test_status_report_leads_with_the_live_gate_state():
    assert build_status_report("healthy").startswith("state:")
    assert "healthy" in build_status_report("healthy")


def test_status_report_omits_classification_while_healthy():
    """Same rule as the title: a stale classification from a resolved incident
    must not read as a current one.
    """
    assert "classification" not in build_status_report("healthy", "dns")


def test_status_report_includes_classification_during_an_incident():
    assert "dns" in build_status_report("incident", "dns")


def test_status_report_says_so_when_no_report_has_been_written():
    assert "(none this session)" in build_status_report("healthy")


def test_status_report_surfaces_a_swallowed_tick_error():
    """app.py's tick guard swallows exceptions so one bad tick cannot kill
    monitoring; without this line a persistently failing probe is invisible.
    """
    text = build_status_report("healthy", last_tick_error="OSError: boom")
    assert "OSError: boom" in text


def test_status_report_lists_monitored_domains_and_their_count():
    text = build_status_report("healthy", domains=["a.example", "b.example"])
    assert "(2)" in text
    assert "a.example, b.example" in text


def test_status_report_handles_an_empty_domain_list():
    assert "(none)" in build_status_report("healthy", domains=[])
