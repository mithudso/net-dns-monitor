from netdnsmonitor.status import build_title, next_status


def test_next_status_unchanged_when_no_report():
    assert next_status("healthy", None) == "healthy"
    assert next_status("degraded", None) == "degraded"


def test_next_status_healthy_when_report_resolved():
    assert next_status("degraded", {"resolved": True, "classification": "dns"}) == "healthy"


def test_next_status_degraded_when_report_unresolved():
    assert next_status("healthy", {"resolved": False, "classification": "network"}) == "degraded"


def test_build_title_healthy_has_no_classification():
    title = build_title("healthy", None)
    assert "healthy" in title.lower()
    assert "issue" not in title.lower()


def test_build_title_degraded_includes_classification():
    report = {"resolved": False, "classification": "dns"}
    title = build_title("degraded", report)
    assert "dns" in title.lower()
