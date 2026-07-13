import json
from datetime import datetime, timezone

from netdnsmonitor.classifier import Classification
from netdnsmonitor.report import build_report
from netdnsmonitor.report_storage import save_report


def _report():
    return build_report(
        started_at=datetime(2026, 7, 13, 9, 0, tzinfo=timezone.utc),
        ended_at=datetime(2026, 7, 13, 9, 2, tzinfo=timezone.utc),
        classification=Classification.DNS,
        probe_results={"external_reachable": True, "dns_ok": False},
        log_excerpts=["mDNSResponder: query timed out"],
        ladder_results=[{"name": "flush_dns_cache", "outcome": "ok"}],
        repair_outcome="flush_dns_cache: ok",
        recheck_ok=True,
        escalation=None,
    )


def test_writes_both_json_and_markdown_files(tmp_path):
    paths = save_report(_report(), str(tmp_path))
    assert paths["json_path"].endswith(".json")
    assert paths["markdown_path"].endswith(".md")
    with open(paths["json_path"]) as f:
        saved = json.load(f)
    assert saved["classification"] == "dns"
    with open(paths["markdown_path"]) as f:
        md = f.read()
    assert "# Network/DNS Incident Report" in md


def test_creates_directory_if_missing(tmp_path):
    target = tmp_path / "does" / "not" / "exist"
    paths = save_report(_report(), str(target))
    assert target.is_dir()
    assert (target / paths["json_path"].split("/")[-1]).exists()
