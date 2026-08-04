import contextlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from netdnsmonitor.classifier import Classification
from netdnsmonitor.report import build_report, render_markdown
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


def test_markdown_is_written_utf8_even_though_json_would_survive_ascii(tmp_path):
    """The regression test for the 0-byte reports. Three `.md` files on this
    machine were 0 bytes beside complete `.json` siblings; the real launchd
    traceback was `UnicodeEncodeError: 'ascii' codec` at the `.md` write.

    Under launchd no `LANG` is set, so the process locale encoding is ASCII and
    an unencoded `open(..., "w")` raises on the first non-ASCII character --
    while `json.dump`'s `ensure_ascii=True` keeps the JSON half writable. Hence
    full JSON, empty Markdown.

    Reading the bytes back and decoding UTF-8 explicitly pins the on-disk
    encoding rather than the test host's locale, so this fails on any
    non-UTF-8 write regardless of where it runs. The curly quotes mirror the
    real payload: they came from the Claude escalation text.
    """
    report = _report()
    report["escalation"] = {"analysis": "the resolver returned “no answer” for café.local"}

    paths = save_report(report, str(tmp_path))

    written = Path(paths["markdown_path"]).read_bytes().decode("utf-8")
    assert written == render_markdown(report)
    assert "“no answer”" in written


def test_markdown_file_is_the_complete_rendering_not_a_truncated_prefix(tmp_path):
    """`open(path, "w")` truncates before any content lands, and the `.md` is
    written second, so anything that interrupts or shortens that write leaves
    an unusable human-readable half whose machine-readable sibling looks fine.

    Asserting only the H1 heading is not enough: a write truncated to 40 bytes
    keeps the heading and passes. Pin a nonzero size and the whole rendering.
    """
    report = _report()
    paths = save_report(report, str(tmp_path))

    assert os.path.getsize(paths["markdown_path"]) > 0
    with open(paths["markdown_path"]) as f:
        assert f.read() == render_markdown(report)


def test_a_failed_render_leaves_the_previous_report_intact(tmp_path):
    """The point of writing via a temp file and `os.replace`: a destination is
    only ever replaced by content that was written in full. Without it, a
    second save that dies mid-write truncates the good report already on disk.
    """
    report = _report()
    paths = save_report(report, str(tmp_path))
    good = Path(paths["markdown_path"]).read_bytes()

    class Unrenderable(dict):
        def __getitem__(self, key):
            if key == "classification":
                raise RuntimeError("render blew up")
            return super().__getitem__(key)

    broken = Unrenderable(report)
    # The raise is the point of the fixture, not the thing under test -- what is
    # under test is the file on disk afterwards.
    with contextlib.suppress(RuntimeError):
        save_report(broken, str(tmp_path))

    assert Path(paths["markdown_path"]).read_bytes() == good


def test_no_temp_files_are_left_behind(tmp_path):
    save_report(_report(), str(tmp_path))
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []


def test_report_filename_has_no_colons_from_the_iso_timestamp(tmp_path):
    """`started_at` is an ISO timestamp, so it contains colons, and the
    `.replace(":", "-")` is deliberate defensive code for a file a human is
    told to open and hand to IT. Nothing pinned it.
    """
    paths = save_report(_report(), str(tmp_path))
    for path in (paths["json_path"], paths["markdown_path"]):
        assert ":" not in os.path.basename(path)
    assert "2026-07-13T09-00-00" in os.path.basename(paths["markdown_path"])
