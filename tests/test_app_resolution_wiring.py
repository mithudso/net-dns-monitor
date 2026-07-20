"""build_resolution_job wires query_log -> resolution_prober -> resolution_log
together; verified here with every external effect patched out so it never
touches a real subprocess, socket, or resolver.
"""

from unittest.mock import patch

from netdnsmonitor import app


def _config(tmp_path):
    return {
        "resolution_lookback": "1h",
        "resolution_top_n": 50,
        "resolution_timeout_seconds": 2.0,
        "resolution_max_workers": 10,
        "resolution_log_path": str(tmp_path / "resolution-log.jsonl"),
    }


def test_resolution_job_chains_reader_extract_resolve_and_log(tmp_path):
    config = _config(tmp_path)
    fake_reader = lambda: ["raw log line"]
    fake_findings = [{"domain": "example.com", "resolved": True, "error": None, "elapsed_seconds": 0.01}]

    with patch.object(app, "make_query_log_reader", return_value=fake_reader) as make_reader, \
         patch.object(app, "extract_top_domains", return_value=["example.com"]) as extract, \
         patch.object(app, "resolve_domains_parallel", return_value=fake_findings) as resolve, \
         patch.object(app, "append_resolution_findings") as append_log:
        job = app.build_resolution_job(config)
        result = job()

    make_reader.assert_called_once_with(lookback="1h")
    extract.assert_called_once_with(["raw log line"], limit=50)
    resolve.assert_called_once_with(["example.com"], timeout=2.0, max_workers=10)
    append_log.assert_called_once_with(fake_findings, config["resolution_log_path"])
    assert result == fake_findings
