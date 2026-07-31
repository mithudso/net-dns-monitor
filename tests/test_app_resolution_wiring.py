"""build_resolution_job wires stall_log -> resolution_prober -> resolution_log
together; verified here with every external effect patched out so it never
touches a real socket or resolver.

Every value in `_config` is deliberately *unlike* the corresponding
DEFAULT_CONFIG value. Reusing the defaults would make these assertions pass
even if `app.py` hardcoded the numbers and ignored the user's config entirely.
"""

from unittest.mock import patch

from netdnsmonitor import app


def _config(tmp_path):
    return {
        "resolution_stall_seconds": 7.5,
        "resolution_batch_deadline_seconds": 123,
        "resolution_timeout_seconds": 9.0,
        "resolution_max_workers": 3,
        "resolution_log_path": str(tmp_path / "resolution-log.jsonl"),
    }


def test_resolution_job_chains_stall_select_resolve_and_log(tmp_path):
    config = _config(tmp_path)
    fake_findings = [
        {
            "domain": "example.com",
            "resolved": True,
            "error": None,
            "elapsed_seconds": 0.01,
            "outcome": "completed",
        }
    ]

    with patch.object(app, "select_stalled_domains", return_value=["example.com"]) as select, \
         patch.object(app, "resolve_domains_parallel", return_value=fake_findings) as resolve, \
         patch.object(app, "append_resolution_findings") as append_log:
        job = app.build_resolution_job(config)
        result = job()

    select.assert_called_once_with(
        config["resolution_log_path"],
        stall_seconds=config["resolution_stall_seconds"],
    )
    resolve.assert_called_once_with(
        ["example.com"],
        timeout=config["resolution_timeout_seconds"],
        max_workers=config["resolution_max_workers"],
        deadline_seconds=config["resolution_batch_deadline_seconds"],
    )
    append_log.assert_called_once_with(fake_findings, config["resolution_log_path"])
    assert result == fake_findings


def test_app_construction_installs_the_real_resolution_job(tmp_path):
    """The bridge from build_resolution_job into the app. Every other app-level
    test replaces `resolution_job` with a stub, so without this the wiring in
    NetDnsMonitorApp.__init__ could be deleted and the whole suite would stay
    green while the 5-minute batch silently did nothing in production.
    """
    real_app = app.NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))

    with patch.object(app, "select_stalled_domains", return_value=["example.com"]) as select, \
         patch.object(app, "resolve_domains_parallel", return_value=[]) as resolve, \
         patch.object(app, "append_resolution_findings") as append_log:
        real_app.resolution_job()

    assert select.called and resolve.called and append_log.called
    # Sourced from the app's own loaded config, not from a stub closure.
    assert select.call_args[0][0] == real_app.config["resolution_log_path"]
    assert select.call_args[1]["stall_seconds"] == real_app.config["resolution_stall_seconds"]


def test_resolution_job_reads_and_appends_the_same_log(tmp_path):
    """The stall list is sourced from the log the job also appends to, so the
    feature is self-feeding. Pin that both ends use one path.
    """
    config = _config(tmp_path)

    with patch.object(app, "select_stalled_domains", return_value=[]) as select, \
         patch.object(app, "resolve_domains_parallel", return_value=[]), \
         patch.object(app, "append_resolution_findings") as append_log:
        app.build_resolution_job(config)()

    assert select.call_args[0][0] == append_log.call_args[0][1]
