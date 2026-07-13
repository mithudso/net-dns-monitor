from types import SimpleNamespace

from netdnsmonitor.log_watcher import make_log_watcher

SAMPLE_LOG = "\n".join(
    [
        "2026-07-13 09:00:01 mDNSResponder: normal startup message",
        "2026-07-13 09:00:05 mDNSResponder: query for example.com timed out",
        "2026-07-13 09:00:07 networkd: interface en0 came up",
        "2026-07-13 09:00:09 mDNSResponder: DNS resolution failed for corp.local",
    ]
)


def test_returns_only_error_like_lines():
    run_fn = lambda args, **kwargs: SimpleNamespace(returncode=0, stdout=SAMPLE_LOG, stderr="")
    watcher = make_log_watcher(run_fn=run_fn)
    excerpts = watcher()
    assert any("timed out" in line for line in excerpts)
    assert any("failed" in line for line in excerpts)
    assert not any("came up" in line for line in excerpts)
    assert not any("normal startup" in line for line in excerpts)


def test_invokes_log_show_with_lookback_window():
    captured = {}

    def run_fn(args, **kwargs):
        captured["args"] = args
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    watcher = make_log_watcher(run_fn=run_fn, lookback="10m")
    watcher()
    assert captured["args"][:2] == ["log", "show"]
    assert "10m" in captured["args"]


def test_returns_empty_list_when_command_fails():
    run_fn = lambda args, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="permission denied")
    watcher = make_log_watcher(run_fn=run_fn)
    assert watcher() == []


def test_returns_empty_list_on_subprocess_timeout_instead_of_raising():
    import subprocess

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    watcher = make_log_watcher(run_fn=timing_out)
    assert watcher() == []
