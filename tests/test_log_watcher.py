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
    args = captured["args"]
    assert args[:2] == ["log", "show"]
    # Assert the flag/value pair, not bare membership: "10m" is still "in" the
    # arg list when it trails a different flag, so `--last` could become
    # `--start` unnoticed. `log show` then exits 64 on the malformed window and
    # this reader turns any nonzero return into [] -- every incident report
    # silently carrying zero log evidence.
    assert args[args.index("--last") + 1] == "10m"


def test_returns_empty_list_when_command_fails():
    run_fn = lambda args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="permission denied"
    )
    watcher = make_log_watcher(run_fn=run_fn)
    assert watcher() == []


def test_returns_empty_list_on_subprocess_timeout_instead_of_raising():
    import subprocess

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    watcher = make_log_watcher(run_fn=timing_out)
    assert watcher() == []


def test_requests_explicit_utf8_decoding_instead_of_relying_on_locale():
    # A frozen .app launched via `open` doesn't inherit the shell's locale
    # env vars, so Python's default text-mode decoding falls back to ASCII
    # and `log show` output containing non-ASCII bytes crashes -- confirmed
    # empirically (UnicodeDecodeError from a real run). Decoding must be
    # pinned explicitly, not left to the ambient locale.
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_log_watcher(run_fn=run_fn)()
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"


def test_returns_empty_list_on_unicode_decode_error_instead_of_raising():
    def bad_decode(args, **kwargs):
        raise UnicodeDecodeError("ascii", b"\xe2", 0, 1, "ordinal not in range(128)")

    watcher = make_log_watcher(run_fn=bad_decode)
    assert watcher() == []


def test_returns_empty_list_when_the_log_binary_is_missing_instead_of_raising():
    """The OSError arm of `except (SubprocessError, OSError, UnicodeError)` --
    the only one of the three with no coverage. FileNotFoundError is what
    subprocess.run raises when the executable isn't on PATH, and the frozen
    .app does not inherit the shell's environment (the same root cause as the
    explicit-encoding fix), so it is the reachable case.
    """

    def missing_binary(args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "log")

    watcher = make_log_watcher(run_fn=missing_binary)
    assert watcher() == []


def test_bounds_the_log_show_call_and_captures_its_output():
    """Two kwargs every fake in this file supplies for free, so nothing else
    pins them: without `timeout=` a wedged `log show` hangs the menu bar poll
    loop with no upper bound, and without `capture_output=` subprocess leaves
    result.stdout as None and the marker filter raises AttributeError.
    """
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_log_watcher(run_fn=run_fn)()
    assert captured.get("timeout") == 10
    assert captured.get("capture_output") is True
    assert captured.get("text") is True
