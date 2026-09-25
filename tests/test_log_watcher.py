import subprocess
from types import SimpleNamespace

from netdnsmonitor.domain_learner import extract_failed_domains
from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX, make_log_watcher

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
    # By absolute path, the way system_log.py does it: a frozen .app launched via
    # `open` does not inherit the shell's PATH, and a PATH lookup can find a
    # different `log` first.
    assert args[:2] == ["/usr/bin/log", "show"]
    # Assert the flag/value pair, not bare membership: "10m" is still "in" the
    # arg list when it trails a different flag, so `--last` could become
    # `--start` unnoticed. `log show` then exits 64 on the malformed window, and
    # every incident report carries a "no log evidence" line instead of the log.
    assert args[args.index("--last") + 1] == "10m"


def test_a_clean_run_with_no_error_lines_is_an_empty_list():
    """[] is kept for exactly one meaning: `log show` ran and nothing matched."""
    run_fn = lambda args, **kwargs: SimpleNamespace(
        returncode=0, stdout="2026-07-13 09:00:07 networkd: interface en0 came up", stderr=""
    )
    assert make_log_watcher(run_fn=run_fn)() == []


def test_a_nonzero_exit_is_reported_as_no_evidence_rather_than_as_no_errors():
    run_fn = lambda args, **kwargs: SimpleNamespace(
        returncode=1, stdout="", stderr="permission denied"
    )
    watcher = make_log_watcher(run_fn=run_fn)
    assert watcher() == [f"{NO_EVIDENCE_PREFIX} no log evidence: log show exited 1"]


def test_a_timeout_is_reported_as_no_evidence_with_the_limit_and_lookback():
    """A 30m lookback measured 10.15s against the 10s limit. The report has to say
    the log was not read, or an empty section reads as a quiet network.
    """

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    watcher = make_log_watcher(run_fn=timing_out, lookback="30m")
    assert watcher() == [
        f"{NO_EVIDENCE_PREFIX} no log evidence: log show timed out after 10s (lookback 30m)"
    ]


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


def test_a_unicode_decode_error_is_reported_as_no_evidence_instead_of_raising():
    def bad_decode(args, **kwargs):
        raise UnicodeDecodeError("ascii", b"\xe2", 0, 1, "ordinal not in range(128)")

    watcher = make_log_watcher(run_fn=bad_decode)
    assert watcher() == [
        f"{NO_EVIDENCE_PREFIX} no log evidence: log show failed: UnicodeDecodeError"
    ]


def test_a_missing_log_binary_is_reported_by_class_name_only_instead_of_raising():
    """The OSError arm of the except clause. The line carries the exception class
    name and nothing from the exception's message, which goes into the LLM bundle.
    """

    def missing_binary(args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "/usr/bin/log")

    lines = make_log_watcher(run_fn=missing_binary)()
    assert lines == [f"{NO_EVIDENCE_PREFIX} no log evidence: log show failed: FileNotFoundError"]
    assert "No such file" not in lines[0]
    assert "/usr/bin/log" not in lines[0]


def test_the_no_evidence_line_is_marked_as_this_apps_own_text():
    """The prefix is what lets a reader of the report, and the domain learner, tell
    this app's note apart from a line the unified log actually produced.
    """
    assert NO_EVIDENCE_PREFIX == "[net-dns-monitor]"
    run_fn = lambda args, **kwargs: SimpleNamespace(returncode=64, stdout="", stderr="")
    (line,) = make_log_watcher(run_fn=run_fn)()
    assert line.startswith("[net-dns-monitor] ")


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


def test_the_timeout_is_injectable_and_defaults_to_ten_seconds():
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_log_watcher(run_fn=run_fn, timeout=30)()
    assert captured["timeout"] == 30


def test_the_excerpt_list_is_capped_and_says_how_much_was_dropped():
    """424 error-like lines at 5m, 3,942 at 30m -- and the whole list goes into
    the escalation prompt. Keep the newest, and say what was cut rather than
    silently handing the model a truncated log.
    """
    stdout = "\n".join(
        f"2026-07-13 09:{i // 60:02d}:{i % 60:02d} mDNSResponder: error {i}" for i in range(600)
    )
    run_fn = lambda args, **kwargs: SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    excerpts = make_log_watcher(run_fn=run_fn, max_lines=500)()
    assert len(excerpts) == 501
    assert "omitted" in excerpts[0]
    assert "100" in excerpts[0]
    assert excerpts[-1].endswith("error 599")
    assert excerpts[1].endswith("error 100")
    assert extract_failed_domains(excerpts[:1]) == []


def test_a_result_without_stdout_or_returncode_is_reported_not_a_crash():
    """The other `log show` reader (system_log) reads both through getattr, for
    the same reason: a run_fn whose result carries neither must not raise from
    inside an incident tick.
    """
    run_fn = lambda args, **kwargs: SimpleNamespace()
    excerpts = make_log_watcher(run_fn=run_fn)()
    # No returncode counts as a failed read, which is reported, not raised.
    assert len(excerpts) == 1
    assert excerpts[0].startswith(NO_EVIDENCE_PREFIX)
