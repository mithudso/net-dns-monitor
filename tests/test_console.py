"""Offline tests for the console.

`handle` is a pure function of (line, state) plus an injected runner, so the
whole REPL is testable without a window and without a subprocess. The handful of
tests at the bottom that *do* spawn a process are there on purpose: the timeout,
the process-group kill and the closed stdin are the guards that keep a mistyped
command from wedging the menu bar app, and a fake runner cannot prove any of
them.
"""

import contextlib
import os
import signal
import threading
import time

from netdnsmonitor import console
from netdnsmonitor.console import (
    CLEAR,
    ClearSignal,
    CommandResult,
    ConsoleState,
    child_env,
    format_result,
    handle,
    kill_running,
    run_command,
    truncate,
)


def group_is_gone(pgid: int, within: float = 2.0) -> bool:
    """Poll until no process is left in the group. SIGKILL is delivered at
    once, but the orphans are reaped by launchd, not by this process.
    """
    deadline = time.monotonic() + within
    while True:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return True
        if time.monotonic() > deadline:
            return False
        time.sleep(0.05)


def recording_runner(result=None):
    """A fake runner that captures what it was asked to run."""
    calls = []

    def runner(command, cwd, timeout):
        calls.append({"command": command, "cwd": cwd, "timeout": timeout})
        return result if result is not None else CommandResult(stdout="ok")

    runner.calls = calls
    return runner


# --- built-ins --------------------------------------------------------------


def test_blank_line_does_nothing():
    state = ConsoleState(cwd="/tmp")
    runner = recording_runner()
    text, next_state = handle("   ", state, runner)
    assert text == ""
    assert runner.calls == []
    assert next_state.history == []


def test_help_does_not_reach_the_runner():
    runner = recording_runner()
    text, _ = handle(":help", ConsoleState(cwd="/tmp"), runner)
    assert "shell command" in text or "built-ins" in text
    assert ":scripts" in text
    assert ":tools" in text
    assert ":suggested" in text
    assert runner.calls == []


def test_scripts_builtin_returns_scripts_catalog():
    runner = recording_runner()
    text, _ = handle(":scripts", ConsoleState(cwd="/tmp"), runner)
    assert "python3 -m netdnsmonitor.app" in text
    assert "SCRIPTS.md" in text
    assert "prober.py" in text
    assert runner.calls == []


def test_tools_builtin_returns_diagnostic_tools():
    runner = recording_runner()
    text, _ = handle(":tools", ConsoleState(cwd="/tmp"), runner)
    assert "scutil --dns" in text
    assert "traceroute" in text
    assert "lsof" in text
    assert runner.calls == []


def test_suggested_builtin_returns_suggested_commands():
    runner = recording_runner()
    text, _ = handle(":suggested", ConsoleState(cwd="/tmp"), runner)
    assert "scutil --nwi" in text
    assert "dig @8.8.8.8" in text
    assert runner.calls == []


def test_clear_returns_the_sentinel_not_an_action():
    """The window owns its text storage; `handle` only says it should be empty."""
    text, _ = handle(":clear", ConsoleState(cwd="/tmp"), recording_runner())
    assert text == CLEAR


def test_pwd_reports_console_cwd_not_process_cwd():
    text, _ = handle(":pwd", ConsoleState(cwd="/tmp"), recording_runner())
    assert text == "/tmp"


def test_quit_closes_the_window_without_running_anything():
    """`q` must not quit the app: losing the monitor because you typed a letter
    in the console is the opposite of what the person wants.
    """
    runner = recording_runner()
    for word in ("q", ":q", "exit", ":close"):
        _, state = handle(word, ConsoleState(cwd="/tmp"), runner)
        assert state.closed is True
    assert runner.calls == []


def test_unknown_builtin_is_not_passed_to_the_shell():
    """A typo'd `:sttaus` reaching /bin/sh would be a confusing error at best."""
    runner = recording_runner()
    text, _ = handle(":sttaus", ConsoleState(cwd="/tmp"), runner)
    assert "unknown built-in" in text
    assert runner.calls == []


def test_history_records_commands_but_not_builtins():
    state = ConsoleState(cwd="/tmp")
    runner = recording_runner()
    _, state = handle("echo one", state, runner)
    _, state = handle(":help", state, runner)
    _, state = handle("echo two", state, runner)
    assert state.history == ["echo one", "echo two"]
    text, _ = handle(":history", state, runner)
    assert "echo one" in text and "echo two" in text
    assert ":help" not in text


def test_history_is_empty_before_anything_runs():
    text, _ = handle(":history", ConsoleState(cwd="/tmp"), recording_runner())
    assert text == "(nothing yet)"


# --- status -----------------------------------------------------------------


def test_status_uses_the_injected_provider():
    text, _ = handle(
        ":status", ConsoleState(cwd="/tmp"), recording_runner(), status=lambda: "healthy"
    )
    assert text == "healthy"


def test_status_without_a_provider_says_so_rather_than_crashing():
    text, _ = handle(":status", ConsoleState(cwd="/tmp"), recording_runner())
    assert "not available" in text


def test_a_failing_status_provider_does_not_kill_the_console():
    """Same rule as the tick guard in app.py: a dead console is worse than a
    lost line of output.
    """

    def boom():
        raise RuntimeError("state machine went away")

    text, _ = handle(":status", ConsoleState(cwd="/tmp"), recording_runner(), status=boom)
    assert "failed to read monitor state" in text
    assert "RuntimeError" in text


# --- cd ---------------------------------------------------------------------


def test_cd_is_a_builtin_because_a_subprocess_cannot_change_our_directory(tmp_path):
    runner = recording_runner()
    state = ConsoleState(cwd="/tmp")
    text, state = handle(f"cd {tmp_path}", state, runner)
    assert state.cwd == str(tmp_path)
    assert text == str(tmp_path)
    assert runner.calls == []


def test_cd_is_relative_to_the_console_cwd_not_the_process(tmp_path):
    """`cd ..` has to mean the same thing the second time as the first."""
    child = tmp_path / "child"
    child.mkdir()
    state = ConsoleState(cwd=str(child))
    _, state = handle("cd ..", state, recording_runner())
    assert state.cwd == str(tmp_path)


def test_cd_separated_by_a_tab_is_still_the_builtin(tmp_path):
    """A prefix test that only knows about `"cd "` sends `cd<tab>/etc` to the
    shell, where the directory change happens in the child and dies with it --
    a built-in that silently does nothing.
    """
    state = ConsoleState(cwd="/tmp")
    runner = recording_runner()
    _, state = handle(f"cd\t{tmp_path}", state, runner)
    assert state.cwd == str(tmp_path)
    assert runner.calls == []


def test_a_command_merely_starting_with_cd_is_not_the_builtin():
    """`cdto` is somebody's script, not a directory change."""
    runner = recording_runner()
    handle("cdto /tmp", ConsoleState(cwd="/tmp"), runner)
    assert runner.calls[0]["command"] == "cdto /tmp"


def test_bare_cd_goes_home():
    state = ConsoleState(cwd="/tmp")
    _, state = handle("cd", state, recording_runner())
    assert state.cwd == os.path.expanduser("~")


def test_cd_to_a_missing_directory_reports_and_leaves_cwd_alone():
    state = ConsoleState(cwd="/tmp")
    text, state = handle("cd /no/such/place", state, recording_runner())
    assert "no such directory" in text
    assert state.cwd == "/tmp"


def test_cd_accepts_a_quoted_or_escaped_path(tmp_path):
    """HELP says quoting works. `cd "a b"` used to look for a directory whose
    name included the quotes.
    """
    spaced = tmp_path / "a b"
    spaced.mkdir()
    for line in (f'cd "{spaced}"', f"cd '{spaced}'", f"cd {tmp_path}/a\\ b"):
        text, state = handle(line, ConsoleState(cwd="/tmp"), recording_runner())
        assert state.cwd == str(spaced), f"{line!r} -> {text}"


def test_cd_expands_environment_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    _, state = handle("cd $HOME", ConsoleState(cwd="/tmp"), recording_runner())
    assert state.cwd == str(tmp_path)


def test_cd_with_an_unbalanced_quote_reports_rather_than_raising():
    text, state = handle('cd "unterminated', ConsoleState(cwd="/tmp"), recording_runner())
    assert "no such directory" in text
    assert state.cwd == "/tmp"


def test_a_chained_cd_says_it_cannot_chain_rather_than_blaming_the_directory(tmp_path):
    """`cd /tmp && ls` is a normal thing to type. Reporting it as
    `no such directory: /tmp && ls` reads as "that directory is missing", which
    sends the reader looking for the wrong problem.
    """
    state = ConsoleState(cwd="/tmp")
    text, state = handle(f"cd {tmp_path} && ls", state, recording_runner())
    assert "cannot chain" in text
    assert "no such directory" not in text
    assert state.cwd == "/tmp"


def test_cd_strips_quotes_and_expands_variables(tmp_path, monkeypatch):
    """`cd "$SCRATCH"` is how a shell user types a path with spaces in it; the
    built-in has no shell to do the unquoting and expansion for it.
    """
    target = tmp_path / "with space"
    target.mkdir()
    monkeypatch.setenv("SCRATCH", str(target))
    state = ConsoleState(cwd="/tmp")
    _, state = handle('cd "$SCRATCH"', state, recording_runner())
    assert state.cwd == str(target)
    _, state = handle(f"cd '{target}'", ConsoleState(cwd="/tmp"), recording_runner())
    assert state.cwd == str(target)


def test_history_output_is_capped_like_any_other_output():
    state = ConsoleState(cwd="/tmp", history=["x" * 1000] * 100)
    text, _ = handle(":history", state, recording_runner())
    assert "truncated" in text


def test_status_output_is_capped_like_any_other_output():
    """The domain list `:status` prints is learned at runtime and unbounded."""
    text, _ = handle(
        ":status", ConsoleState(cwd="/tmp"), recording_runner(), status=lambda: "z" * 200_000
    )
    assert "truncated" in text


def test_cwd_is_passed_to_every_command(tmp_path):
    runner = recording_runner()
    state = ConsoleState(cwd=str(tmp_path))
    handle("ls", state, runner)
    assert runner.calls[0]["cwd"] == str(tmp_path)


# --- rendering --------------------------------------------------------------


def test_both_streams_are_shown():
    """A failing `dig` puts the useful part on stdout and the reason on stderr;
    showing one of them is how a console starts lying about what happened.
    """
    text = format_result(CommandResult(stdout="answer", stderr="warning", returncode=0))
    assert "answer" in text and "warning" in text


def test_nonzero_exit_is_reported():
    text = format_result(CommandResult(stdout="", stderr="not found", returncode=127))
    assert "[exit 127]" in text


def test_silent_success_is_not_a_blank_line():
    assert format_result(CommandResult()) == "(no output)"


def test_timeout_is_reported_as_a_timeout_not_as_an_exit_code():
    text = format_result(CommandResult(timed_out=True, returncode=-9), timeout=20.0)
    assert "timed out after 20s" in text
    assert "[exit" not in text


def test_the_exit_marker_survives_a_capped_body():
    """Both streams are capped independently upstream, so this can be handed
    twice the cap. A marker added before truncating would be the part cut off,
    losing the exit status on exactly the noisiest failures.
    """
    text = format_result(CommandResult(stdout="x" * 200_000, returncode=1))
    assert "[exit 1]" in text
    assert "truncated" in text


def test_the_timeout_marker_survives_a_capped_body():
    text = format_result(
        CommandResult(stdout="x" * 100_000, stderr="y" * 100_000, timed_out=True),
        timeout=20.0,
    )
    assert "timed out after 20s" in text


def test_output_is_capped_in_bytes():
    """Bytes, not lines: one `log show` produces a few enormous lines, and it is
    the byte count that wedges the text view.
    """
    capped = truncate("x" * 5000, limit=1000)
    assert len(capped.encode()) < 1200
    assert "truncated 4000 more bytes" in capped


def test_short_output_is_untouched():
    assert truncate("hello", limit=1000) == "hello"


def test_multibyte_output_is_not_cut_into_invalid_utf8():
    capped = truncate("é" * 500, limit=101)
    assert "truncated" in capped  # decoded without raising, which is the point


def test_a_long_command_result_is_truncated_on_the_way_through_handle(tmp_path):
    # The real runner, not a fake: the runner is what caps the stream, so a fake
    # result hands format_result the whole stream and proves nothing about the pair.
    text, _ = handle(
        "head -c 300000 /dev/zero | tr '\\0' y",
        ConsoleState(cwd=str(tmp_path)),
        run_command,
    )
    assert "truncated" in text
    assert len(text.encode()) < console.MAX_OUTPUT_BYTES + 300


# --- the real runner --------------------------------------------------------


def test_run_command_executes_in_the_given_directory(tmp_path):
    result = run_command("pwd", cwd=str(tmp_path), timeout=10)
    assert result.returncode == 0
    assert os.path.realpath(result.stdout.strip()) == os.path.realpath(str(tmp_path))


def test_run_command_supports_pipes_because_it_is_a_real_shell(tmp_path):
    result = run_command("printf 'a\\nb\\n' | wc -l", cwd=str(tmp_path), timeout=10)
    assert result.stdout.strip() == "2"


def test_stdin_is_closed_so_an_interactive_command_fails_instead_of_hanging(tmp_path):
    """`cat` with no argument reads stdin forever. With /dev/null it returns at
    once -- which is what stops `sudo` and `ssh` from burning the full timeout.
    """
    started = time.monotonic()
    result = run_command("cat", cwd=str(tmp_path), timeout=10)
    assert time.monotonic() - started < 5
    assert result.timed_out is False
    assert result.stdout == ""


def test_a_command_that_never_exits_is_killed_at_the_timeout(tmp_path):
    """The guard that matters most: a bare `ping google.com` never exits, and
    without this the console would hold a worker thread forever.
    """
    started = time.monotonic()
    result = run_command("sleep 30", cwd=str(tmp_path), timeout=1.0)
    elapsed = time.monotonic() - started
    assert result.timed_out is True
    assert elapsed < 10


def test_the_whole_process_group_dies_not_just_the_shell(tmp_path):
    """`subprocess.run(timeout=...)` under `shell=True` kills /bin/sh and leaves
    the child running, detached and invisible -- one orphan per attempt. The
    shell prints its own pid, which is the group id, so the proof is that the
    group is empty afterwards. The grandchild's output is redirected so it does
    not hold the pipes: otherwise the background-job kill would empty the group
    too, and this would pass even with a timeout that killed only the shell.
    """
    result = run_command(
        "echo $$; sh -c 'sleep 30' > /dev/null 2>&1 & wait", cwd=str(tmp_path), timeout=0.5
    )
    assert result.timed_out is True
    pgid = int(result.stdout.split()[0])
    assert group_is_gone(pgid), "a child outlived the timeout: process group not killed"


def test_a_background_job_does_not_outlive_the_command(tmp_path):
    """`ping 1.1.1.1 &` exits the shell at once, so the timeout never fires,
    and the orphan holds the output pipes open. Without the group kill the
    readers block on it: a leaked process and two threads per line.
    """
    started = time.monotonic()
    result = run_command("echo $$; sleep 30 &", cwd=str(tmp_path), timeout=20)
    assert time.monotonic() - started < 3
    assert result.timed_out is False
    assert group_is_gone(int(result.stdout.split()[0]))


def test_a_redirected_background_job_is_left_running(tmp_path):
    """The group kill is for jobs that hold the console's pipes. One the user
    detached from them is a deliberate choice and is not second-guessed.
    """
    result = run_command("echo $$; sleep 30 > /dev/null 2>&1 &", cwd=str(tmp_path), timeout=20)
    pgid = int(result.stdout.split()[0])
    try:
        os.killpg(pgid, 0)  # raises ProcessLookupError if it was killed
    finally:
        with contextlib.suppress(OSError):
            os.killpg(pgid, signal.SIGKILL)


def test_kill_running_ends_a_command_in_flight(tmp_path):
    """Registered for app quit: `start_new_session` detaches each command from
    the app's group, so nothing else would end it.
    """
    results = []
    worker = threading.Thread(
        target=lambda: results.append(run_command("sleep 30", str(tmp_path), 60))
    )
    worker.start()
    deadline = time.monotonic() + 2
    while not console._LIVE and time.monotonic() < deadline:
        time.sleep(0.01)
    assert console._LIVE, "the command never registered as running"
    pgid = next(iter(console._LIVE))

    started = time.monotonic()
    kill_running()
    worker.join(timeout=5)

    assert not worker.is_alive()
    assert time.monotonic() - started < 2
    assert results[0].returncode == -signal.SIGKILL
    assert group_is_gone(pgid)
    assert not console._LIVE, "a finished command must not stay registered"


def test_kill_running_with_nothing_running_is_harmless():
    kill_running()


# --- child environment ------------------------------------------------------


def test_the_built_app_does_not_hand_its_python_home_to_commands():
    """py2app's launcher sets PYTHONHOME to the bundle; inherited, it breaks the
    user's own `python3` with "No module named encodings".
    """
    environ = {
        "PYTHONHOME": "/Applications/Net-DNS-Monitor.app/Contents/Resources",
        "PYTHONPATH": "/bundle/lib",
        "RESOURCEPATH": "/bundle",
        "ARGVZERO": "/bundle/MacOS/app",
        "EXECUTABLEPATH": "/bundle/MacOS/app",
        "PATH": "/usr/bin:/bin",
        "HOME": "/Users/someone",
    }
    assert child_env(environ, "macosx_app") == {"PATH": "/usr/bin:/bin", "HOME": "/Users/someone"}


def test_running_from_source_passes_the_environment_through_unchanged():
    environ = {"PYTHONPATH": "/my/project", "PATH": "/usr/bin"}
    env = child_env(environ, None)
    assert env == environ
    assert env is not environ


def test_console_commands_never_inherit_the_apps_credentials():
    # `env` in the console would print them, and a backgrounded command would
    # keep them for its whole life. The app reads them from the Keychain, so
    # nothing a console command needs is lost.
    environ = {
        "ANTHROPIC_API_KEY": "sk-ant-secret",
        "SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T/B/x",
        "SMTP_PASSWORD": "hunter2",
        "PATH": "/usr/bin",
    }
    for frozen in (None, "macosx_app"):
        assert child_env(environ, frozen) == {"PATH": "/usr/bin"}


def test_output_survives_a_child_that_outlives_the_shell(tmp_path):
    """`sh -c 'sleep 20' & echo started` exits at once, but the grandchild keeps
    the pipe's write end open. A reader that waits for a full block or EOF sits
    on that pipe and the line that *was* printed is reported as no output.
    """
    started = time.monotonic()
    result = run_command("sh -c 'sleep 20' & echo started", cwd=str(tmp_path), timeout=10)
    elapsed = time.monotonic() - started
    assert "started" in result.stdout
    assert result.timed_out is False
    assert elapsed < 3


def test_a_background_job_does_not_hold_the_console_open(tmp_path):
    """A `&` job that outlives its shell must not keep the reader threads -- and
    the console line -- alive until the job ends on its own.
    """
    before = set(threading.enumerate())
    started = time.monotonic()
    result = run_command("sh -c 'sleep 20' & echo started", cwd=str(tmp_path), timeout=20)
    elapsed = time.monotonic() - started
    assert result.timed_out is False
    assert elapsed < 3
    # The reader threads wind down after run_command has returned, on the
    # scheduler's timing, not before it: a count taken on the very next line
    # saw 3 for 2 once on the CI runner. Compare identities because unrelated
    # threads can also finish during this test. The claim is that they do not live
    # the 20 s of the job, so give them a moment, not the job's lifetime.
    deadline = time.monotonic() + 2
    while set(threading.enumerate()) - before and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not (set(threading.enumerate()) - before)


def test_a_flood_of_output_is_capped_without_buffering_all_of_it(tmp_path):
    """`communicate()` would hold the whole stream in memory -- `yes` for the
    full timeout is gigabytes, inside the menu bar app that has to survive the
    incident. The reader keeps the cap and discards the rest, so this returns
    bounded output and does not hit the timeout.
    """
    started = time.monotonic()
    result = run_command(
        "yes abcdefghijklmnopqrstuvwxyz | head -c 20000000", cwd=str(tmp_path), timeout=30
    )
    assert result.timed_out is False
    assert len(result.stdout) <= 64 * 1024 + 1
    assert time.monotonic() - started < 25


def test_partial_output_survives_a_timeout(tmp_path):
    """A command that prints and then hangs must still show what it printed;
    reporting it as empty would hide the useful half of a diagnosis.
    """
    result = run_command("echo before-the-hang; sleep 30", cwd=str(tmp_path), timeout=1.5)
    assert result.timed_out is True
    assert "before-the-hang" in result.stdout


def test_a_bad_cwd_is_an_error_message_not_a_crash(tmp_path):
    """The directory `cd` accepted can be gone by the time a command runs."""
    doomed = tmp_path / "gone"
    doomed.mkdir()
    doomed.rmdir()
    result = run_command("echo hi", cwd=str(doomed), timeout=5)
    assert result.returncode != 0
    assert result.stderr


# --- findings from the optimizer pass ---------------------------------------


def test_flood_output_says_it_was_truncated(tmp_path):
    result = run_command("yes abcdefghijklmnopqrstuvwxyz | head -c 2000000", str(tmp_path), 20)
    assert result.dropped_stdout > 1_000_000
    text = format_result(result)
    assert "truncated" in text
    assert len(text.encode()) < console.MAX_OUTPUT_BYTES + 300


def test_a_result_that_dropped_bytes_upstream_is_marked_even_when_short():
    text = format_result(CommandResult(stdout="kept", dropped_stdout=5000))
    assert "truncated 5000 more bytes" in text


def test_stderr_reason_survives_a_capped_stdout(tmp_path):
    result = run_command(
        "head -c 100000 /dev/zero | tr '\\0' a; echo 'dig: connection refused' >&2; exit 9",
        str(tmp_path),
        20,
    )
    text = format_result(result)
    assert "connection refused" in text
    assert "[exit 9]" in text


def test_both_streams_flooding_each_keep_a_share():
    text = format_result(CommandResult(stdout="o" * 200_000, stderr="e" * 200_000, returncode=1))
    assert "o" * 1000 in text and "e" * 1000 in text
    assert len(text.encode()) < console.MAX_OUTPUT_BYTES + 500


def test_reader_start_failure_does_not_leak_the_child(tmp_path, monkeypatch):
    real = threading.Thread
    calls = {"n": 0}
    groups = []
    real_popen = console.subprocess.Popen

    class Flaky(real):
        def start(self):
            calls["n"] += 1
            if calls["n"] == 2:
                raise RuntimeError("can't start new thread")
            return super().start()

    def recording_popen(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        groups.append(process.pid)
        return process

    monkeypatch.setattr(console.threading, "Thread", Flaky)
    monkeypatch.setattr(console.subprocess, "Popen", recording_popen)
    try:
        result = run_command("sleep 25", str(tmp_path), 1.0)
    finally:
        monkeypatch.setattr(console.threading, "Thread", real)
        for pgid in groups:
            if not group_is_gone(pgid, within=0.0):
                with contextlib.suppress(OSError):
                    os.killpg(pgid, signal.SIGKILL)
    assert result.returncode == 127
    assert "RuntimeError" in result.stderr and "thread" not in result.stderr
    assert group_is_gone(groups[0])
    with console._LIVE_LOCK:
        assert groups[0] not in console._LIVE


def test_command_output_equal_to_the_sentinel_does_not_clear_the_window(tmp_path):
    for output in ("__CLEAR__\n", "__CLEAR__"):
        runner = lambda command, cwd, timeout, o=output: CommandResult(stdout=o)  # noqa: E731
        text, _ = handle("curl -s http://host/x", ConsoleState(cwd=str(tmp_path)), runner)
        assert not isinstance(text, ClearSignal)
    text, _ = handle(":clear", ConsoleState(cwd=str(tmp_path)))
    assert isinstance(text, ClearSignal)


def test_a_session_escaping_child_does_not_hold_the_console_line(tmp_path):
    started = time.monotonic()
    run_command("echo hi; perl -MPOSIX -e 'setsid(); sleep 12' &", str(tmp_path), 20)
    assert time.monotonic() - started < 3


def test_the_help_text_does_not_hard_code_a_test_count():
    assert "187" not in console.SCRIPTS_HELP
