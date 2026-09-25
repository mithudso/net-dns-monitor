"""Offline tests for the console.

`handle` is a pure function of (line, state) plus an injected runner, so the
whole REPL is testable without a window and without a subprocess. The handful of
tests at the bottom that *do* spawn a process are there on purpose: the timeout,
the process-group kill and the closed stdin are the guards that keep a mistyped
command from wedging the menu bar app, and a fake runner cannot prove any of
them.
"""

import os
import threading
import time

from netdnsmonitor.console import (
    CLEAR,
    CommandResult,
    ConsoleState,
    format_result,
    handle,
    run_command,
    truncate,
)


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


def test_a_long_command_result_is_truncated_on_the_way_through_handle():
    runner = recording_runner(CommandResult(stdout="y" * (200 * 1024)))
    text, _ = handle("cat big", ConsoleState(cwd="/tmp"), runner)
    assert "truncated" in text


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
    marker file is written by the grandchild *after* the timeout would have
    fired, so its absence is the proof that the group was killed.
    """
    marker = tmp_path / "survivor"
    result = run_command(
        f"sh -c 'sleep 1.5; touch {marker}' & wait", cwd=str(tmp_path), timeout=1.0
    )
    assert result.timed_out is True
    time.sleep(2.5)
    assert not marker.exists(), "a child outlived the timeout: process group not killed"


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
    before = threading.active_count()
    started = time.monotonic()
    result = run_command("sh -c 'sleep 20' & echo started", cwd=str(tmp_path), timeout=20)
    elapsed = time.monotonic() - started
    assert result.timed_out is False
    assert elapsed < 3
    assert threading.active_count() == before


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
