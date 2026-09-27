"""Tests for the console window controller's dispatch logic.

The AppKit calls (`show`, the NSTextView writes) cannot be tested here and are
not the point. What *is* testable, and is where the bugs live, is everything
around them: the busy interlock, which thread clears it, and how the three
outcomes `handle` can return -- text, clear, close -- get routed. `runner` and
`on_main` are injected so none of that needs a window or a subprocess.

`text_view is None` throughout, which is the controller's headless mode: append
falls back to `print`, so these tests capture stdout to see what was drawn.
"""

import pytest

from netdnsmonitor.console import CLEAR, CommandResult, ConsoleState
from netdnsmonitor.console_window import BUSY_MESSAGE, ConsoleWindowController


def immediately(fn):
    """Stand-in for the hop to the main thread."""
    fn()


def controller(**kwargs):
    kwargs.setdefault("on_main", immediately)
    kwargs.setdefault("runner", lambda command, cwd, timeout: CommandResult(stdout="ok"))
    return ConsoleWindowController(**kwargs)


def test_a_line_runs_and_its_output_is_drawn(capsys):
    console = controller()
    console.run_line("echo hi")
    assert "ok" in capsys.readouterr().out


def test_busy_holds_until_the_output_is_drawn(capsys):
    """Cleared on the worker, the flag dropped before the draw was queued: with
    the main thread busy, a second Return was accepted and its echo landed
    above the first command's output.
    """
    queued = []
    console = controller(on_main=queued.append)
    console._busy = True
    console.run_line("echo a")

    console.submit("echo b")
    assert console._busy is True
    assert BUSY_MESSAGE in capsys.readouterr().out

    for fn in queued:
        fn()
    assert console._busy is False
    assert "ok" in capsys.readouterr().out


def test_busy_is_cleared_when_the_hop_to_the_main_thread_fails():
    """No hop queued means no `_finish`, so the worker has to clear the flag or
    the console refuses every later line as 'still running'.
    """

    def broken(fn):
        raise RuntimeError("no main queue")

    console = controller(on_main=broken)
    console._busy = True
    with pytest.raises(RuntimeError):
        console.run_line("echo hi")
    assert console._busy is False


def test_busy_is_cleared_when_drawing_raises():
    def explode(text):
        raise RuntimeError("AppKit")

    console = controller()
    console.append = explode
    console._busy = True
    with pytest.raises(RuntimeError):
        console._finish("output")
    assert console._busy is False


def test_busy_is_cleared_even_when_the_command_raises():
    def explode(command, cwd, timeout):
        raise RuntimeError("runner died")

    console = controller(runner=explode)
    console._busy = True
    console.run_line("echo hi")
    assert console._busy is False


def test_a_raising_runner_is_reported_rather_than_killing_the_window(capsys):
    def explode(command, cwd, timeout):
        raise RuntimeError("runner died")

    console = controller(runner=explode)
    console.run_line("echo hi")
    out = capsys.readouterr().out
    assert "failed:" in out and "RuntimeError" in out


def test_submit_refuses_a_second_line_while_one_is_running(capsys):
    console = controller()
    console._busy = True
    console.submit("echo hi")
    assert BUSY_MESSAGE in capsys.readouterr().out


def test_a_failed_thread_start_does_not_strand_the_busy_flag(capsys, monkeypatch):
    """The flag is cleared once the output is drawn, which never happens if the
    thread never starts -- leaving the console refusing every later line.
    """
    import netdnsmonitor.console_window as module

    class DeadThread:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("can't start new thread")

    monkeypatch.setattr(module.threading, "Thread", DeadThread)
    console = controller()
    console.submit("echo hi")
    assert console._busy is False
    assert "failed to start command" in capsys.readouterr().out


def test_submit_ignores_a_blank_line(capsys):
    console = controller()
    console.submit("   ")
    assert capsys.readouterr().out == ""
    assert console._busy is False


def test_the_line_is_echoed_before_the_work_starts(capsys):
    """A command that takes the full timeout must not leave the window looking
    frozen for twenty seconds with nothing on screen.
    """
    console = controller()
    console._busy = True  # stops the thread from starting; we only want the echo
    console.submit("dig example.com")
    assert "netdns> dig example.com" not in capsys.readouterr().out  # busy path

    console = controller()
    console.submit("dig example.com")
    assert "netdns> dig example.com" in capsys.readouterr().out


def test_clear_sentinel_is_routed_to_clear_not_printed(capsys):
    cleared = []
    console = controller()
    console.clear = lambda: cleared.append(True)
    console._finish(CLEAR)
    assert cleared == [True]
    assert CLEAR not in capsys.readouterr().out


def test_a_closed_state_closes_the_window(capsys):
    closed = []
    console = controller()
    console.close = lambda: closed.append(True)
    console.state = ConsoleState(closed=True)
    console._finish("")
    assert closed == [True]


def test_a_reopened_console_is_not_born_closed():
    """`closed` is consumed when acted on; otherwise the next `show()` would
    hand back a window that shuts itself on the first command.
    """
    console = controller()
    console.close = lambda: None
    console.state = ConsoleState(closed=True)
    console._finish("")
    assert console.state.closed is False


def test_cwd_persists_across_lines(tmp_path):
    console = controller()
    console.run_line(f"cd {tmp_path}")
    assert console.state.cwd == str(tmp_path)
    seen = {}

    def runner(command, cwd, timeout):
        seen["cwd"] = cwd
        return CommandResult(stdout="")

    console.runner = runner
    console.run_line("ls")
    assert seen["cwd"] == str(tmp_path)


def test_the_status_provider_is_passed_through(capsys):
    console = controller(status=lambda: "state: healthy")
    console.run_line(":status")
    assert "state: healthy" in capsys.readouterr().out
