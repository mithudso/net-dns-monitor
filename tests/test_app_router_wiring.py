"""The Router submenu and the login item, as wired into the rumps shell.

Nothing here runs `osascript`, `sudo`, `pfctl`, `networksetup` or `open`: the
router is a fake, the login plist lands under the per-test HOME that
conftest.py redirects, and every subprocess the menu items start goes through
the app's `run_fn` seam.
"""

import os
import plistlib
import stat
import subprocess
import sys
import threading
import time

import pytest

from netdnsmonitor import privileges
from netdnsmonitor.app import OPEN_BIN, NetDnsMonitorApp


class FakeRouter:
    """Records what the app asked of it and answers with a canned status."""

    built: list = []
    started: list = []
    stopped: list = []
    start_status = "ok"

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    @classmethod
    def from_config(cls, config, **seams):
        router = cls(**{k: config.get(k) for k in ("wan_interface", "lan_interface")})
        cls.built.append(router)
        return router

    def start(self) -> str:
        self.started.append(self)
        return self.start_status

    def stop(self) -> str:
        self.stopped.append(self)
        return "ok"


class Sender:
    """A rumps.MenuItem stand-in: the one attribute toggle_login reads and writes."""

    state = False


@pytest.fixture(autouse=True)
def _fake_router(monkeypatch):
    FakeRouter.built = []
    FakeRouter.started = []
    FakeRouter.stopped = []
    FakeRouter.start_status = "ok"
    monkeypatch.setattr("netdnsmonitor.app.Router", FakeRouter)


@pytest.fixture(autouse=True)
def _quiet_rumps(monkeypatch):
    """Notifications and alerts are recorded, not shown."""
    notes = []
    monkeypatch.setattr("rumps.notification", lambda *a, **k: notes.append(" ".join(map(str, a))))
    monkeypatch.setattr(
        "rumps.alert", lambda *a, **k: notes.append(" ".join(map(str, a)) + " " + str(k))
    )
    return notes


def build_app(tmp_path, **config):
    path = tmp_path / "config.yaml"
    if config:
        path.write_text("".join(f"{k}: {v}\n" for k, v in config.items()))
    return NetDnsMonitorApp(config_path=str(path))


def finish(app):
    if app._action_thread is not None:
        app._action_thread.join(timeout=5)
        assert not app._action_thread.is_alive(), "router worker hung"
    app.ui_tick()


def completed(argv, stdout="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")


# --- the router itself -------------------------------------------------------


def test_router_is_not_started_during_construction(tmp_path):
    """`Router.start()` ends in an `osascript ... with administrator privileges`
    dialog. In `__init__` that would raise a password prompt before the run loop
    exists, and the tests that construct this class would each hit it.
    """
    app = build_app(tmp_path, router_enabled="true")
    assert FakeRouter.started == []
    assert app.router is None


def test_starting_the_router_from_the_menu_reports_the_status_it_returned(tmp_path, _quiet_rumps):
    """`start()` answers `ok`, `NEEDS_PRIVILEGE` or `failed: ...`; a click that
    discards that answer leaves someone unable to tell a refused start from a
    successful one.
    """
    FakeRouter.start_status = "NEEDS_PRIVILEGE"
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append

    app.start_router(None)
    finish(app)

    assert len(FakeRouter.started) == 1
    assert any("NEEDS_PRIVILEGE" in note for note in _quiet_rumps)
    assert "Router start: NEEDS_PRIVILEGE" in "".join(output)


def test_starting_the_router_does_not_run_on_the_run_loop(tmp_path):
    """The admin dialog waits for a human, up to two minutes. Inline, that would
    freeze the window and every timer until someone typed a password.
    """
    release = threading.Event()

    class BlockingRouter(FakeRouter):
        def start(self) -> str:
            release.wait(timeout=5)
            return "ok"

    app = build_app(tmp_path)
    app.router = BlockingRouter()
    started = time.monotonic()
    app.start_router(None)
    assert time.monotonic() - started < 1.0
    release.set()
    finish(app)


def test_stopping_a_router_that_was_never_started_says_so(tmp_path, _quiet_rumps):
    app = build_app(tmp_path)
    app.stop_router(None)
    finish(app)
    assert FakeRouter.stopped == []
    assert any("not been started" in note for note in _quiet_rumps)


def test_stopping_the_router_reports_the_status_it_returned(tmp_path, _quiet_rumps):
    app = build_app(tmp_path)
    app.start_router(None)
    finish(app)
    app.stop_router(None)
    finish(app)
    assert len(FakeRouter.stopped) == 1
    assert any("Router stop: ok" in note for note in _quiet_rumps)


# --- the shell-out menu items -------------------------------------------------


def test_troubleshoot_router_uses_non_interactive_sudo_with_a_deadline(tmp_path, monkeypatch):
    """A bare `sudo` on the run loop waits for a password nobody can type into
    a menu bar app, and `check_output` without a timeout waits forever.
    """
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        text = {"pfctl": "nat on en3\n", "sysctl": "net.inet.ip.forwarding: 1\n"}.get(
            os.path.basename(argv[2] if argv[1] == "-n" else argv[0]), "root 1 bootpd\n"
        )
        return completed(argv, stdout=text)

    app = build_app(tmp_path)
    # Belt and braces for the pre-fix shape, which shelled out directly: a real
    # `sudo pfctl` must never run from the suite, whatever the app does.
    monkeypatch.setattr(
        "netdnsmonitor.app.subprocess.check_output",
        lambda *a, **k: pytest.fail("router diagnostics must go through run_fn"),
    )
    app.run_fn = fake_run
    output = []
    app._append_output = output.append

    app.troubleshoot_router(None)
    finish(app)

    assert calls, "no command was run"
    assert calls[0][0][:2] == [privileges.SUDO, "-n"]
    assert all(0 < kwargs.get("timeout", 0) <= 5 for _argv, kwargs in calls)
    text = "".join(output)
    assert "DHCP server running: True" in text
    assert "nat on en3" in text


def test_troubleshoot_router_reports_a_refused_sudo_by_class_name(tmp_path, monkeypatch):
    def refused(argv, **kwargs):
        raise subprocess.CalledProcessError(1, argv, output="sudo: a password is required")

    app = build_app(tmp_path)
    monkeypatch.setattr(
        "netdnsmonitor.app.subprocess.check_output",
        lambda *a, **k: pytest.fail("router diagnostics must go through run_fn"),
    )
    app.run_fn = refused
    output = []
    app._append_output = output.append

    app.troubleshoot_router(None)
    finish(app)

    text = "".join(output)
    assert "Need sudo for full diagnostics. (CalledProcessError)" in text
    assert "a password is required" not in text


def test_list_interfaces_reports_a_failed_command_instead_of_raising(tmp_path, _quiet_rumps):
    def missing(argv, **kwargs):
        raise OSError("networksetup vanished")

    app = build_app(tmp_path)
    app.run_fn = missing
    app.list_interfaces(None)
    assert any("Could not list interfaces (OSError)" in note for note in _quiet_rumps)
    assert not any("vanished" in note for note in _quiet_rumps)


def test_list_interfaces_bounds_the_command(tmp_path, _quiet_rumps):
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((list(argv), kwargs))
        return completed(argv, stdout="Hardware Port: Wi-Fi\nDevice: en0\n")

    app = build_app(tmp_path)
    app.run_fn = fake_run
    app.list_interfaces(None)
    assert calls[0][0] == ["networksetup", "-listallhardwareports"]
    assert 0 < calls[0][1].get("timeout", 0) <= 10
    assert any("Hardware Port: Wi-Fi" in note for note in _quiet_rumps)


def test_configure_router_opens_the_configured_path(tmp_path, monkeypatch):
    """Not the default path: an app started with `--config` elsewhere would
    otherwise open a file it is not reading.
    """
    calls = []
    app = build_app(tmp_path)
    monkeypatch.setattr(
        "netdnsmonitor.app.subprocess.run",
        lambda *a, **k: pytest.fail("configure_router must go through run_fn"),
    )
    app.run_fn = lambda argv, **kwargs: calls.append((list(argv), kwargs)) or completed(argv)

    app.configure_router(None)

    assert calls[0][0] == [OPEN_BIN, "-t", str(tmp_path / "config.yaml")]
    assert 0 < calls[0][1].get("timeout", 0) <= 10


def test_configure_router_survives_a_missing_open(tmp_path):
    def missing(argv, **kwargs):
        raise OSError("no open")

    app = build_app(tmp_path)
    app.run_fn = missing
    app.configure_router(None)  # a menu click must not raise


def test_open_router_window_failure_costs_the_window_not_the_app(
    tmp_path, monkeypatch, _quiet_rumps
):
    class BrokenController:
        def __init__(self, *args, **kwargs):
            pass

        def show(self):
            raise RuntimeError("AppKit said no")

    monkeypatch.setattr("netdnsmonitor.app.RouterWindowController", BrokenController)
    app = build_app(tmp_path)
    app.open_router_window(None)
    assert app.router_window is None
    assert any("Could not open the router window (RuntimeError)" in n for n in _quiet_rumps)


def test_open_router_window_hands_the_controller_the_real_config_path(tmp_path, monkeypatch):
    seen = {}

    class RecordingController:
        def __init__(self, config, app, **kwargs):
            seen.update(kwargs)

        def show(self):
            pass

    monkeypatch.setattr("netdnsmonitor.app.RouterWindowController", RecordingController)
    app = build_app(tmp_path)
    app.open_router_window(None)
    assert seen["config_path"] == str(tmp_path / "config.yaml")


# --- start at login ------------------------------------------------------------


def agent_plist(home_dir):
    return home_dir / "Library" / "LaunchAgents" / "com.netdnsmonitor.plist"


def test_toggle_login_writes_a_plist_pointing_at_this_interpreter(tmp_path, isolate_home):
    """The launch agent must start the checkout that wrote it, with the
    interpreter that is running -- a hardcoded path is a different machine.
    """
    app = build_app(tmp_path)
    sender = Sender()

    app.toggle_login(sender)

    assert sender.state is True
    with open(agent_plist(isolate_home), "rb") as f:
        data = plistlib.load(f)
    assert data["ProgramArguments"] == [sys.executable, "-m", "netdnsmonitor.app"]
    assert os.path.isfile(os.path.join(data["WorkingDirectory"], "netdnsmonitor", "app.py"))
    assert data["RunAtLoad"] is True


def test_toggle_login_leaves_the_checkbox_off_when_the_write_fails(
    tmp_path, isolate_home, _quiet_rumps
):
    """A ticked box beside a plist that does not exist tells someone the app
    will start at login when it will not.
    """
    if os.geteuid() == 0:
        pytest.skip("root ignores directory modes")
    agents = isolate_home / "Library" / "LaunchAgents"
    agents.mkdir(parents=True)
    agents.chmod(stat.S_IRUSR | stat.S_IXUSR)
    app = build_app(tmp_path)
    sender = Sender()
    try:
        app.toggle_login(sender)
    finally:
        agents.chmod(stat.S_IRWXU)

    assert sender.state is False
    assert not agent_plist(isolate_home).exists()
    assert any("Could not update the login item (PermissionError)" in n for n in _quiet_rumps)


def test_toggle_login_off_removes_the_plist(tmp_path, isolate_home):
    app = build_app(tmp_path)
    sender = Sender()
    app.toggle_login(sender)
    assert agent_plist(isolate_home).exists()

    app.toggle_login(sender)

    assert sender.state is False
    assert not agent_plist(isolate_home).exists()
