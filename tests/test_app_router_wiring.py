"""The Router menu and the Start at Login item, as wired into the rumps shell.

No test here runs osascript, sudo, pfctl, launchctl or networksetup: the Router
is a fake built through `router_factory`, every read goes through
`app.router_run_fn`, and notifications land on `app._notify`. HOME is a
per-test directory (conftest.py), so the login-item tests write their
LaunchAgents there.
"""

import os
import plistlib
import sys
import threading
import time
from types import SimpleNamespace

import pytest
import rumps
import yaml

import netdnsmonitor
from netdnsmonitor import app as app_module
from netdnsmonitor.app import (
    LOGIN_AGENT_LABEL,
    OPEN_BIN,
    SERVICE_AGENT_LABEL,
    NetDnsMonitorApp,
    login_agent_path,
    login_agent_plist,
)
from netdnsmonitor.credentials import ERR_SEC_ITEM_NOT_FOUND, CredentialStore
from netdnsmonitor.router_window import RouterWindowController


class FakeRouter:
    def __init__(self, **settings):
        self.settings = settings
        self.wan_if = settings.get("wan_if")
        self.lan_if = settings.get("lan_if")
        self.calls = []
        self.release = threading.Event()
        self.release.set()

    def start(self):
        self.calls.append("start")
        self.release.wait(timeout=5)
        return "ok: router started (read back: NAT en0 -> en3)"

    def stop(self):
        self.calls.append("stop")
        self.release.wait(timeout=5)
        return "cancelled: nothing was changed"


@pytest.fixture(autouse=True)
def _no_modal_alerts(monkeypatch):
    """rumps.alert is modal: it holds the run loop, and every timer, until
    someone clicks. No router path may reach it.
    """
    monkeypatch.setattr(
        rumps, "alert", lambda *a, **k: pytest.fail("rumps.alert must never be called")
    )


def build_app(tmp_path, router_enabled=True, **config):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"router_enabled": router_enabled, **config}))
    built = []

    def factory(**settings):
        router = FakeRouter(**settings)
        built.append(router)
        return router

    app = NetDnsMonitorApp(config_path=str(path), router_factory=factory)
    app.notes = []
    app._notify = lambda subtitle, message: app.notes.append((subtitle, message))
    app.output = []
    app._append_output = app.output.append
    app.open_dashboard = lambda *a, **k: app.notes.append(("dashboard", "opened"))
    app.built_routers = built
    return app


def drain(app, *threads):
    for thread in threads:
        if thread is not None:
            thread.join(timeout=5)
            assert not thread.is_alive(), "router worker hung"
    app._drain_router_results()


# --- launch -----------------------------------------------------------------


def test_constructing_the_app_with_the_router_enabled_starts_nothing(tmp_path):
    """Starting runs a root script behind the admin dialog. From __init__ that
    dialog appeared at every launch and login, and the app waited on it before
    any monitoring timer had run.
    """
    app = build_app(tmp_path, router_enabled=True, wan_interface="en5", lan_interface="en6")

    assert app.router is app.built_routers[0]
    assert app.router.calls == []
    assert app.router.settings["wan_if"] == "en5"
    assert app.router.settings["lan_if"] == "en6"
    assert app.router.settings["lan_ip"] == app.config["lan_ip"]


def test_constructing_the_app_with_the_router_disabled_builds_none(tmp_path):
    app = build_app(tmp_path, router_enabled=False)
    assert app.router is None
    assert app.built_routers == []


# --- start and stop ---------------------------------------------------------


@pytest.mark.parametrize(
    ("handler", "label", "outcome"),
    [
        ("start_router", "Start router", "ok: router started"),
        ("stop_router", "Stop router", "cancelled: nothing was changed"),
    ],
)
def test_start_and_stop_return_before_the_admin_dialog_is_answered(
    tmp_path, handler, label, outcome
):
    app = build_app(tmp_path)
    app.router.release.clear()  # the dialog is open and nobody has answered

    started = time.monotonic()
    getattr(app, handler)(None)
    assert time.monotonic() - started < 1.0

    app.router.release.set()
    drain(app, app._router_thread)

    assert app.router.calls == [handler.split("_")[0]]
    assert any(label in text and outcome in text for text in app.output)
    assert any(message.startswith(f"{label}: {outcome}") for _s, message in app.notes)


def test_a_second_start_while_the_first_waits_is_refused_not_stacked(tmp_path):
    app = build_app(tmp_path)
    app.router.release.clear()
    app.start_router(None)
    first = app._router_thread

    app.start_router(None)

    assert app._router_thread is first
    assert any("still running" in message for _s, message in app.notes)
    app.router.release.set()
    drain(app, first)
    assert app.router.calls == ["start"]


@pytest.mark.parametrize("handler", ["start_router", "stop_router"])
def test_start_and_stop_with_the_router_disabled_say_so(tmp_path, handler):
    """They used to return silently, which reads as "it worked"."""
    app = build_app(tmp_path, router_enabled=False)

    getattr(app, handler)(None)

    assert app._router_thread is None
    assert ("Router", "Router disabled (set router_enabled)") in app.notes


def test_a_raising_router_is_reported_by_class_name(tmp_path):
    app = build_app(tmp_path)

    def boom():
        raise RuntimeError("/tmp/secret-script failed")

    app.router.start = boom
    app.start_router(None)
    drain(app, app._router_thread)

    assert any("failed: RuntimeError" in text for text in app.output)
    assert not any("secret-script" in text for text in app.output)


# --- the menu and the router window share one worker slot ------------------

WINDOW_VALUES = {
    "wan_interface": "en5",
    "lan_interface": "en6",
    "lan_ip": "192.168.10.1",
    "lan_netmask": "255.255.255.0",
    "dhcp_start": "192.168.10.100",
    "dhcp_end": "192.168.10.200",
}


def window_for(app):
    """A real RouterWindowController on the real app, with no window and no
    worker of its own: every router action it takes must go through the app.
    """
    started_own = []
    ran = []
    controller = RouterWindowController(
        config_getter=lambda: app.config,
        config_path=app.config_path,
        app=app,
        run_fn=lambda *args, **kwargs: ran.append(args),
        post=lambda fn, *args: fn(*args),
        spawn=started_own.append,
        environ={},
    )
    controller.lines = []
    controller.append_log = controller.lines.append
    controller.started_own = started_own
    controller.ran = ran
    return controller


def test_a_window_start_waiting_on_its_dialog_makes_the_menu_stop_refuse(tmp_path):
    """The window and the menu used to guard with two separate flags, so a Stop
    from the menu ran its root script while the window's Start was still inside
    its own.
    """
    app = build_app(tmp_path)
    window = window_for(app)
    app.router.release.clear()  # the window's admin dialog is open

    window.on_start(WINDOW_VALUES)
    running = app._router_thread
    assert running is not None and running.is_alive()

    app.stop_router(None)

    assert app._router_thread is running
    assert ("Router", "Stop router: the previous router action is still running.") in app.notes
    app.router.release.set()
    drain(app, running)
    assert app.router.calls == ["start"]
    assert window.started_own == [] and window.ran == []
    assert window.lines[-1] == "Start router: ok: router started (read back: NAT en0 -> en3)"
    assert any(message.startswith("Start router: ok:") for _s, message in app.notes)


@pytest.mark.parametrize(
    ("window_action", "label"),
    [("on_stop", "Stop router"), ("on_start", "Start router")],
)
def test_a_menu_start_waiting_on_its_dialog_makes_the_window_refuse(tmp_path, window_action, label):
    app = build_app(tmp_path)
    window = window_for(app)
    app.router.release.clear()  # the menu's admin dialog is open
    app.start_router(None)
    running = app._router_thread

    args = (WINDOW_VALUES,) if window_action == "on_start" else ()
    getattr(window, window_action)(*args)

    assert app._router_thread is running
    assert window.lines[-1] == f"{label}: not started (the notification says why)"
    assert ("Router", f"{label}: the previous router action is still running.") in app.notes
    app.router.release.set()
    drain(app, running)
    assert app.router.calls == ["start"]
    assert window.started_own == [] and window.ran == []


# --- read-only router menu items --------------------------------------------

HARDWARE_PORTS = (
    "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: Thunderbolt Ethernet\nDevice: en3\n"
)


def recording_run(outputs=None, raises=None):
    calls = []

    def run(argv, **kwargs):
        calls.append({"argv": list(argv), **kwargs})
        if raises is not None and argv[0] in raises:
            raise raises[argv[0]]
        stdout = (outputs or {}).get(argv[0], "")
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    run.calls = calls
    return run


def test_list_interfaces_runs_off_the_run_loop_and_shows_them_in_the_pane(tmp_path):
    app = build_app(tmp_path)
    gate = threading.Event()
    inner = recording_run({"networksetup": HARDWARE_PORTS})

    def slow_run(argv, **kwargs):
        gate.wait(timeout=5)
        return inner(argv, **kwargs)

    app.router_run_fn = slow_run

    started = time.monotonic()
    app.list_interfaces(None)
    assert time.monotonic() - started < 1.0

    gate.set()
    drain(app, app._router_info_thread)

    text = "".join(app.output)
    assert "Wi-Fi (en0)" in text
    assert "Thunderbolt Ethernet (en3)" in text
    assert ("dashboard", "opened") in app.notes
    assert all(call.get("timeout") for call in inner.calls)


def test_a_failed_interface_listing_says_so_rather_than_alerting(tmp_path):
    app = build_app(tmp_path)
    app.router_run_fn = recording_run(raises={"networksetup": FileNotFoundError("networksetup")})

    app.list_interfaces(None)
    drain(app, app._router_info_thread)

    assert any("Could not list network interfaces." in text for text in app.output)


def test_troubleshoot_never_lets_sudo_prompt_and_shows_class_names_only(tmp_path):
    """A sudo that can prompt waits on a terminal the app does not have. The
    failure text is a class name: an exception message can carry command output.
    """
    app = build_app(tmp_path)
    run = recording_run(
        outputs={
            "netstat": "default 192.168.1.1 UGScg en0\n",
            "sysctl": "net.inet.ip.forwarding: 0\n",
        },
        raises={"/usr/bin/sudo": PermissionError("sudo: a password is required for mitch")},
    )
    app.router_run_fn = run

    started = time.monotonic()
    app.troubleshoot_router(None)
    assert time.monotonic() - started < 1.0
    drain(app, app._router_info_thread)

    sudo_calls = [call["argv"] for call in run.calls if call["argv"][0].endswith("sudo")]
    assert sudo_calls, "the NAT rules were not read"
    assert all(argv[1] == "-n" for argv in sudo_calls)
    assert all(call.get("timeout") for call in run.calls)

    text = "".join(app.output)
    assert "net.inet.ip.forwarding: 0" in text
    assert "not checked (PermissionError)" in text
    assert "password is required" not in text
    assert "mitch" not in text


def test_troubleshoot_reads_the_live_router_interfaces(tmp_path):
    app = build_app(tmp_path)
    app.router.wan_if = app.router.lan_if = "en7"  # as the router window would set them
    app.router_run_fn = recording_run()

    app.troubleshoot_router(None)
    drain(app, app._router_info_thread)

    assert "OBVIOUS CONFLICT" in "".join(app.output)


def test_configure_opens_the_config_file_the_app_loaded_creating_it(tmp_path):
    """The path was hardcoded, and `open -t` on a missing file shows nothing."""
    app = build_app(tmp_path)
    app.config_path = str(tmp_path / "nested" / "other.yaml")
    run = recording_run()
    app.router_run_fn = run

    app.configure_router(None)

    assert os.path.isfile(app.config_path)
    assert run.calls[0]["argv"] == [OPEN_BIN, "-t", app.config_path]
    assert run.calls[0]["timeout"]
    assert app.notes == []


def test_configure_reports_an_open_that_failed(tmp_path):
    app = build_app(tmp_path)
    app.router_run_fn = lambda argv, **kwargs: SimpleNamespace(returncode=1, stdout="", stderr="")

    app.configure_router(None)

    assert any("open exited 1" in message for _s, message in app.notes)


# --- the router window --------------------------------------------------------


class RecordingController:
    instances = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.shown = 0
        RecordingController.instances.append(self)

    def show(self):
        self.shown += 1


def test_the_router_window_reads_the_live_config_and_the_apps_path(tmp_path, monkeypatch):
    """A dict captured at open went stale when Settings replaced it, and the
    window then wrote the stale copy back over the user's edits.
    """
    RecordingController.instances = []
    monkeypatch.setattr(app_module, "RouterWindowController", RecordingController)
    app = build_app(tmp_path)

    app.open_router_window(None)
    app.open_router_window(None)

    assert len(RecordingController.instances) == 1
    controller = RecordingController.instances[0]
    assert controller.shown == 2
    assert controller.kwargs["config_path"] == app.config_path
    assert controller.kwargs["app"] is app
    assert controller.kwargs["config_getter"]() is app.config
    assert "config" not in controller.kwargs


class KeychainWithKey:
    def __init__(self, items):
        self.items = {name: value.encode() for name, value in items.items()}

    def read(self, account):
        if account not in self.items:
            return ERR_SEC_ITEM_NOT_FOUND, None
        return 0, self.items[account]


def test_the_router_windows_ai_check_reads_the_key_from_the_apps_credential_store(
    tmp_path, monkeypatch
):
    """An app launched from Finder or the Dock has no shell environment, so a
    key saved in the Keychain is the only one it can have. The window read
    os.environ, and the AI check said the key was missing.
    """
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    RecordingController.instances = []
    monkeypatch.setattr(app_module, "RouterWindowController", RecordingController)
    app = build_app(tmp_path)
    keychain = KeychainWithKey({"ANTHROPIC_API_KEY": "sk-ant-keychain-not-real"})
    app.credentials = CredentialStore(env={}, backend_factory=lambda: keychain)

    app.open_router_window(None)

    getter = RecordingController.instances[0].kwargs["api_key_getter"]
    assert getter() == "sk-ant-keychain-not-real"
    # Read when the check runs, not captured when the window opened.
    keychain.items.clear()
    assert getter() is None


def test_a_router_window_that_fails_to_open_notifies_and_is_rebuilt_next_time(
    tmp_path, monkeypatch
):
    class BrokenController(RecordingController):
        def show(self):
            raise RuntimeError("no window server at /private/path")

    monkeypatch.setattr(app_module, "RouterWindowController", BrokenController)
    app = build_app(tmp_path)

    app.open_router_window(None)

    assert app.router_window is None
    assert app.notes == [
        ("Router console", "Could not open the router console window (RuntimeError).")
    ]


# --- start at login -----------------------------------------------------------


class Sender:
    def __init__(self, state=False):
        self.state = state


SOURCE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(netdnsmonitor.__file__)))


def test_turning_login_on_writes_an_agent_for_this_interpreter_and_checkout(tmp_path):
    """The agent this replaced ran one named user's checkout, so on any other
    account it started nothing -- while the item showed a checkmark.
    """
    app = build_app(tmp_path)
    sender = Sender(state=False)

    app.toggle_login(sender)

    with open(login_agent_path(LOGIN_AGENT_LABEL), "rb") as f:
        plist = plistlib.load(f)
    assert plist["Label"] == LOGIN_AGENT_LABEL
    assert plist["ProgramArguments"] == [sys.executable, "-m", "netdnsmonitor.app"]
    assert plist["WorkingDirectory"] == SOURCE_ROOT
    assert "mitch.hudson" not in str(plist)
    assert login_agent_path(LOGIN_AGENT_LABEL).startswith(os.environ["HOME"])
    assert sender.state is True


def test_turning_login_off_removes_the_agent(tmp_path):
    app = build_app(tmp_path)
    sender = Sender()
    app.toggle_login(sender)

    app.toggle_login(sender)

    assert not os.path.exists(login_agent_path(LOGIN_AGENT_LABEL))
    assert sender.state is False


def test_a_failed_write_leaves_the_item_unchecked_and_says_why(tmp_path):
    """The checkmark used to flip before the write, so a failure left it on."""
    app = build_app(tmp_path)
    library = os.path.join(os.environ["HOME"], "Library")
    os.makedirs(library, exist_ok=True)
    with open(os.path.join(library, "LaunchAgents"), "w") as f:
        f.write("not a directory")
    sender = Sender(state=False)

    app.toggle_login(sender)

    assert sender.state is False
    assert len(app.notes) == 1
    subtitle, message = app.notes[0]
    assert subtitle == "Start at Login"
    assert message.startswith("Not changed (")


def test_the_service_scripts_agent_counts_as_on_and_is_not_removed(tmp_path):
    """net-dns-monitor-service installs its own agent, which carries the
    supervision flag. The item shows it, and leaves removing it to the script.
    """
    service = login_agent_path(SERVICE_AGENT_LABEL)
    os.makedirs(os.path.dirname(service), exist_ok=True)
    with open(service, "wb") as f:
        plistlib.dump({"Label": SERVICE_AGENT_LABEL}, f)

    app = build_app(tmp_path)
    assert app.menu["Start at Login"].state
    sender = Sender(state=True)

    app.toggle_login(sender)

    assert os.path.exists(service)
    assert sender.state is True
    assert any("net-dns-monitor-service uninstall" in message for _s, message in app.notes)


def test_a_frozen_app_starts_its_own_bundle_executable():
    plist = login_agent_plist(
        True, "/Applications/Net-DNS-Monitor.app/Contents/MacOS/Net-DNS-Monitor", "/ignored"
    )
    assert plist["ProgramArguments"] == [
        "/Applications/Net-DNS-Monitor.app/Contents/MacOS/Net-DNS-Monitor"
    ]
    assert "WorkingDirectory" not in plist
