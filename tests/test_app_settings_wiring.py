"""The Settings window's Save and Reload, as wired into the rumps shell.

What these pin is that a saved value reaches the running app. The window itself
is never built: `_save_settings` is what its buttons call, and the parsing and
writing are covered by test_settings_window.py.
"""

import re

import pytest
import rumps
import yaml

from netdnsmonitor import app as app_module
from netdnsmonitor import distribution
from netdnsmonitor.app import NetDnsMonitorApp
from netdnsmonitor.config import ConfigError
from netdnsmonitor.settings_window import SERVICE_RESTART_HINT, STORE_RESTART_HINT

STORE = distribution.detect({"NETDNS_DISTRIBUTION": "appstore"})
DIRECT = distribution.detect({})


@pytest.fixture
def pinged(monkeypatch):
    """The ping job's two subprocesses, replaced where app.py bound them."""
    hosts = []

    def fake_ping_once(host, timeout_seconds):
        hosts.append(host)
        return {"ok": True, "rtt_ms": 1.0, "error": None}

    monkeypatch.setattr("netdnsmonitor.app.ping_once", fake_ping_once)
    monkeypatch.setattr("netdnsmonitor.app.read_interface_counters", lambda: None)
    return hosts


def build_app(tmp_path, capabilities=None):
    return NetDnsMonitorApp(config_path=str(tmp_path / "config.yaml"), capabilities=capabilities)


def test_a_saved_ping_host_is_what_the_running_heartbeat_pings(tmp_path, pinged):
    """The ping job holds the config dict it was built with. Rebinding
    `app.config` to a freshly loaded dict left it pinging the launch-time host
    until a restart, while the note said the change took effect immediately.
    """
    app = build_app(tmp_path)
    live = app.config

    note = app._save_settings({"ping_host": "9.9.9.9"})
    app.ping_job()

    assert pinged == ["9.9.9.9"]
    assert app.config is live
    assert note.startswith("Saved. These take effect immediately.")


def test_a_restart_only_key_keeps_its_launch_value_until_a_restart(tmp_path, pinged):
    """The flap gate was built with the launch threshold. A running config that
    claimed the new one would describe objects that do not exist.
    """
    app = build_app(tmp_path)
    launch_threshold = app.config["failure_threshold"]

    note = app._save_settings({"failure_threshold": str(launch_threshold + 3)})

    assert app.config["failure_threshold"] == launch_threshold
    on_disk = yaml.safe_load((tmp_path / "config.yaml").read_text().split("\n", 1)[1])
    assert on_disk["failure_threshold"] == launch_threshold + 3
    assert "failure_threshold" in note


def test_the_restart_note_names_only_the_keys_that_changed(tmp_path, pinged):
    """The window sends every field, so a note built from `updates` alone listed
    every restart-only key on every save.
    """
    app = build_app(tmp_path)

    note = app._save_settings(
        {
            "failure_threshold": str(app.config["failure_threshold"] + 1),
            "poll_interval_seconds": str(app.config["poll_interval_seconds"]),
            "ping_host": "9.9.9.9",
        }
    )

    assert "failure_threshold" in note
    assert "poll_interval_seconds" not in note
    assert "ping_host" not in note


def test_reload_applies_the_file_in_place_and_keeps_restart_keys(tmp_path, pinged):
    app = build_app(tmp_path)
    live = app.config
    launch_threshold = app.config["failure_threshold"]
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"ping_host": "1.0.0.1", "failure_threshold": launch_threshold + 5})
    )

    assert app._save_settings(None) == "Reloaded from disk."
    app.ping_job()

    assert app.config is live
    assert pinged == ["1.0.0.1"]
    assert app.config["failure_threshold"] == launch_threshold


def test_a_refused_reload_changes_nothing(tmp_path, pinged):
    """load_config raises ConfigError, which the window shows; the running config
    must not be half-applied on the way.
    """
    from netdnsmonitor.config import ConfigError

    app = build_app(tmp_path)
    before = dict(app.config)
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"ping_host": "1.0.0.1", "probe_timeout_seconds": 0})
    )

    with pytest.raises(ConfigError):
        app._save_settings(None)

    assert app.config == before


class FakeSettingsWindow:
    def __init__(self, on_save, **options):
        self.options = options
        self.loaded = None
        self.status = None

    def load(self, config):
        self.loaded = dict(config)

    def show(self):
        pass

    def set_status(self, text):
        self.status = text


def test_opening_settings_shows_the_file_not_the_running_config(tmp_path, monkeypatch):
    """Restart-only keys keep their launch values in `app.config`. The window
    edits the file, so it has to show the file.
    """
    monkeypatch.setattr("netdnsmonitor.app.SettingsWindow", FakeSettingsWindow)
    app = build_app(tmp_path)
    launch_threshold = app.config["failure_threshold"]
    (tmp_path / "config.yaml").write_text(
        yaml.safe_dump({"failure_threshold": launch_threshold + 2})
    )

    app.open_settings()

    assert app._settings.loaded["failure_threshold"] == launch_threshold + 2
    assert app._settings.status is None


def test_opening_settings_on_an_unreadable_file_says_why(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.app.SettingsWindow", FakeSettingsWindow)
    app = build_app(tmp_path)
    (tmp_path / "config.yaml").write_text("ping_host: [unclosed\n")

    app.open_settings()

    assert app._settings.loaded == app.config
    # A YAML error's message quotes the file, so only its class name is shown.
    status = app._settings.status
    assert re.fullmatch(r"Showing the running config; the file was not read -- \w+Error", status)
    assert "unclosed" not in app._settings.status


# --- the store build names its own restart and config file ------------------


@pytest.mark.parametrize(
    ("capabilities", "hint", "absent"),
    [(STORE, STORE_RESTART_HINT, "net-dns-monitor-service"), (DIRECT, SERVICE_RESTART_HINT, None)],
)
def test_the_restart_note_names_the_restart_this_build_has(tmp_path, capabilities, hint, absent):
    """The store build ships no service script: its note named a command that
    does not exist there.
    """
    app = build_app(tmp_path, capabilities=capabilities)
    launch_threshold = app.config["failure_threshold"]

    note = app._save_settings({"failure_threshold": str(launch_threshold + 3)})

    assert "failure_threshold" in note
    assert hint in note
    if absent is not None:
        assert absent not in note


def test_the_store_builds_settings_window_names_its_own_file_and_restart(tmp_path, monkeypatch):
    """Its config lives in the sandbox container, not at ~/.config."""
    monkeypatch.setattr("netdnsmonitor.app.SettingsWindow", FakeSettingsWindow)
    app = build_app(tmp_path, capabilities=STORE)

    app.open_settings()

    assert app._settings.options == {
        "config_path_display": app.config_path,
        "restart_hint": STORE_RESTART_HINT,
    }


def test_the_direct_builds_settings_window_keeps_its_defaults(tmp_path, monkeypatch):
    monkeypatch.setattr("netdnsmonitor.app.SettingsWindow", FakeSettingsWindow)
    app = build_app(tmp_path, capabilities=DIRECT)

    app.open_settings()

    assert app._settings.options == {}


# --- main() on a config the app refuses ---------------------------------------


@pytest.mark.parametrize(
    ("error", "shown"),
    [
        (
            ConfigError("failure_threshold", "config key 'failure_threshold': must be >= 1"),
            "ConfigError: config key 'failure_threshold': must be >= 1",
        ),
        (
            ValueError("config file /private/secret/config.yaml must contain a mapping"),
            "ValueError",
        ),
        (yaml.YAMLError("line 3 quotes: slack_webhook: https://hooks.example/secret"), "YAMLError"),
    ],
)
def test_main_on_a_refused_config_says_why_once_and_exits_2(
    tmp_path, capsys, monkeypatch, error, shown
):
    """Launched from Finder, the Dock or a LaunchAgent, a traceback on stderr is
    invisible: the app just never appeared, and Settings could not be opened to
    fix the file. Only a ConfigError's own text is shown; other messages quote
    the file.
    """
    monkeypatch.setattr(rumps, "alert", lambda *a, **k: pytest.fail("modal outside the seam"))
    alerts = []
    path = str(tmp_path / "config.yaml")

    def refusing_factory(config_path):
        assert config_path == path
        raise error

    with pytest.raises(SystemExit) as exited:
        app_module.main(
            app_factory=refusing_factory,
            startup_alert=lambda title, message: alerts.append((title, message)),
            config_path=path,
        )

    assert exited.value.code == 2
    assert alerts == [("Net-DNS-Monitor could not start", f"{shown}\n\nConfig file: {path}")]
    err = capsys.readouterr().err
    assert shown in err
    assert path in err
    assert "secret" not in err
    assert "Traceback" not in err


def test_main_still_exits_2_when_the_alert_itself_fails(tmp_path, capsys):
    def broken_alert(title, message):
        raise RuntimeError("no window server")

    def refusing_factory(config_path):
        raise ConfigError("ping_host", "config key 'ping_host': refused")

    with pytest.raises(SystemExit) as exited:
        app_module.main(
            app_factory=refusing_factory,
            startup_alert=broken_alert,
            config_path=str(tmp_path / "config.yaml"),
        )

    assert exited.value.code == 2
    assert "ping_host" in capsys.readouterr().err


def test_main_runs_the_app_it_built(tmp_path):
    ran = []

    class StartedApp:
        def run(self):
            ran.append(True)

    app_module.main(
        app_factory=lambda config_path: StartedApp(),
        startup_alert=lambda *a: pytest.fail("no alert for a good config"),
        config_path=str(tmp_path / "config.yaml"),
    )

    assert ran == [True]
