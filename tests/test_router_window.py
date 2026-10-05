"""Tests for the router console window's decisions.

The AppKit calls cannot be tested here. Everything around them can: every
subprocess, the Anthropic client, the worker thread and the hop back to the
main thread are injected, and `text_view is None` is the controller's headless
mode. Form values are passed straight to the handlers, which is the seam the
ObjC target skips by calling them with no arguments.
"""

from types import SimpleNamespace

import yaml

from netdnsmonitor import router_window
from netdnsmonitor.router_window import (
    RouterWindowController,
    ai_config_check,
    bootpd_status,
    collect_diagnostics,
    device_from_title,
    get_interfaces,
    ping_target,
    router_updates,
)

VALUES = {
    "wan_interface": "en3",
    "lan_interface": "en0",
    "lan_ip": "192.168.10.1",
    "lan_netmask": "255.255.255.0",
    "dhcp_start": "192.168.10.100",
    "dhcp_end": "192.168.10.200",
}


class Runner:
    """Fake subprocess.run keyed by argv[0] (or the whole argv joined)."""

    def __init__(self, outputs=None, returncode=0, raises=None):
        self.outputs = outputs or {}
        self.returncode = returncode
        self.raises = raises
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if self.raises is not None:
            raise self.raises
        key = " ".join(argv)
        stdout = self.outputs.get(key, self.outputs.get(argv[0], ""))
        return SimpleNamespace(returncode=self.returncode, stdout=stdout, stderr="")


class FakeRouter:
    def __init__(self, outcome="ok: started"):
        self.outcome = outcome
        self.started = 0
        self.stopped = 0

    def start(self):
        self.started += 1
        return self.outcome

    def stop(self):
        self.stopped += 1
        return "ok: stopped"


def controller(tmp_path=None, router=None, config=None, **kwargs):
    config = config if config is not None else {"sensitive_strings": []}
    app = SimpleNamespace(router=router, config=config)
    kwargs.setdefault("run_fn", Runner())
    kwargs.setdefault("post", lambda fn, *args: fn(*args))
    kwargs.setdefault("spawn", lambda fn: fn())
    kwargs.setdefault("environ", {})
    ctrl = RouterWindowController(
        config_getter=lambda: config,
        config_path=str(tmp_path / "config.yaml") if tmp_path is not None else None,
        app=app,
        **kwargs,
    )
    lines = []
    ctrl.append_log = lines.append
    return ctrl, lines


# --- helpers ----------------------------------------------------------------


def test_anthropic_and_appkit_are_not_module_level_imports():
    """`import anthropic` at module level cost ~300ms on every app start, and a
    module-level AppKit import is what kept this file out of the offline suite.
    """
    assert "anthropic" not in vars(router_window)
    assert "AppKit" not in vars(router_window)
    assert "objc" not in vars(router_window)


def test_get_interfaces_parses_networksetup_output():
    out = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: x\n\nHardware Port: USB LAN\nDevice: en13\n"
    run = Runner({"networksetup": out})
    assert get_interfaces(run) == ["Wi-Fi (en0)", "USB LAN (en13)"]
    assert run.calls[0][1]["timeout"]


def test_get_interfaces_returns_empty_when_the_command_fails():
    assert get_interfaces(Runner(raises=OSError("gone"))) == []
    assert get_interfaces(Runner(returncode=1)) == []


def test_device_from_title_does_not_guess_when_nothing_is_selected():
    assert device_from_title("Wi-Fi (en0)") == "en0"
    assert device_from_title(None) is None
    assert device_from_title("") is None


def test_router_updates_keeps_only_the_router_keys():
    updates = router_updates({**VALUES, "sensitive_strings": ["x"], "ping_host": "1.1.1.1"})
    assert set(updates) == set(VALUES)


def test_ping_target_rejects_option_injection():
    assert ping_target("8.8.8.8") == "8.8.8.8"
    assert ping_target("example.com") == "example.com"
    assert ping_target("-f") is None
    assert ping_target("-c 100000 8.8.8.8") is None
    assert ping_target("8.8.8.8; id") is None
    assert ping_target("") is None


def test_bootpd_status_reads_the_launchd_job_not_ps():
    run = Runner(returncode=0)
    assert bootpd_status(run) == "bootpd job loaded (UDP 67 held)"
    assert run.calls[0][0] == ["/bin/launchctl", "print", "system/com.apple.bootpd"]
    assert "ps" not in [argv[0] for argv, _ in run.calls]
    assert bootpd_status(Runner(returncode=113)) == "bootpd job not loaded"
    assert bootpd_status(Runner(raises=OSError())).startswith("bootpd job: not checked")


def test_every_diagnostic_subprocess_has_a_timeout():
    run = Runner({"netstat": "routes", "sysctl": "net.inet.ip.forwarding: 1\n"})
    collect_diagnostics(run, "en3", "en0")
    assert run.calls
    assert all(kwargs.get("timeout") for _, kwargs in run.calls)


def test_diagnostics_survive_a_failing_command():
    lines = collect_diagnostics(Runner(raises=OSError("boom")), "en3", "en0")
    assert any("not checked (OSError)" in line for line in lines)


def test_diagnostics_flag_same_wan_and_lan():
    lines = collect_diagnostics(Runner(), "en0", "en0")
    assert any("same interface" in line for line in lines)


# --- AI check -----------------------------------------------------------------


class FakeClient:
    def __init__(self, text="looks fine", raises=None):
        self.prompts = []
        self.kwargs = []
        self.raises = raises
        self.text = text
        self.messages = self

    def create(self, **kwargs):
        self.kwargs.append(kwargs)
        self.prompts.append(kwargs["messages"][0]["content"])
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(content=[SimpleNamespace(text=self.text)])


def test_ai_check_redacts_sensitive_strings_and_mac_addresses():
    client = FakeClient()
    run = Runner(
        {
            "netstat": "192.168.10.23  a4:83:e7:1:2:3  UHLWIi  en0\nsecret-host.corp 10.0.0.1",
            "sysctl": "net.inet.ip.forwarding: 1\n",
        }
    )
    out = ai_config_check(VALUES, run, ["secret-host.corp"], "key", client_factory=lambda: client)
    assert out == "\n[AI Analysis]\nlooks fine"
    prompt = client.prompts[0]
    assert "secret-host.corp" not in prompt
    assert "a4:83:e7:1:2:3" not in prompt
    assert "[REDACTED]" in prompt


def test_ai_check_uses_the_escalator_model_and_a_timeout():
    from netdnsmonitor.anthropic_escalator import DEFAULT_MODEL

    client = FakeClient()
    ai_config_check(VALUES, Runner(), [], "key", client_factory=lambda: client)
    assert client.kwargs[0]["model"] == DEFAULT_MODEL
    assert client.kwargs[0]["timeout"]


def test_ai_check_is_skipped_without_an_api_key():
    made = []
    out = ai_config_check(VALUES, Runner(), [], None, client_factory=lambda: made.append(1))
    assert out == "skipped: ANTHROPIC_API_KEY not set"
    assert made == []


def test_ai_check_failure_shows_only_the_exception_class_name():
    class AuthenticationError(Exception):
        pass

    client = FakeClient(raises=AuthenticationError("invalid x-api-key sk-ant-SECRET"))
    out = ai_config_check(VALUES, Runner(), [], "key", client_factory=lambda: client)
    assert "AuthenticationError" in out
    assert "sk-ant-SECRET" not in out


def test_ai_check_passes_the_key_to_the_default_client(monkeypatch):
    """A sandboxed app has no shell environment for the SDK's own lookup, so the
    key the caller resolved has to reach the client explicitly.
    """
    from netdnsmonitor import anthropic_escalator

    client = FakeClient()
    keys = []
    monkeypatch.setattr(
        anthropic_escalator, "default_client", lambda api_key=None: keys.append(api_key) or client
    )
    out = ai_config_check(VALUES, Runner(), [], "from-keychain")
    assert keys == ["from-keychain"]
    assert out == "\n[AI Analysis]\nlooks fine"


def test_ai_check_reads_the_key_from_the_getter_on_the_worker(tmp_path):
    client = FakeClient()
    reads = []
    jobs = []
    ctrl, lines = controller(
        tmp_path,
        client_factory=lambda: client,
        environ={},
        api_key_getter=lambda: reads.append(1) or "k",
        spawn=jobs.append,
    )
    ctrl.on_ai_check(VALUES)
    assert reads == []  # a Keychain read must not block the main thread
    jobs.pop()()
    assert reads == [1]
    assert lines[-1] == "\n[AI Analysis]\nlooks fine"


def test_a_failing_key_getter_is_reported_by_class_name_only(tmp_path):
    def broken():
        raise RuntimeError("keychain item sk-ant-SECRET")

    made = []
    ctrl, lines = controller(tmp_path, client_factory=lambda: made.append(1), api_key_getter=broken)
    ctrl.on_ai_check(VALUES)
    assert lines[-1] == "skipped: could not read ANTHROPIC_API_KEY (RuntimeError)"
    assert made == []


def test_ai_check_through_the_controller_posts_the_result(tmp_path):
    client = FakeClient(text="fine")
    ctrl, lines = controller(
        tmp_path,
        client_factory=lambda: client,
        environ={"ANTHROPIC_API_KEY": "k"},
        config={"sensitive_strings": ["192.168.10.1"]},
    )
    ctrl.on_ai_check(VALUES)
    assert lines[-1] == "\n[AI Analysis]\nfine"
    assert "192.168.10.1" not in client.prompts[0]


# --- controller -----------------------------------------------------------------


def test_save_config_writes_only_router_keys_and_keeps_the_rest(tmp_path):
    path = tmp_path / "config.yaml"
    original = "# my comment\nping_host: 9.9.9.9\nsensitive_strings:\n- corp\nlan_ip: 10.0.0.1\n"
    path.write_text(original)
    config = {"ping_host": "9.9.9.9", "sensitive_strings": ["corp"], "running_only": 1}
    router = FakeRouter()
    ctrl, lines = controller(tmp_path, router=router, config=config)

    assert ctrl.on_save_config(VALUES) is True

    saved = yaml.safe_load(path.read_text())
    assert saved["ping_host"] == "9.9.9.9"
    assert saved["sensitive_strings"] == ["corp"]
    assert saved["lan_ip"] == "192.168.10.1"
    assert "running_only" not in saved  # the running config was not dumped
    backups = list(tmp_path.glob("config.yaml.bak-*"))
    assert len(backups) == 1 and backups[0].read_text() == original
    assert router.lan_ip == "192.168.10.1"
    assert "saved" in lines[-1]


def test_save_config_failure_logs_the_class_name_only(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    ctrl, lines = controller(router=FakeRouter())
    ctrl.config_path = str(blocker / "config.yaml")
    assert ctrl.on_save_config(VALUES) is False
    assert lines[-1].startswith("Error saving config: ")
    assert str(blocker) not in lines[-1]


def test_save_config_refuses_without_both_interfaces(tmp_path):
    ctrl, lines = controller(tmp_path, router=FakeRouter())
    assert ctrl.on_save_config({**VALUES, "lan_interface": None}) is False
    assert not (tmp_path / "config.yaml").exists()


def test_start_refuses_same_wan_and_lan(tmp_path):
    router = FakeRouter()
    ctrl, lines = controller(tmp_path, router=router)
    ctrl.on_start({**VALUES, "lan_interface": "en3"})
    assert router.started == 0
    assert "refused: WAN and LAN are the same interface" in lines


def test_start_without_both_interfaces_never_reaches_the_router(tmp_path):
    """The save refuses an empty popup; start used to go ahead anyway on
    whatever interfaces the router already held.
    """
    router = FakeRouter()
    ctrl, lines = controller(tmp_path, router=router)
    ctrl.on_start({**VALUES, "wan_interface": None})
    assert router.started == 0
    assert "refused: select both a WAN and a LAN interface" in lines
    assert not (tmp_path / "config.yaml").exists()


def test_start_reports_the_routers_own_outcome(tmp_path):
    router = FakeRouter(
        outcome="failed: exit 1; steps before the failing one may have taken effect"
    )
    ctrl, lines = controller(tmp_path, router=router)
    ctrl.on_start(VALUES)
    assert router.started == 1
    assert lines[-1].startswith("Start router: failed: exit 1")
    assert not any("started via osascript" in line for line in lines)


def test_a_second_start_while_one_runs_is_refused(tmp_path):
    router = FakeRouter()
    ctrl, lines = controller(tmp_path, router=router, spawn=lambda fn: None)
    ctrl.on_start(VALUES)
    ctrl.on_start(VALUES)
    assert any("still running" in line for line in lines)


def test_a_failed_worker_start_does_not_strand_the_busy_flag(tmp_path):
    def dead(fn):
        raise RuntimeError("can't start new thread")

    ctrl, lines = controller(tmp_path, router=FakeRouter(), spawn=dead)
    ctrl.on_stop()
    assert ctrl._busy is False


class WorkerApp:
    """The app's side of the router worker: one slot shared with the menu."""

    def __init__(self, router, accept=True):
        self.router = router
        self.accept = accept
        self.jobs = []

    def _start_router_worker(self, slot, label, work, reveal=False):
        self.jobs.append((slot, label, work))
        return self.accept


def window_on(app, tmp_path):
    def no_own_worker(fn):
        raise AssertionError("the window started its own router worker")

    ctrl = RouterWindowController(
        config_getter=dict,
        config_path=str(tmp_path / "config.yaml"),
        app=app,
        run_fn=Runner(),
        post=lambda fn, *args: fn(*args),
        spawn=no_own_worker,
        environ={},
    )
    lines = []
    ctrl.append_log = lines.append
    return ctrl, lines


def test_router_actions_share_the_apps_worker_slot_with_the_menu(tmp_path):
    """Two guards on two threads let the menu and the window run root scripts
    at the same time; the app's slot is the one both must go through.
    """
    router = FakeRouter()
    app = WorkerApp(router)
    ctrl, lines = window_on(app, tmp_path)

    ctrl.on_start(VALUES)
    ctrl.on_stop()

    assert [(slot, label) for slot, label, _ in app.jobs] == [
        ("_router_thread", "Start router"),
        ("_router_thread", "Stop router"),
    ]
    assert router.started == 0  # queued on the app's worker, not run here
    assert app.jobs[0][2]() == "ok: started"
    assert lines[-1] == "Start router: ok: started"


def test_an_action_the_app_refuses_says_so_in_the_window(tmp_path):
    app = WorkerApp(FakeRouter(), accept=False)
    ctrl, lines = window_on(app, tmp_path)
    ctrl.on_stop()
    assert lines[-1] == "Stop router: not started (the notification says why)"


def test_a_raising_router_action_is_logged_by_class_name(tmp_path):
    class Broken(FakeRouter):
        def stop(self):
            raise RuntimeError("detail at /private/path")

    app = WorkerApp(Broken())
    ctrl, lines = window_on(app, tmp_path)
    ctrl.on_stop()
    assert app.jobs[0][2]() == "failed: RuntimeError"
    assert lines[-1] == "Stop router: failed: RuntimeError"


class FakePopup:
    def __init__(self):
        self.items = []
        self.selected = None

    def removeAllItems(self):
        self.items = []
        self.selected = None

    def addItemsWithTitles_(self, titles):
        self.items.extend(titles)

    def selectItemAtIndex_(self, index):
        # AppKit: -1 clears the selection.
        self.selected = None if index < 0 else index

    def titleOfSelectedItem(self):
        return self.items[self.selected] if self.selected is not None else None


class FakeField:
    def __init__(self, text):
        self.text = text

    def stringValue(self):
        return self.text


def fake_form(ctrl):
    """The widgets `_build_window` would create, for the handlers that read them."""
    ctrl.wan_popup, ctrl.lan_popup = FakePopup(), FakePopup()
    ctrl.lan_ip = FakeField(VALUES["lan_ip"])
    ctrl.lan_nm = FakeField(VALUES["lan_netmask"])
    ctrl.dhcp_s = FakeField(VALUES["dhcp_start"])
    ctrl.dhcp_e = FakeField(VALUES["dhcp_end"])


HARDWARE_PORTS = "Hardware Port: Wi-Fi\nDevice: en0\n\nHardware Port: USB LAN\nDevice: en3\n"


def test_interfaces_are_listed_on_the_worker_not_the_main_thread(tmp_path):
    """`networksetup` can take its full timeout; show() used to wait for it."""
    run = Runner({"networksetup": HARDWARE_PORTS})
    jobs = []
    config = {"wan_interface": "en3", "lan_interface": "en0"}
    ctrl, lines = controller(tmp_path, run_fn=run, spawn=jobs.append, config=config)
    fake_form(ctrl)

    assert ctrl._request_interfaces() is True
    assert run.calls == []

    jobs.pop()()
    assert ctrl.interfaces == ["Wi-Fi (en0)", "USB LAN (en3)"]
    assert ctrl.wan_popup.titleOfSelectedItem() == "USB LAN (en3)"
    assert ctrl.lan_popup.titleOfSelectedItem() == "Wi-Fi (en0)"
    assert jobs == []  # no refresh was asked for


def test_the_first_refresh_waits_for_the_selected_interfaces(tmp_path):
    run = Runner({"networksetup": HARDWARE_PORTS})
    jobs = []
    config = {"wan_interface": "en0", "lan_interface": "en0"}
    ctrl, lines = controller(tmp_path, run_fn=run, spawn=jobs.append, config=config)
    fake_form(ctrl)

    ctrl._request_interfaces(refresh=True)
    jobs.pop()()
    jobs.pop()()  # the diagnostics the populate step asked for
    assert "same interface" in lines[-1]


def test_an_empty_interface_list_is_said_after_the_refresh_clears_the_log(tmp_path):
    jobs = []
    ctrl, lines = controller(tmp_path, run_fn=Runner(returncode=1), spawn=jobs.append)
    fake_form(ctrl)
    cleared = []
    ctrl._clear_log = lambda: cleared.append(len(lines))

    ctrl._request_interfaces(refresh=True)
    jobs.pop()()
    assert ctrl.interfaces == []
    assert cleared == [0]
    assert lines == ["Could not list network interfaces."]


def test_a_worker_that_cannot_start_leaves_the_popups_empty(tmp_path):
    def dead(fn):
        raise RuntimeError("can't start new thread")

    run = Runner({"networksetup": HARDWARE_PORTS})
    ctrl, lines = controller(tmp_path, run_fn=run, spawn=dead)
    assert ctrl._request_interfaces() is False
    assert run.calls == []
    assert lines[-1] == "failed: could not start a worker (RuntimeError)"


def test_ping_refuses_an_option_and_never_runs(tmp_path):
    run = Runner()
    ctrl, lines = controller(tmp_path, run_fn=run)
    ctrl.on_ping("-f")
    assert run.calls == []
    assert lines[-1].startswith("\nrefused:")


def test_ping_result_is_posted_with_real_newlines(tmp_path):
    run = Runner({"ping": "4 packets transmitted\n"})
    ctrl, lines = controller(tmp_path, run_fn=run)
    ctrl.on_ping("8.8.8.8")
    assert run.calls[0][0] == ["ping", "-c", "4", "8.8.8.8"]
    assert run.calls[0][1]["timeout"]
    assert "4 packets transmitted\n" in lines
    assert not any("\\n" in line for line in lines)


def test_refresh_draws_diagnostics_without_literal_backslash_n(tmp_path):
    run = Runner({"netstat": "default 192.168.1.1 UGScg en3\n", "sysctl": "x: 1\n"})
    ctrl, lines = controller(tmp_path, run_fn=run)
    ctrl.on_refresh(VALUES)
    assert lines and "Routing Table" in lines[-1]
    assert not any("\\n" in line for line in lines)


def test_the_legacy_config_keyword_still_constructs(tmp_path):
    config = {"lan_interface": "en7"}
    app = SimpleNamespace(router=None, config_path=str(tmp_path / "c.yaml"))
    ctrl = RouterWindowController(config=config, app=app)
    assert ctrl.config_getter() is config
    assert ctrl.config_path == str(tmp_path / "c.yaml")
    assert ctrl._default("lan_interface") == "en7"
    assert ctrl._default("wan_interface") == "en3"


def test_failed_save_leaves_live_router_unchanged_and_refuses_start(tmp_path):
    router = FakeRouter()
    router.lan_ip = "192.168.10.2"
    ctrl, lines = controller(router=router)
    ctrl.on_start(VALUES)
    assert router.started == 0
    assert router.lan_ip == "192.168.10.2"
    assert any("not saved: no config file path" in line for line in lines)


def test_disk_save_failure_refuses_router_start(tmp_path):
    blocker = tmp_path / "blocked"
    blocker.write_text("not a directory")
    router = FakeRouter()
    router.lan_ip = "192.168.10.2"
    ctrl, _ = controller(router=router)
    ctrl.config_path = str(blocker / "config.yaml")
    ctrl.on_start(VALUES)
    assert router.started == 0
    assert router.lan_ip == "192.168.10.2"


# --- audit fixes -----------------------------------------------------------


def test_save_validates_router_values_even_when_router_is_disabled(tmp_path):
    ctrl, lines = controller(tmp_path, router=FakeRouter())
    bad = {**VALUES, "lan_ip": "$(reboot)", "lan_netmask": "x"}
    assert ctrl.on_save_config(bad) is False
    assert any(line.startswith("not saved: lan_ip") for line in lines)
    assert not (tmp_path / "config.yaml").exists()


def test_refused_start_does_not_mutate_live_router_or_config(tmp_path):
    router = FakeRouter()
    router.lan_ip = "192.168.10.2"
    config = {"sensitive_strings": []}
    ctrl, _ = controller(tmp_path, router=router, config=config)
    ctrl.app._start_router_worker = lambda slot, label, work: False
    ctrl.on_start(
        {
            **VALUES,
            "lan_ip": "192.168.77.1",
            "dhcp_start": "192.168.77.10",
            "dhcp_end": "192.168.77.20",
        }
    )
    assert router.lan_ip == "192.168.10.2"
    assert router.started == 0
    assert "lan_ip" not in config


def test_accepted_start_applies_values_inside_the_worker(tmp_path):
    router = FakeRouter()
    ctrl, _ = controller(tmp_path, router=router)
    seen = []

    def starter(slot, label, work):
        seen.append(getattr(router, "lan_ip", None))
        work()
        return True

    ctrl.app._start_router_worker = starter
    ctrl.on_start(VALUES)
    assert seen == [None]
    assert router.lan_ip == VALUES["lan_ip"]
    assert router.started == 1


def test_select_interface_with_no_match_clears_the_selection():
    ctrl, _ = controller()
    ctrl.interfaces = ["Wi-Fi (en0)", "USB LAN (en3)"]
    popup = FakePopup()
    popup.items = list(ctrl.interfaces)
    popup.selected = 0
    ctrl._select_interface(popup, "en9")
    assert popup.titleOfSelectedItem() is None
    ctrl._select_interface(popup, "en3")
    assert popup.titleOfSelectedItem() == "USB LAN (en3)"


def test_subprocess_calls_decode_utf8_with_replacement(tmp_path):
    run = Runner()
    ctrl, _ = controller(tmp_path, run_fn=run)
    get_interfaces(run)
    bootpd_status(run)
    collect_diagnostics(run, "en3", "en0")
    ctrl.on_ping("127.0.0.1")
    assert run.calls
    for _argv, kwargs in run.calls:
        assert kwargs.get("encoding") == "utf-8"
        assert kwargs.get("errors") == "replace"
