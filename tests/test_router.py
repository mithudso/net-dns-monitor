"""Tests for the bootpd/pf router and its window controller.

Nothing here runs osascript, sudo, pfctl or a network command. `run_fn`,
`tmp_dir`, `on_main`, `spawn` and `client_factory` are injected, so what is
under test is the script text the router would hand to root, the validation
in front of it, and how each outcome is reported back to the window.
"""

import os
import plistlib
import subprocess

import yaml

from netdnsmonitor.anthropic_escalator import DEFAULT_MODEL, DEFAULT_TIMEOUT_SECONDS
from netdnsmonitor.repair_executor import NETSTAT
from netdnsmonitor.router import PF_ANCHOR, Router
from netdnsmonitor.router_window import ROUTER_KEYS, RouterWindowController, get_interfaces

SETTINGS = {
    "wan_if": "en0",
    "lan_if": "en1",
    "lan_ip": "192.168.10.1",
    "lan_netmask": "255.255.255.0",
    "dhcp_start": "192.168.10.100",
    "dhcp_end": "192.168.10.200",
}


class Proc:
    def __init__(self, returncode, stderr=b""):
        self.returncode = returncode
        self.stderr = stderr


class Recorder:
    """A `run_fn` that answers pgrep and osascript separately and keeps every argv."""

    def __init__(self, osascript=None, dnsmasq_running=False):
        self.calls = []
        self.osascript = osascript if osascript is not None else Proc(0)
        self.dnsmasq_running = dnsmasq_running

    def __call__(self, argv, timeout):
        self.calls.append(argv)
        if argv[0] == "pgrep":
            return Proc(0 if self.dnsmasq_running else 1)
        return self.osascript

    def osascript_calls(self):
        return [c for c in self.calls if c[0] == "osascript"]


def router(tmp_path, run_fn=None, **overrides):
    return Router(
        **{**SETTINGS, **overrides},
        run_fn=run_fn if run_fn is not None else Recorder(),
        tmp_dir=str(tmp_path),
    )


def read(tmp_path, name):
    with open(os.path.join(tmp_path, name), encoding="utf-8") as f:
        return f.read()


# --- router.py: outcome reporting -------------------------------------------


def test_start_reports_ok_only_when_osascript_exits_zero(tmp_path):
    assert router(tmp_path).start() == "ok"


def test_cancelled_admin_dialog_is_needs_privilege_not_ok(tmp_path):
    run_fn = Recorder(osascript=Proc(1, b"execution error: User canceled. (-128)"))
    assert router(tmp_path, run_fn).start() == "NEEDS_PRIVILEGE"


def test_other_osascript_failure_carries_the_exit_code(tmp_path):
    run_fn = Recorder(osascript=Proc(1, b"sh: pfctl: syntax error"))
    assert router(tmp_path, run_fn).start() == "failed: osascript rc=1"


def test_a_raising_run_fn_is_reported_as_its_class_name(tmp_path):
    def explode(argv, timeout):
        if argv[0] == "pgrep":
            return Proc(1)
        raise subprocess.TimeoutExpired(argv, timeout)

    assert router(tmp_path, explode).start() == "failed: TimeoutExpired"


def test_stop_reports_the_admin_outcome_too(tmp_path):
    run_fn = Recorder(osascript=Proc(1, b"User canceled."))
    assert router(tmp_path, run_fn).stop() == "NEEDS_PRIVILEGE"


# --- router.py: the script handed to root ----------------------------------


def test_pf_rule_ends_with_a_real_newline_not_a_literal_backslash_n(tmp_path):
    router(tmp_path).start()
    rule = read(tmp_path, "pf_nat.conf")
    assert rule.endswith("\n")
    assert "\\n" not in rule
    assert rule.startswith("nat on en0 from en1:network to any -> (en0)")


def test_start_script_stops_at_the_first_failure_and_uses_the_anchor(tmp_path):
    router(tmp_path).start()
    script = read(tmp_path, "router.sh")
    assert script.startswith("#!/bin/sh\nset -e\n")
    assert f"pfctl -a {PF_ANCHOR} -f " in script
    assert "-F all -d" not in script
    assert "pfctl -f " not in script


def test_stop_script_flushes_only_the_anchor_and_never_disables_pf(tmp_path):
    router(tmp_path).stop()
    script = read(tmp_path, "router.sh")
    assert f"pfctl -a {PF_ANCHOR} -F all" in script
    assert "-d" not in script.split("pfctl")[1].splitlines()[0]
    assert "pfctl -F all" not in script


def test_script_paths_point_into_the_private_directory_not_tmp(tmp_path):
    router(tmp_path).start()
    script = read(tmp_path, "router.sh")
    assert os.path.join(tmp_path, "pf_nat.conf") in script
    assert os.path.join(tmp_path, "bootpd.plist") in script
    assert "/tmp/" not in script


def test_osascript_runs_the_script_from_the_private_directory(tmp_path):
    run_fn = Recorder()
    router(tmp_path, run_fn).start()
    (call,) = run_fn.osascript_calls()
    assert os.path.join(tmp_path, "router.sh") in call[2]
    assert "/tmp/router.sh" not in call[2]


def test_private_files_are_not_world_readable(tmp_path):
    router(tmp_path).start()
    for name in ("router.sh", "pf_nat.conf", "bootpd.plist"):
        assert os.stat(os.path.join(tmp_path, name)).st_mode & 0o077 == 0


def test_a_planted_symlink_is_refused_and_the_target_untouched(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    os.symlink(victim, tmp_path / "router.sh")
    run_fn = Recorder()
    assert router(tmp_path, run_fn).start() == "failed: OSError"
    assert victim.read_text() == "keep me"
    assert run_fn.osascript_calls() == []


# --- router.py: bootpd.plist -------------------------------------------------


def test_bootpd_plist_uses_dhcp_router_and_the_real_subnet(tmp_path):
    router(
        tmp_path,
        lan_ip="10.1.2.1",
        lan_netmask="255.255.0.0",
        dhcp_start="10.1.5.10",
        dhcp_end="10.1.5.20",
    ).start()
    with open(os.path.join(tmp_path, "bootpd.plist"), "rb") as f:
        data = plistlib.load(f)
    (subnet,) = data["Subnets"]
    assert subnet["dhcp_router"] == "10.1.2.1"
    assert "routers" not in subnet
    assert subnet["net_address"] == "10.1.0.0"
    assert subnet["net_mask"] == "255.255.0.0"
    assert subnet["net_range"] == ["10.1.5.10", "10.1.5.20"]
    assert data["dhcp_enabled"] == ["en1"]


def test_clients_are_pointed_at_the_lan_ip_for_dns(tmp_path):
    router(tmp_path).start()
    with open(os.path.join(tmp_path, "bootpd.plist"), "rb") as f:
        data = plistlib.load(f)
    assert data["Subnets"][0]["dhcp_domain_name_server"] == ["192.168.10.1"]


# --- router.py: validation before anything reaches root ---------------------


def test_shell_metacharacters_in_lan_ip_run_nothing(tmp_path):
    run_fn = Recorder()
    status = router(tmp_path, run_fn, lan_ip="1.2.3.4; touch /tmp/x").start()
    assert status == "failed: invalid lan_ip"
    assert run_fn.calls == []
    assert not os.path.exists(tmp_path / "router.sh")


def test_interface_names_are_validated(tmp_path):
    run_fn = Recorder()
    assert router(tmp_path, run_fn, wan_if="en0 $(id)").start() == "failed: invalid wan_if"
    assert router(tmp_path, run_fn, lan_if="").start() == "failed: invalid lan_if"
    assert router(tmp_path, run_fn, lan_if="Ethernet").start() == "failed: invalid lan_if"
    assert run_fn.calls == []


def test_netmask_and_dhcp_range_are_validated(tmp_path):
    run_fn = Recorder()
    assert (
        router(tmp_path, run_fn, lan_netmask="255.255.255.x").start()
        == "failed: invalid lan_netmask"
    )
    assert (
        router(tmp_path, run_fn, dhcp_start="192.168.11.100").start()
        == "failed: invalid dhcp_start"
    )
    assert router(tmp_path, run_fn, dhcp_end="nope").start() == "failed: invalid dhcp_end"
    assert run_fn.calls == []


def test_start_refuses_while_the_dnsmasq_stack_owns_port_67(tmp_path):
    run_fn = Recorder(dnsmasq_running=True)
    assert router(tmp_path, run_fn).start() == "failed: dnsmasq stack active"
    assert run_fn.osascript_calls() == []


def test_from_config_maps_the_config_keys(tmp_path):
    config = {
        "wan_interface": "en3",
        "lan_interface": "en0",
        "lan_ip": "192.168.10.1",
        "lan_netmask": "255.255.255.0",
        "dhcp_start": "192.168.10.100",
        "dhcp_end": "192.168.10.200",
        "router_enabled": False,
    }
    r = Router.from_config(config, run_fn=Recorder(), tmp_dir=str(tmp_path))
    assert (r.wan_if, r.lan_if) == ("en3", "en0")


# --- router_window.py --------------------------------------------------------


class Field:
    def __init__(self, value):
        self._value = value

    def stringValue(self):  # noqa: N802 - mirrors the AppKit selector
        return self._value


class Popup:
    def __init__(self, title):
        self._title = title

    def titleOfSelectedItem(self):  # noqa: N802 - mirrors the AppKit selector
        return self._title


class App:
    def __init__(self):
        self.router = None


def immediately(fn):
    fn()


def config(**overrides):
    base = {
        "wan_interface": "en0",
        "lan_interface": "en1",
        "lan_ip": "192.168.10.1",
        "lan_netmask": "255.255.255.0",
        "dhcp_start": "192.168.10.100",
        "dhcp_end": "192.168.10.200",
        "router_enabled": False,
        "sensitive_strings": ["corp-secret-host"],
        "unrelated": "kept",
    }
    return {**base, **overrides}


def controller(tmp_path, **kwargs):
    kwargs.setdefault("on_main", immediately)
    kwargs.setdefault("spawn", immediately)
    kwargs.setdefault("run_fn", lambda argv: (0, "ok"))
    kwargs.setdefault("config_path", str(tmp_path / "config.yaml"))
    kwargs.setdefault("config", config())
    kwargs.setdefault("app", App())
    ctrl = RouterWindowController(**kwargs)
    ctrl.wan_popup = Popup("Wi-Fi (en0)")
    ctrl.lan_popup = Popup("Ethernet (en1)")
    ctrl.lan_ip = Field("192.168.10.1")
    ctrl.lan_nm = Field("255.255.255.0")
    ctrl.dhcp_s = Field("192.168.10.100")
    ctrl.dhcp_e = Field("192.168.10.200")
    ctrl.ping_target = Field("8.8.8.8")
    return ctrl


def test_ping_output_reaches_the_log_through_the_main_thread_hop(tmp_path, capsys):
    ctrl = controller(tmp_path, run_fn=lambda argv: (0, "4 packets transmitted, 4 received"))
    ctrl.on_ping()
    assert "4 received" in capsys.readouterr().out


def test_ping_failure_is_reported_not_swallowed(tmp_path, capsys):
    controller(tmp_path, run_fn=lambda argv: (2, "Request timeout")).on_ping()
    out = capsys.readouterr().out
    assert "Ping failed (exit 2)" in out
    assert "Request timeout" in out


def test_ai_check_redacts_and_uses_the_escalator_model_and_timeout(tmp_path):
    seen = {}

    class Messages:
        def create(self, **kwargs):
            seen.update(kwargs)

            class R:
                content = [type("B", (), {"text": "looks fine"})()]

            return R()

    class Client:
        messages = Messages()

    ctrl = controller(
        tmp_path,
        run_fn=lambda argv: (0, "default 10.0.0.1 corp-secret-host en0"),
        client_factory=Client,
    )
    ctrl.on_ai_check()
    prompt = seen["messages"][0]["content"]
    assert "corp-secret-host" not in prompt
    assert "[REDACTED]" in prompt
    assert seen["model"] == DEFAULT_MODEL
    assert seen["timeout"] == DEFAULT_TIMEOUT_SECONDS


def test_ai_check_failure_logs_the_class_name_not_the_message(tmp_path, capsys):
    def boom():
        raise RuntimeError("sk-ant-secret in url")

    controller(tmp_path, client_factory=boom).on_ai_check()
    out = capsys.readouterr().out
    assert "AI Check Failed: RuntimeError" in out
    assert "sk-ant-secret" not in out


def test_save_writes_only_the_router_keys_and_backs_up_the_old_file(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("check_interval: 5\n")
    ctrl = controller(tmp_path, config_path=str(path))
    ctrl.on_save_config()
    on_disk = yaml.safe_load(path.read_text())
    assert set(ROUTER_KEYS) <= set(on_disk)
    assert on_disk["check_interval"] == 5
    assert "unrelated" not in on_disk
    assert "sensitive_strings" not in on_disk
    assert any(p.name.startswith("config.yaml.bak-") for p in tmp_path.iterdir())


def test_start_builds_the_router_lazily_and_reports_its_status(tmp_path, capsys):
    cancelled = Recorder(osascript=Proc(1, b"User canceled."))
    ctrl = controller(
        tmp_path,
        router_factory=lambda cfg: Router.from_config(cfg, run_fn=cancelled, tmp_dir=str(tmp_path)),
    )
    ctrl.on_start()
    out = capsys.readouterr().out
    assert ctrl.app.router is not None
    assert "Router start: NEEDS_PRIVILEGE" in out
    assert "started" not in out


def test_get_interfaces_is_empty_when_networksetup_cannot_run():
    def missing(argv):
        raise OSError("no networksetup")

    assert get_interfaces(missing) == []


def test_get_interfaces_pairs_port_names_with_devices():
    listing = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa\n\nHardware Port: USB LAN\nDevice: en5\n"
    assert get_interfaces(lambda argv: (0, listing)) == ["Wi-Fi (en0)", "USB LAN (en5)"]
    assert get_interfaces(lambda argv: (1, listing)) == []


def test_diagnostics_use_absolute_netstat_and_report_a_nonzero_exit_as_data(tmp_path, capsys):
    seen = []

    def run(argv):
        seen.append(argv)
        return (1, "netstat: sysctl: Cannot allocate memory") if "netstat" in argv[0] else (0, "ok")

    controller(tmp_path, run_fn=run).on_refresh()
    assert seen[0][0] == NETSTAT
    out = capsys.readouterr().out
    assert "netstat exited 1" in out
    assert "Cannot allocate memory" in out
