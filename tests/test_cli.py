"""Offline tests for the `netdns` subcommands: argument parsing, exit codes, and
the wiring each subcommand shares with the menu bar app.

Every side effect enters through a parameter -- `run_fn`, `context`,
`probe_fn`, `executor_factory`, `load_config_fn` -- so nothing here opens a
socket or spawns a process. Renderer and catalogue tests live in
test_cli_console.py next to the REPL that shares them.
"""

import json
from types import SimpleNamespace

import pytest
import yaml

from netdnsmonitor import cli, privileges
from netdnsmonitor.cli import (
    build_parser,
    cmd_failover,
    cmd_ladder,
    cmd_run,
    cmd_status,
    interface_probe_settings,
    main,
    render_failover_status,
    render_interfaces,
    run_catalog_command,
)
from netdnsmonitor.config import DEFAULT_CONFIG, ConfigError
from netdnsmonitor.failover import _BUSY, _neither_side
from netdnsmonitor.repair_executor import make_repair_executor


def collect():
    lines = []
    return lines, lines.append


def fake_run(returncode=0, stdout="", stderr=""):
    calls = []

    def run(argv, **kwargs):
        calls.append({"argv": argv, **kwargs})
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    run.calls = calls
    return run


# --- interface prober settings ---------------------------------------------


def test_interface_probe_uses_the_failover_targets_not_the_internet_ones():
    """On a machine routing through a VPN, IP_BOUND_IF bypasses the tunnel, so
    an internet target reads every physical link unreachable. The app aims this
    prober at `failover_probe_targets`; the CLI has to agree with it, or
    `netdns interfaces` calls a working link dead.
    """
    config = dict(DEFAULT_CONFIG)
    config["external_targets"] = [["1.1.1.1", 443]]
    config["failover_probe_targets"] = [["192.168.1.1", 80], ["10.0.0.1", 80]]
    config["failover_probe_timeout_seconds"] = 6
    config["probe_timeout_seconds"] = 2.0

    targets, timeout = interface_probe_settings(config)

    assert targets == [("192.168.1.1", 80), ("10.0.0.1", 80)]
    assert timeout == 6.0


def test_interface_probe_falls_back_to_external_targets_when_unset():
    config = dict(DEFAULT_CONFIG)
    config["external_targets"] = [["1.1.1.1", 443]]
    config["failover_probe_targets"] = []
    config["failover_probe_timeout_seconds"] = 0
    config["probe_timeout_seconds"] = 3.0

    assert interface_probe_settings(config) == ([("1.1.1.1", 443)], 3.0)


def test_build_context_hands_the_failover_settings_to_the_prober(monkeypatch):
    """No seam for the prober factory, so it is replaced on the module."""
    seen = {}

    def factory(**kwargs):
        seen.update(kwargs)
        return lambda device: None

    monkeypatch.setattr(cli, "make_interface_prober", factory)
    config = dict(DEFAULT_CONFIG)
    config["failover_probe_targets"] = [["192.168.1.1", 80]]
    config["failover_probe_timeout_seconds"] = 6

    cli.build_context(config)

    assert seen == {"targets": [("192.168.1.1", 80)], "timeout": 6.0}


# --- parser -----------------------------------------------------------------


def test_options_before_the_subcommand_are_not_overwritten_by_it():
    """argparse copies every attribute a subparser sets onto the shared
    namespace, so a subparser default used to replace the value typed before
    the subcommand: `--config X status` loaded the default config.
    """
    args = build_parser().parse_args(["--config", "/tmp/x.yaml", "--json", "status"])
    assert args.config == "/tmp/x.yaml"
    assert args.json is True


def test_options_after_the_subcommand_still_work():
    args = build_parser().parse_args(["status", "--json", "--config", "/tmp/y.yaml"])
    assert args.config == "/tmp/y.yaml"
    assert args.json is True


def test_options_default_when_given_nowhere():
    args = build_parser().parse_args(["status"])
    assert args.config == cli.DEFAULT_CONFIG_PATH
    assert args.json is False


# --- main -------------------------------------------------------------------


@pytest.mark.parametrize("argv_order", ["before", "after"])
def test_main_loads_the_config_that_was_named(tmp_path, argv_order):
    path = tmp_path / "config.yaml"
    loaded = []

    def load(p):
        loaded.append(p)
        return dict(DEFAULT_CONFIG)

    argv = (
        ["--config", str(path), "guide"]
        if argv_order == "before"
        else ["guide", "--config", str(path)]
    )
    lines, out = collect()
    assert main(argv, out=out, load_config_fn=load) == 0
    assert loaded == [str(path)]
    assert "what to do when the network breaks" in lines[0]


def _refuse_config(path):
    raise ConfigError("poll_interval_seconds", "must be a positive number")


def _unparseable_config(path):
    return yaml.safe_load("a: [b")


def _unreadable_config(path):
    raise PermissionError(13, "Permission denied", path)


@pytest.mark.parametrize("load", [_refuse_config, _unparseable_config, _unreadable_config])
def test_a_bad_config_exits_2_with_a_message_instead_of_a_traceback(load, capsys):
    lines, out = collect()
    assert main(["status"], out=out, load_config_fn=load) == 2
    assert lines == []
    assert capsys.readouterr().err.startswith("config error: ")


# --- run --------------------------------------------------------------------


def run_args(*argv):
    return build_parser().parse_args(["run", *argv])


def test_a_mutating_command_without_yes_is_refused_and_never_runs():
    run = fake_run()
    lines, out = collect()
    code = cmd_run(run_args("enable", "--value", "service=Wi-Fi"), {}, out, run_fn=run)
    assert code == 2
    assert run.calls == []
    assert "--yes" in lines[0]


def test_a_nonzero_exit_with_output_is_a_failure():
    """Output is not success. `run enable --value service=Typo --yes` printed
    networksetup's error and exited 0, which reads as a change that happened.
    """
    run = fake_run(returncode=4, stderr="** Error: The parameters were not valid.")
    lines, out = collect()
    code = cmd_run(run_args("enable", "--value", "service=Typo", "--yes"), {}, out, run_fn=run)
    assert code == 1
    assert "The parameters were not valid" in lines[0]
    assert lines[0].splitlines()[-1] == "failed: exit 4"


def test_a_zero_exit_is_success():
    lines, out = collect()
    assert cmd_run(run_args("nwi"), {}, out, run_fn=fake_run(stdout="Network information")) == 0
    assert "failed" not in lines[0]


def test_each_command_runs_with_its_own_timeout_and_a_tolerant_decode():
    run = fake_run(stdout="1 1.1.1.1")
    run_catalog_command("traceroute", {}, run_fn=run)
    assert run.calls[0]["timeout"] == 45.0
    assert run.calls[0]["errors"] == "replace"


def test_a_decode_error_is_reported_as_text_not_a_traceback():
    """A Latin-1 SSID in `wdutil info` output raised UnicodeDecodeError, a
    ValueError, which the old except clause did not catch.
    """

    def undecodable(argv, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid continuation byte")

    text = run_catalog_command("wifi", {}, run_fn=undecodable)
    assert text.startswith("$ wdutil info")
    assert "failed: UnicodeDecodeError" in text


def test_a_timeout_is_a_failure():
    import subprocess

    def slow(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    lines, out = collect()
    assert cmd_run(run_args("ping"), {}, out, run_fn=slow) == 1
    assert "timed out after 15s" in lines[0]


def test_the_command_caveat_is_shown_with_the_result():
    """`flush-dns` exits 0 having done half a flush. Without the note, the
    success reads as the whole repair.
    """
    lines, out = collect()
    code = cmd_run(run_args("flush-dns", "--yes"), {}, out, run_fn=fake_run())
    assert code == 0
    assert any("half a flush" in line for line in lines)


# --- rendering --------------------------------------------------------------


def test_an_unknown_enabled_state_is_not_rendered_as_off():
    """`enabled` is None for a service missing from the order. OFF names a
    different fault -- a disabled service -- and sends someone to enable it.
    """
    text = render_interfaces(
        [
            {
                "name": "Ethernet",
                "device": None,
                "enabled": None,
                "reachable": None,
                "throughput_mbps": None,
            }
        ]
    )
    assert "OFF" not in text
    assert "?" in text


def failover_snapshot(**overrides):
    snap = {
        "error": None,
        "active_side": "preferred",
        "active_service": "AX88179B",
        "auto_enabled": True,
        "last_event": None,
        "preferred": {
            "name": "AX88179B",
            "device": "en6",
            "found": True,
            "enabled": True,
            "reachable": True,
            "throughput_mbps": None,
        },
        "backups": [
            {
                "name": "Wi-Fi",
                "device": "en0",
                "found": True,
                "enabled": True,
                "reachable": True,
                "throughput_mbps": None,
            }
        ],
    }
    snap.update(overrides)
    return snap


def test_a_service_missing_from_the_order_says_not_found():
    snap = failover_snapshot(
        preferred={
            "name": "Ethernet",
            "device": None,
            "found": False,
            "enabled": None,
            "reachable": None,
            "throughput_mbps": None,
        }
    )
    text = render_failover_status(snap)
    assert "NOT FOUND" in text
    assert "OFF" not in text


def test_a_third_service_at_the_head_is_not_called_the_preferred_link():
    """`active_side` reports "preferred" for anything that is not a configured
    backup. Saying "on the preferred link" about a Thunderbolt Bridge tells the
    reader a switch-back already happened.
    """
    text = render_failover_status(failover_snapshot(active_service="Thunderbolt Bridge"))
    assert "on the preferred link" not in text
    assert "on neither the preferred link nor a backup" in text


def test_the_preferred_and_backup_sides_are_still_named():
    assert "on the preferred link" in render_failover_status(failover_snapshot())
    on_backup = failover_snapshot(active_side="backup", active_service="Wi-Fi")
    assert "on the backup" in render_failover_status(on_backup)


# --- status -----------------------------------------------------------------


NO_FAILOVER = (None, None, None, None)


@pytest.mark.parametrize("as_json", [True, False])
def test_status_exits_nonzero_during_an_incident_in_both_output_modes(as_json):
    """A script checking `$?` on `status --json` got 0 through an outage."""
    argv = ["status", "--json"] if as_json else ["status"]
    lines, out = collect()
    code = cmd_status(
        build_parser().parse_args(argv),
        {},
        out,
        context=NO_FAILOVER,
        probe_fn=lambda: {"external_reachable": False, "dns_ok": False},
    )
    assert code == 1
    if as_json:
        assert json.loads(lines[0])["classification"] == "network"


def test_status_exits_zero_when_healthy_in_json_mode():
    lines, out = collect()
    code = cmd_status(
        build_parser().parse_args(["status", "--json"]),
        {},
        out,
        context=NO_FAILOVER,
        probe_fn=lambda: {"external_reachable": True, "dns_ok": True},
    )
    assert code == 0
    assert json.loads(lines[0])["failover"] is None


# --- failover ---------------------------------------------------------------


def failover_context(outcome):
    failover = SimpleNamespace(switch_now=lambda target, service=None: outcome)
    return (None, None, failover, None)


@pytest.mark.parametrize(
    "outcome, expected",
    [
        ("ok: service order now starts with 'AX88179B'", 0),
        ("no switch: already on the preferred network", 0),
        ("no switch: already on the backup network", 0),
        ("no switch: already on 'iPhone USB'", 0),
        ("failed: could not read the current network service order", 1),
        ("NEEDS_PRIVILEGE: reordering network services was refused", 1),
        # The real texts, so a rewording cannot quietly turn these into successes.
        (_neither_side("Thunderbolt Bridge"), 1),
        (_BUSY, 1),
    ],
)
def test_failover_exit_code_follows_the_outcome(outcome, expected):
    """Already being where you asked to be is not an error. A refusal worded as
    "no switch:" is: the machine is not where it was asked to be, so
    `netdns failover preferred && ...` must not carry on as if it were.
    """
    lines, out = collect()
    args = build_parser().parse_args(["failover", "preferred"])
    assert cmd_failover(args, {}, out, context=failover_context(outcome)) == expected
    assert lines == [outcome]


# --- ladder -----------------------------------------------------------------


def recording_factory(run_fn, granted=True, primary="en0"):
    """Records what cmd_ladder wires in, then builds a real executor with fake
    privilege probes so no subprocess or DNS query runs.
    """
    seen = {}

    def factory(**kwargs):
        seen.update(kwargs)
        return make_repair_executor(
            run_fn=run_fn,
            query_fn=lambda domain: True,
            resolver_dir_exists_fn=lambda path: False,
            is_granted_fn=lambda: granted,
            primary_interface_fn=lambda: primary,
            failover_fn=kwargs.get("failover_fn"),
        )

    factory.seen = seen
    return factory


def test_the_ladder_is_wired_to_the_real_privilege_probes():
    """Without them the executor describes an ungranted machine, so a user who
    had installed the grant was told it "has not been granted".
    """
    factory = recording_factory(fake_run(stdout="ok"))
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network", "--repair"])
    cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False)
    assert factory.seen["is_granted_fn"] is privileges.is_granted
    assert factory.seen["primary_interface_fn"] is privileges.primary_interface
    assert not any("has not been granted" in line for line in lines)


def test_the_ladder_does_not_switch_networks_even_when_failover_is_configured():
    factory = recording_factory(fake_run(stdout="ok"))
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network", "--repair"])
    cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=True)
    switch = next(line for line in lines if line.startswith("switch_to_backup_network:"))
    assert "skipped:" in switch
    assert "netdns failover backup" in switch


def test_the_ladder_reports_failover_as_unconfigured_when_it_is():
    factory = recording_factory(fake_run(stdout="ok"))
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network", "--repair"])
    cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False)
    assert factory.seen["failover_fn"] is None
    assert any("not configured" in line for line in lines)


def test_a_failing_repair_step_makes_the_ladder_exit_nonzero():
    factory = recording_factory(fake_run(returncode=1, stderr="ipconfig: denied"))
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network", "--repair"])
    code = cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False)
    assert code == 1
    assert any(line.startswith("renew_dhcp_lease: failed:") for line in lines)


def test_an_ungranted_repair_makes_the_ladder_exit_nonzero():
    factory = recording_factory(fake_run(stdout="ok"), granted=False)
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network", "--repair"])
    assert cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False) == 1


def test_a_partial_flush_makes_the_ladder_exit_nonzero():
    def run(argv, **kwargs):
        # dscacheutil succeeds; the HUP and the elevated retry both fail.
        code = 0 if argv[0] == "dscacheutil" else 1
        return SimpleNamespace(returncode=code, stdout="", stderr="not permitted")

    factory = recording_factory(run)
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "dns", "--repair"])
    assert cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False) == 1
    assert any(line.startswith("flush_dns_cache: partial") for line in lines)


def test_checks_alone_that_succeed_exit_zero():
    factory = recording_factory(fake_run(stdout="ok"))
    lines, out = collect()
    args = build_parser().parse_args(["ladder", "network"])
    assert cmd_ladder(args, {}, out, executor_factory=factory, failover_configured=False) == 0
    assert any("SKIPPED" in line for line in lines)
