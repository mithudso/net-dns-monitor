"""Offline tests for the CLI renderers, the command catalogue, and the console
loop. `handle` is a pure function of (line, state) so the REPL is testable
without a terminal.
"""

import os
from types import SimpleNamespace

from netdnsmonitor.cli import (
    build_parser,
    cmd_ladder,
    cmd_run,
    cmd_status,
    interface_rows,
    main,
    render_catalog,
    render_failover_status,
    render_interfaces,
    render_usage_guide,
)
from netdnsmonitor.cli_console import ConsoleState, handle
from netdnsmonitor.commands import BY_KEY, CATALOG, missing_placeholder, placeholders_in, resolve
from netdnsmonitor.config import DEFAULT_CONFIG
from netdnsmonitor.service_order import NetworkService

LISTING = """An asterisk (*) denotes that a network service is disabled.
(1) AX88179B
(Hardware Port: AX88179B, Device: en6)

(*) M3100
(Hardware Port: M3100, Device: en12)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
"""


def runner(argv, timeout=5):
    if argv[:2] == ["networksetup", "-listnetworkserviceorder"]:
        return SimpleNamespace(returncode=0, stdout=LISTING, stderr="")
    return SimpleNamespace(returncode=0, stdout=f"ran {' '.join(argv)}", stderr="")


def recording_runner():
    """Records each argv with the timeout it was given."""
    calls = []

    def run(argv, timeout=5):
        calls.append((argv, timeout))
        return SimpleNamespace(returncode=0, stdout="out", stderr="")

    run.calls = calls
    return run


SERVICES = [
    NetworkService("AX88179B", "en6", True),
    NetworkService("M3100", "en12", False),
    NetworkService("Wi-Fi", "en0", True),
]


# --- command catalogue ------------------------------------------------------


def test_every_catalogue_entry_has_a_unique_key():
    keys = [c.key for c in CATALOG]
    assert len(keys) == len(set(keys))


def test_state_changing_commands_are_marked():
    """A console that offers `disable` beside `scutil --nwi` with no
    distinction is a foot-gun.
    """
    for key in ("enable", "disable", "renew-dhcp", "flush-dns"):
        assert BY_KEY[key].mutates is True
    for key in ("nwi", "order", "routes", "dns"):
        assert BY_KEY[key].mutates is False


def test_resolve_fills_a_placeholder():
    assert resolve("iface", device="en0") == ["ifconfig", "en0"]


def test_resolve_refuses_to_run_with_an_unfilled_placeholder():
    """Better to return nothing than to shell out with a literal {device}."""
    assert resolve("iface") is None
    assert resolve("iface", device="") is None


def test_resolve_returns_none_for_an_unknown_key():
    assert resolve("no-such-command") is None


def test_missing_placeholder_names_what_is_needed():
    assert missing_placeholder("iface") == "device"
    assert missing_placeholder("iface", device="en0") is None
    assert missing_placeholder("nwi") is None


def test_catalogue_binaries_with_a_known_path_are_not_resolved_through_path():
    """The same rule the repair executor follows: a `scutil` found first on a
    user-writable PATH entry is not the system's `scutil`.
    """
    from netdnsmonitor.privileges import IPCONFIG
    from netdnsmonitor.repair_executor import DSCACHEUTIL, NETSTAT, SCUTIL

    assert BY_KEY["nwi"].argv[0] == SCUTIL
    assert BY_KEY["dns"].argv[0] == SCUTIL
    assert BY_KEY["routes"].argv[0] == NETSTAT
    assert BY_KEY["flush-dns"].argv[0] == DSCACHEUTIL
    assert BY_KEY["renew-dhcp"].argv[0] == IPCONFIG


def test_resolve_refuses_a_value_that_looks_like_a_flag():
    """`ifconfig -a` is not "show interface -a": the tool reads it as an option."""
    assert resolve("iface", device="-a") is None
    assert resolve("enable", service="--help") is None


def test_no_catalogue_command_has_more_than_one_placeholder():
    """The console's pending-value path fills exactly one placeholder before
    running; a second one would reach `resolve` unfilled.
    """
    assert all(len(placeholders_in(c.key)) <= 1 for c in CATALOG)


# --- renderers --------------------------------------------------------------


def test_interface_table_marks_disabled_services():
    rows = [
        {
            "name": "M3100",
            "device": "en12",
            "enabled": False,
            "reachable": False,
            "throughput_mbps": None,
        },
        {
            "name": "Wi-Fi",
            "device": "en0",
            "enabled": True,
            "reachable": True,
            "throughput_mbps": 3.8,
        },
    ]
    text = render_interfaces(rows)
    assert "OFF" in text and "M3100" in text
    assert "3.8" in text


def test_interface_table_shows_an_unknown_service_state_as_unknown():
    """`enabled` is None for a configured service missing from the order. That
    is "not found", not "disabled" -- printing OFF sends someone to enable a
    service that does not exist.
    """
    rows = [
        {
            "name": "Gone",
            "device": None,
            "enabled": None,
            "reachable": None,
            "throughput_mbps": None,
        }
    ]
    text = render_interfaces(rows)
    assert "OFF" not in text
    assert "?" in text


def test_interface_table_says_not_probed_rather_than_unreachable():
    rows = [
        {
            "name": "iPhone USB",
            "device": "en11",
            "enabled": True,
            "reachable": None,
            "throughput_mbps": None,
        }
    ]
    assert "not probed" in render_interfaces(rows)


def test_unmeasured_speed_shows_a_dash_not_a_zero():
    rows = [
        {
            "name": "Wi-Fi",
            "device": "en0",
            "enabled": True,
            "reachable": True,
            "throughput_mbps": None,
        }
    ]
    assert " -" in render_interfaces(rows)
    assert "0.0" not in render_interfaces(rows)


def test_empty_interface_list_says_so():
    assert "No network services" in render_interfaces([])


def test_catalog_render_flags_the_mutating_commands():
    text = render_catalog()
    assert "changes system state" in text
    assert "enable" in text and "nwi" in text


def test_catalog_render_shows_every_note_and_the_admin_marker():
    """`notes` and `needs_admin` used to be read nowhere, so flush-dns's
    "only half a flush" caveat never reached anyone.
    """
    text = render_catalog()
    for command in CATALOG:
        if command.notes:
            assert command.notes in text
    wifi_line = next(line for line in text.splitlines() if " wifi " in line)
    assert "(needs admin)" in wifi_line
    nwi_line = next(line for line in text.splitlines() if " nwi " in line)
    assert "(needs admin)" not in nwi_line


def test_guide_covers_both_fault_layers_and_the_disabled_trap():
    guide = render_usage_guide()
    assert "DNS faults" in guide and "Network-layer faults" in guide
    assert "DISABLED" in guide


def test_failover_status_when_unconfigured():
    assert "not configured" in render_failover_status(None)


def test_failover_status_reports_an_unreadable_order():
    assert "boom" in render_failover_status({"error": "boom"})


def test_failover_status_lists_preferred_and_every_backup():
    snapshot = {
        "error": None,
        "active_side": "backup",
        "active_service": "M3100",
        "auto_enabled": True,
        "last_event": "ok: switched",
        "preferred": {
            "name": "USB 2.5G",
            "device": "en9",
            "enabled": True,
            "reachable": False,
            "throughput_mbps": None,
        },
        "backups": [
            {
                "name": "M3100",
                "device": "en12",
                "enabled": True,
                "reachable": True,
                "throughput_mbps": 12.0,
            },
            {
                "name": "Wi-Fi",
                "device": "en0",
                "enabled": True,
                "reachable": True,
                "throughput_mbps": 3.8,
            },
        ],
    }
    text = render_failover_status(snapshot)
    assert "on the backup" in text
    assert "USB 2.5G" in text and "M3100" in text and "Wi-Fi" in text
    assert "ok: switched" in text


# --- interface rows ---------------------------------------------------------


def test_interface_rows_read_the_live_service_list():
    rows = interface_rows(runner, prober=lambda d: d == "en0")
    assert [r["name"] for r in rows] == ["AX88179B", "M3100", "Wi-Fi"]
    assert rows[1]["enabled"] is False
    assert rows[2]["reachable"] is True


def test_only_reachable_interfaces_are_benchmarked():
    measured = []
    rows = interface_rows(
        runner,
        prober=lambda d: d == "en0",
        meter=lambda d: measured.append(d) or 5.0,
        measure=True,
    )
    assert measured == ["en0"]
    assert rows[2]["throughput_mbps"] == 5.0
    assert rows[0]["throughput_mbps"] is None


def test_no_benchmark_unless_asked():
    rows = interface_rows(runner, prober=lambda d: True, meter=lambda d: 5.0)
    assert all(r["throughput_mbps"] is None for r in rows)


def test_interface_rows_reuse_a_given_service_list():
    """The console lists services once per refresh; the rows must not shell
    out to networksetup again behind that cache.
    """
    calls = []

    def counting(argv):
        calls.append(argv)
        return runner(argv)

    rows = interface_rows(counting, prober=lambda d: None, services=SERVICES)
    assert [r["name"] for r in rows] == ["AX88179B", "M3100", "Wi-Fi"]
    assert calls == []


# --- subcommand exit codes --------------------------------------------------


def collecting():
    lines = []

    def out(text):
        lines.append(text)

    out.lines = lines
    return out


def test_status_json_exits_nonzero_when_unhealthy():
    """`--json` is the scripted path; a 0 there on a dead network means every
    cron job built on it reports healthy.
    """
    out = collecting()
    failing = lambda: {"external_reachable": False, "dns_ok": False, "domain_results": {}}  # noqa: E731
    code = cmd_status(
        SimpleNamespace(json=True),
        dict(DEFAULT_CONFIG),
        out,
        prober_factory=lambda **kwargs: failing,
    )
    assert code == 1
    assert '"classification": "network"' in "\n".join(out.lines)


def test_run_exits_nonzero_when_the_command_fails():
    def failing_run(argv, **kwargs):
        return SimpleNamespace(
            returncode=1, stdout="", stderr="ifconfig: interface en99 does not exist"
        )

    out = collecting()
    args = SimpleNamespace(key="iface", value=[("device", "en99")], yes=False)
    code = cmd_run(args, dict(DEFAULT_CONFIG), out, run_fn=failing_run)
    text = "\n".join(out.lines)
    assert code == 1
    assert "failed:" in text
    assert "en99 does not exist" in text


def test_ladder_does_not_claim_failover_is_unconfigured():
    """A ladder run from the CLI never switches networks, so it must say that
    -- not "not configured" on a machine where failover is configured.
    """
    config = dict(
        DEFAULT_CONFIG,
        failover_enabled=True,
        failover_preferred_service="USB 2.5G",
        failover_backup_services=["Wi-Fi"],
    )
    seen = []

    def executor(step, classification):
        seen.append(step.name)
        return "ok: fake"

    out = collecting()
    code = cmd_ladder(SimpleNamespace(layer="network", repair=True), config, out, executor=executor)
    text = "\n".join(out.lines)
    assert code == 0
    assert "not configured" not in text
    assert "switch_to_backup_network: SKIPPED" in text
    assert "switch_to_backup_network" not in seen


def test_main_reports_a_bad_config_without_a_traceback(tmp_path, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("- this\n- is a list\n", encoding="utf-8")
    out = collecting()
    code = main(["commands", "--config", str(bad)], out=out)
    assert code == 2
    assert capsys.readouterr().err.startswith("config error: ")


def test_a_global_flag_before_the_subcommand_is_honoured(tmp_path, capsys):
    """`--config x.yaml commands` and `commands --config x.yaml` must load the
    same file; a subparser default that overwrites the first form silently
    runs against the wrong config.
    """
    bad = tmp_path / "config.yaml"
    bad.write_text("- this\n- is a list\n", encoding="utf-8")
    out = collecting()
    code = main(["--config", str(bad), "commands"], out=out)
    assert code == 2
    assert str(bad) in capsys.readouterr().err


def test_console_reports_a_nonzero_exit_with_output_as_failed():
    """`networksetup` refusing a change prints its reason and exits 1; output
    alone renders as success.
    """

    def refusing(argv, **kwargs):
        return SimpleNamespace(returncode=1, stdout="** Error: could not set", stderr="")

    text, _ = handle("nwi", ConsoleState(), SERVICES, refusing)
    assert "could not set" in text
    assert "failed: exited 1" in text


# --- console loop -----------------------------------------------------------


def test_quit_sets_the_quit_flag():
    text, state = handle("q", ConsoleState(), SERVICES, runner)
    assert state.quit is True


def test_help_returns_the_guide():
    text, _ = handle("?", ConsoleState(), SERVICES, runner)
    assert "what to do when the network breaks" in text


def test_a_read_only_command_runs_immediately():
    text, state = handle("nwi", ConsoleState(), SERVICES, runner)
    assert "$ /usr/sbin/scutil --nwi" in text
    assert state.pending_key is None


def test_a_command_can_be_picked_by_number():
    text, _ = handle("1", ConsoleState(), SERVICES, runner)
    assert "/usr/sbin/scutil --nwi" in text


def test_an_out_of_range_number_is_rejected():
    text, _ = handle("999", ConsoleState(), SERVICES, runner)
    assert "unknown" in text


def test_a_superscript_digit_is_rejected_not_a_crash():
    """`'²'.isdigit()` is True and `int('²')` raises -- out of the REPL loop."""
    text, _ = handle("²", ConsoleState(), SERVICES, runner)
    assert "unknown" in text


def test_a_flag_shaped_value_is_refused_before_confirmation():
    _, state = handle("enable", ConsoleState(), SERVICES, runner)
    text, state = handle("--help", state, SERVICES, runner)
    assert text.startswith("failed:")
    assert state.pending_key is None


def test_an_unknown_token_is_rejected_not_executed():
    text, _ = handle("rm -rf /", ConsoleState(), SERVICES, runner)
    assert "unknown" in text
    assert "$" not in text


def test_a_mutating_command_asks_before_running():
    """Picking a number from a list must not silently disable a service. The
    prompt shows the exact argv on purpose -- what must not happen is the
    runner being called.
    """
    called = []

    def recording(argv, timeout=5):
        called.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    text, state = handle("flush-dns", ConsoleState(), SERVICES, recording)
    assert "CHANGES SYSTEM STATE" in text
    assert "/usr/bin/dscacheutil -flushcache" in text, "the user must see what they are approving"
    assert state.pending_confirm is True
    assert called == [], "nothing may run before confirmation"


def test_confirming_a_mutating_command_runs_it():
    _, state = handle("flush-dns", ConsoleState(), SERVICES, runner)
    text, state = handle("yes", state, SERVICES, runner)
    assert "$ /usr/bin/dscacheutil -flushcache" in text
    assert state.pending_key is None


def test_declining_a_mutating_command_cancels_it():
    _, state = handle("flush-dns", ConsoleState(), SERVICES, runner)
    text, state = handle("no", state, SERVICES, runner)
    assert text == "cancelled."
    assert state.pending_key is None


def test_a_placeholder_command_asks_for_the_value_with_a_hint():
    text, state = handle("iface", ConsoleState(), SERVICES, runner)
    assert "needs a device" in text
    assert "en6" in text  # hint drawn from the live service list
    assert state.pending_needs == "device"


def test_supplying_the_placeholder_runs_the_command():
    _, state = handle("iface", ConsoleState(), SERVICES, runner)
    text, state = handle("en0", state, SERVICES, runner)
    assert "$ ifconfig en0" in text
    assert state.pending_key is None


def test_a_blank_answer_cancels_a_pending_command():
    _, state = handle("iface", ConsoleState(), SERVICES, runner)
    text, state = handle("", state, SERVICES, runner)
    assert text == "cancelled."
    assert state.pending_key is None


def test_a_mutating_command_with_a_placeholder_asks_for_both():
    """The value first, then the confirmation -- and it must not run in between."""
    text, state = handle("enable", ConsoleState(), SERVICES, runner)
    assert "needs a service" in text
    text, state = handle("M3100", state, SERVICES, runner)
    assert "CHANGES SYSTEM STATE" in text
    assert "M3100" in text
    assert state.pending_confirm is True
    text, state = handle("yes", state, SERVICES, runner)
    assert "$ networksetup -setnetworkserviceenabled M3100 on" in text


def test_each_command_runs_with_its_own_timeout():
    """At the runner's fixed 5s, `traceroute` (45s budget) and `ping-gw` (15s)
    printed a timeout where their output belonged.
    """
    run = recording_runner()
    handle("traceroute", ConsoleState(), SERVICES, run)
    assert run.calls[-1] == (["traceroute", "-w", "1", "-m", "12", "1.1.1.1"], 45.0)

    _, state = handle("ping-gw", ConsoleState(), SERVICES, run)
    handle("192.168.1.1", state, SERVICES, run)
    assert run.calls[-1] == (["ping", "-c", "3", "192.168.1.1"], 15.0)


def test_a_confirmed_command_keeps_its_own_timeout_through_every_step():
    run = recording_runner()
    _, state = handle("renew-dhcp", ConsoleState(), SERVICES, run)
    _, state = handle("en0", state, SERVICES, run)
    assert run.calls == [], "nothing may run before confirmation"
    handle("yes", state, SERVICES, run)
    # The catalogue may spell the binary as an absolute path.
    assert [([os.path.basename(argv[0]), *argv[1:]], timeout) for argv, timeout in run.calls] == [
        (["ipconfig", "set", "en0", "DHCP"], 20.0)
    ]


def test_a_raising_runner_is_reported_rather_than_ending_the_repl():
    """An undecodable byte of output raises UnicodeDecodeError, a ValueError."""

    def undecodable(argv, timeout=5):
        raise UnicodeDecodeError("utf-8", b"\xe9", 0, 1, "invalid continuation byte")

    text, state = handle("wifi", ConsoleState(), SERVICES, undecodable)
    assert text.startswith("$ wdutil info")
    assert "failed: UnicodeDecodeError" in text
    assert state.quit is False


def test_the_confirmation_shows_the_caveat_and_the_admin_marker():
    text, _ = handle("flush-dns", ConsoleState(), SERVICES, runner)
    assert "half a flush" in text
    text, state = handle("enable", ConsoleState(), SERVICES, runner)
    text, _ = handle("M3100", state, SERVICES, runner)
    assert "CHANGES SYSTEM STATE (needs admin)" in text


def test_a_command_with_a_caveat_prints_it_with_the_result():
    _, state = handle("flush-dns", ConsoleState(), SERVICES, runner)
    text, _ = handle("yes", state, SERVICES, runner)
    assert text.startswith("$ ") and "dscacheutil -flushcache" in text.splitlines()[0]
    assert text.endswith("note: " + BY_KEY["flush-dns"].notes)


def test_read_only_shortcuts_are_named_actions_not_executed_inline():
    """`handle` stays pure; the loop performs the live ones."""
    for key, token in [
        ("__INTERFACES__", "i"),
        ("__BENCH__", "b"),
        ("__STATUS__", "s"),
        ("__PRIORITY__", "priority"),
    ]:
        text, _ = handle(token, ConsoleState(), SERVICES, runner)
        assert text == key


def test_switching_networks_asks_before_acting():
    """Rewriting the service order is a bigger change than anything in the
    catalogue, and `p` sits next to `?` on a keyboard.
    """
    for token, action in [("f", "__SWITCH_BACKUP__"), ("p", "__SWITCH_PREFERRED__")]:
        text, state = handle(token, ConsoleState(), SERVICES, runner)
        assert "Type 'yes' to confirm" in text
        assert state.pending_action == action
        confirmed, _ = handle("yes", state, SERVICES, runner)
        assert confirmed == action


def test_declining_a_switch_cancels_it():
    _, state = handle("f", ConsoleState(), SERVICES, runner)
    text, state = handle("n", state, SERVICES, runner)
    assert text == "cancelled."
    assert state.pending_action is None


def test_promote_names_the_target_and_asks():
    text, state = handle("promote Wi-Fi", ConsoleState(), SERVICES, runner)
    assert "Wi-Fi" in text and "Type 'yes' to confirm" in text
    assert state.pending_action == "__PROMOTE__"
    assert state.values["service"] == "Wi-Fi"
    confirmed, state = handle("yes", state, SERVICES, runner)
    assert confirmed == "__PROMOTE__"
    assert state.values["service"] == "Wi-Fi", "the target must survive confirmation"


def test_promote_rejects_a_service_that_does_not_exist():
    text, state = handle("promote Nope", ConsoleState(), SERVICES, runner)
    assert "no service named" in text
    assert state.pending_action is None


def test_promote_refuses_a_disabled_service_rather_than_claiming_success():
    """Promoting a disabled service changes the stored order and routes
    nothing; reporting ok: for that is a repair that did not happen.
    """
    from netdnsmonitor.cli import promote_service

    outcome = promote_service(runner, SERVICES, "M3100")  # M3100 is disabled
    assert outcome.startswith("failed:")
    assert "DISABLED" in outcome
    assert "python3 -m netdnsmonitor.cli run enable" in outcome


def test_promote_of_an_enabled_service_goes_through():
    """A stateful fake: the reorder rewrites the listing, so the read-back sees
    the new order and the `ok:` path is the one exercised.
    """
    from netdnsmonitor.cli import promote_service

    listing = {"text": LISTING}
    reorders = []

    def stateful(argv, timeout=5):
        if argv[:2] == ["networksetup", "-ordernetworkservices"]:
            reorders.append(argv)
            names = argv[2:]
            devices = {s.name: s for s in SERVICES}
            lines = ["An asterisk (*) denotes that a network service is disabled."]
            position = 0
            for name in names:
                service = devices[name]
                if service.enabled:
                    position += 1
                    lines.append(f"({position}) {name}")
                else:
                    lines.append(f"(*) {name}")
                lines.append(f"(Hardware Port: {name}, Device: {service.device})")
                lines.append("")
            listing["text"] = "\n".join(lines)
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if argv[:2] == ["networksetup", "-listnetworkserviceorder"]:
            return SimpleNamespace(returncode=0, stdout=listing["text"], stderr="")
        return SimpleNamespace(returncode=1, stdout="", stderr="unexpected")

    outcome = promote_service(stateful, SERVICES, "Wi-Fi")
    assert outcome.startswith("ok:"), outcome
    assert reorders == [["networksetup", "-ordernetworkservices", "Wi-Fi", "AX88179B", "M3100"]]


def test_blank_input_does_nothing():
    text, state = handle("", ConsoleState(), SERVICES, runner)
    assert text == ""
    assert state.quit is False


# --- parser -----------------------------------------------------------------


def test_every_subcommand_parses():
    parser = build_parser()
    for argv in (
        ["status"],
        ["interfaces"],
        ["interfaces", "--bench"],
        ["bench"],
        ["failover", "status"],
        ["failover", "backup"],
        ["failover", "backup", "--service", "M3100"],
        ["priority"],
        ["priority", "--promote", "Wi-Fi"],
        ["ladder", "network"],
        ["ladder", "dns", "--repair"],
        ["commands"],
        ["run", "nwi"],
        ["run", "iface", "--value", "device=en0"],
        ["guide"],
        ["console"],
    ):
        assert parser.parse_args(argv).func is not None


def test_a_subcommand_is_required():
    import pytest

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


# The "window shell" tests that used to sit here covered `netdnsmonitor.window`,
# the failover line's own AppKit console. That module was dropped in the
# reconcile: this app already ships an arbitrary-shell console
# (console.py + console_window.py, covered by test_console.py and
# test_console_window.py) reachable from both the menu bar and the dashboard
# button, and two GUI consoles would be two things to keep in sync.
#
# What survives here is the REPL behind `netdns console`, now imported from
# cli_console.py -- a terminal surface over the command catalogue, which is a
# different product from the GUI console and still worth having.
