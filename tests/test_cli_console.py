"""Offline tests for the CLI renderers, the command catalogue, and the console
loop. `handle` is a pure function of (line, state) so the REPL is testable
without a terminal.
"""

from types import SimpleNamespace

from netdnsmonitor.cli import (
    build_parser,
    interface_rows,
    render_catalog,
    render_failover_status,
    render_interfaces,
    render_usage_guide,
)
from netdnsmonitor.commands import BY_KEY, CATALOG, missing_placeholder, resolve
from netdnsmonitor.console import ConsoleState, handle
from netdnsmonitor.service_order import NetworkService

LISTING = """An asterisk (*) denotes that a network service is disabled.
(1) AX88179B
(Hardware Port: AX88179B, Device: en6)

(*) M3100
(Hardware Port: M3100, Device: en12)

(2) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)
"""


def runner(argv):
    if argv[:2] == ["networksetup", "-listnetworkserviceorder"]:
        return SimpleNamespace(returncode=0, stdout=LISTING, stderr="")
    return SimpleNamespace(returncode=0, stdout=f"ran {' '.join(argv)}", stderr="")


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


# --- renderers --------------------------------------------------------------


def test_interface_table_marks_disabled_services():
    rows = [
        {"name": "M3100", "device": "en12", "enabled": False,
         "reachable": False, "throughput_mbps": None},
        {"name": "Wi-Fi", "device": "en0", "enabled": True,
         "reachable": True, "throughput_mbps": 3.8},
    ]
    text = render_interfaces(rows)
    assert "OFF" in text and "M3100" in text
    assert "3.8" in text


def test_interface_table_says_not_probed_rather_than_unreachable():
    rows = [{"name": "iPhone USB", "device": "en11", "enabled": True,
             "reachable": None, "throughput_mbps": None}]
    assert "not probed" in render_interfaces(rows)


def test_unmeasured_speed_shows_a_dash_not_a_zero():
    rows = [{"name": "Wi-Fi", "device": "en0", "enabled": True,
             "reachable": True, "throughput_mbps": None}]
    assert " -" in render_interfaces(rows)
    assert "0.0" not in render_interfaces(rows)


def test_empty_interface_list_says_so():
    assert "No network services" in render_interfaces([])


def test_catalog_render_flags_the_mutating_commands():
    text = render_catalog()
    assert "changes system state" in text
    assert "enable" in text and "nwi" in text


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
        "error": None, "active_side": "backup", "active_service": "M3100",
        "auto_enabled": True, "last_event": "ok: switched",
        "preferred": {"name": "USB 2.5G", "device": "en9", "enabled": True,
                      "reachable": False, "throughput_mbps": None},
        "backups": [
            {"name": "M3100", "device": "en12", "enabled": True,
             "reachable": True, "throughput_mbps": 12.0},
            {"name": "Wi-Fi", "device": "en0", "enabled": True,
             "reachable": True, "throughput_mbps": 3.8},
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
        runner, prober=lambda d: d == "en0",
        meter=lambda d: measured.append(d) or 5.0, measure=True,
    )
    assert measured == ["en0"]
    assert rows[2]["throughput_mbps"] == 5.0
    assert rows[0]["throughput_mbps"] is None


def test_no_benchmark_unless_asked():
    rows = interface_rows(runner, prober=lambda d: True, meter=lambda d: 5.0)
    assert all(r["throughput_mbps"] is None for r in rows)


# --- console loop -----------------------------------------------------------


def test_quit_sets_the_quit_flag():
    text, state = handle("q", ConsoleState(), SERVICES, runner)
    assert state.quit is True


def test_help_returns_the_guide():
    text, _ = handle("?", ConsoleState(), SERVICES, runner)
    assert "what to do when the network breaks" in text


def test_a_read_only_command_runs_immediately():
    text, state = handle("nwi", ConsoleState(), SERVICES, runner)
    assert "$ scutil --nwi" in text
    assert state.pending_key is None


def test_a_command_can_be_picked_by_number():
    text, _ = handle("1", ConsoleState(), SERVICES, runner)
    assert "scutil --nwi" in text


def test_an_out_of_range_number_is_rejected():
    text, _ = handle("999", ConsoleState(), SERVICES, runner)
    assert "unknown" in text


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

    def recording(argv):
        called.append(argv)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    text, state = handle("flush-dns", ConsoleState(), SERVICES, recording)
    assert "CHANGES SYSTEM STATE" in text
    assert "dscacheutil -flushcache" in text, "the user must see what they are approving"
    assert state.pending_confirm is True
    assert called == [], "nothing may run before confirmation"


def test_confirming_a_mutating_command_runs_it():
    _, state = handle("flush-dns", ConsoleState(), SERVICES, runner)
    text, state = handle("yes", state, SERVICES, runner)
    assert "$ dscacheutil -flushcache" in text
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


def test_shortcuts_are_named_actions_not_executed_inline():
    """`handle` stays pure; the loop performs the live ones."""
    for key, token in [
        ("__INTERFACES__", "i"), ("__BENCH__", "b"), ("__STATUS__", "s"),
        ("__SWITCH_BACKUP__", "f"), ("__SWITCH_PREFERRED__", "p"),
    ]:
        text, _ = handle(token, ConsoleState(), SERVICES, runner)
        assert text == key


def test_blank_input_does_nothing():
    text, state = handle("", ConsoleState(), SERVICES, runner)
    assert text == ""
    assert state.quit is False


# --- parser -----------------------------------------------------------------


def test_every_subcommand_parses():
    parser = build_parser()
    for argv in (
        ["status"], ["interfaces"], ["interfaces", "--bench"], ["bench"],
        ["failover", "status"], ["failover", "backup"],
        ["failover", "backup", "--service", "M3100"],
        ["priority"], ["priority", "--promote", "Wi-Fi"],
        ["ladder", "network"], ["ladder", "dns", "--repair"],
        ["commands"], ["run", "nwi"], ["run", "iface", "--value", "device=en0"],
        ["guide"], ["console"],
    ):
        assert parser.parse_args(argv).func is not None


def test_a_subcommand_is_required():
    import pytest

    with pytest.raises(SystemExit):
        build_parser().parse_args([])


# --- window shell (the testable parts) --------------------------------------


def test_dropdown_titles_flag_state_changing_commands():
    """The label says so before the click, not after."""
    from netdnsmonitor.window import command_menu_titles

    titles = command_menu_titles()
    assert len(titles) == len(CATALOG)
    marked = [t for t in titles if t.startswith("!")]
    assert any("enable" in t for t in marked)
    assert all(not t.startswith("!") for t in titles if " nwi " in t)


def test_dropdown_pick_inserts_rather_than_runs():
    """Several entries change system state; a menu that fired on selection
    would run one before the user had read it.
    """
    from netdnsmonitor.window import ConsoleWindowController

    class FakeField:
        def __init__(self):
            self.value = None

        def setStringValue_(self, text):
            self.value = text

    controller = ConsoleWindowController({})
    controller.input_field = FakeField()
    controller.insert_command(0)
    assert controller.input_field.value == CATALOG[0].key


def test_dropdown_pick_ignores_an_out_of_range_index():
    from netdnsmonitor.window import ConsoleWindowController

    controller = ConsoleWindowController({})
    controller.insert_command(-1)   # the placeholder row
    controller.insert_command(9999)
    assert controller.input_field is None


def test_window_module_imports_without_a_gui_session():
    """The offline suite must be able to import it; AppKit window classes are
    only touched inside show().
    """
    import netdnsmonitor.window as window

    assert hasattr(window, "ConsoleWindowController")
