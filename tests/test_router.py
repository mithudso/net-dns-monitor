"""Tests for the app's bootpd/pf router mode.

Nothing here runs osascript, pfctl or launchctl: `run_fn` and `exists_fn` are
injected, and the root script is asserted on as a string.
"""

import base64
import plistlib
import re
import subprocess
import threading
from types import SimpleNamespace

import pytest

from netdnsmonitor import router as router_module
from netdnsmonitor.router import (
    BUSY_MESSAGE,
    CONFLICT_MESSAGE,
    PF_ANCHOR,
    PF_TOKEN_FILE,
    ROUTER_STACK_DAEMON,
    Router,
    bootpd_plist,
    pf_rule,
    start_script,
    stop_script,
    validate,
)

GOOD = dict(
    wan_if="en3",
    lan_if="en0",
    lan_ip="192.168.10.1",
    lan_netmask="255.255.255.0",
    dhcp_start="192.168.10.100",
    dhcp_end="192.168.10.200",
)


class Recorder:
    def __init__(self, returncode=0, stderr="", raises=None):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr
        self.raises = raises

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(returncode=self.returncode, stdout="", stderr=self.stderr)


def make_router(run_fn=None, exists=False, **overrides):
    values = {**GOOD, **overrides}
    return Router(
        **values,
        run_fn=run_fn if run_fn is not None else Recorder(),
        exists_fn=lambda path: exists,
    )


def _decoded_payloads(script):
    return [base64.b64decode(m) for m in re.findall(r"echo ([A-Za-z0-9+/=]+) \|", script)]


def test_start_runs_exactly_one_osascript_and_stages_nothing_in_tmp():
    run = Recorder()
    outcome = make_router(run).start()
    assert outcome.startswith("ok:")
    assert len(run.calls) == 1
    argv, kwargs = run.calls[0]
    assert argv[0].endswith("osascript")
    assert "with administrator privileges" in argv[-1]
    assert not any("/tmp/" in part for part in argv)
    assert kwargs.get("timeout")


def test_the_root_script_is_newline_free():
    """`_osascript_admin` does not escape newlines; the script must not need it."""
    settings = validate(**GOOD)
    assert "\n" not in start_script(settings)
    assert "\n" not in stop_script()


@pytest.mark.parametrize(
    "field, value",
    [
        ("lan_ip", "1.1.1.1;id"),
        ("lan_ip", "1.1.1.1 netmask 0 ; id"),
        ("wan_if", "en0; id"),
        ("lan_if", "-a"),
        ("lan_netmask", "255.255.255.0;id"),
        ("dhcp_start", "192.168.10.100$(id)"),
        ("dhcp_end", "10.0.0.1"),  # outside the LAN network
    ],
)
def test_an_invalid_value_raises_and_never_reaches_the_runner(field, value):
    values = {**GOOD, field: value}
    with pytest.raises(ValueError):
        validate(**values)
    run = Recorder()
    outcome = make_router(run, **{field: value}).start()
    assert outcome.startswith("refused:")
    assert run.calls == []


def test_a_value_assigned_after_construction_is_still_validated():
    """The window writes these attributes directly; validation cannot live only
    in the constructor.
    """
    run = Recorder()
    router = make_router(run)
    router.lan_ip = "1.1.1.1; id"
    assert router.start().startswith("refused:")
    assert run.calls == []


def test_same_wan_and_lan_is_refused():
    run = Recorder()
    assert make_router(run, lan_if="en3").start().startswith("refused:")
    assert run.calls == []


def test_a_reversed_dhcp_range_is_refused():
    with pytest.raises(ValueError):
        validate(**{**GOOD, "dhcp_start": "192.168.10.200", "dhcp_end": "192.168.10.100"})


def test_the_pf_rule_ends_in_a_real_newline_not_a_backslash_n():
    rule = pf_rule(validate(**GOOD))
    assert "\\n" not in rule
    assert rule.endswith("\n")
    assert rule == "nat on en3 from en0:network to any -> (en3)\n"


def test_the_encoded_pf_rule_in_the_script_decodes_to_that_rule():
    settings = validate(**GOOD)
    payloads = _decoded_payloads(start_script(settings))
    assert pf_rule(settings).encode() in payloads


def test_the_bootpd_plist_uses_dhcp_router_and_a_derived_network():
    settings = validate(**{**GOOD, "lan_netmask": "255.255.0.0", "dhcp_end": "192.168.20.5"})
    subnet = bootpd_plist(settings)["Subnets"][0]
    assert subnet["dhcp_router"] == "192.168.10.1"
    assert "routers" not in subnet
    assert subnet["net_address"] == "192.168.0.0"
    assert subnet["net_mask"] == "255.255.0.0"
    assert subnet["net_range"] == ["192.168.10.100", "192.168.20.5"]


def test_a_prefix_length_netmask_is_normalised_to_dotted_form():
    settings = validate(**{**GOOD, "lan_netmask": "24"})
    assert settings.netmask == "255.255.255.0"
    assert "netmask 255.255.255.0" in start_script(settings)


def test_the_encoded_plist_in_the_script_is_the_bootpd_plist():
    settings = validate(**GOOD)
    plists = [p for p in _decoded_payloads(start_script(settings)) if p.startswith(b"<?xml")]
    assert len(plists) == 1
    assert plistlib.loads(plists[0]) == bootpd_plist(settings)


def test_start_loads_into_an_anchor_and_never_replaces_the_main_ruleset():
    script = start_script(validate(**GOOD))
    assert f"pfctl -a {PF_ANCHOR} -f -" in script
    assert PF_ANCHOR.startswith("com.apple/")
    assert "pfctl -f" not in script
    assert "pfctl -e" not in script


def test_stop_flushes_only_the_anchor_and_does_not_disable_pf():
    script = stop_script()
    assert f"pfctl -a {PF_ANCHOR} -F all" in script
    assert "-F all -d" not in script
    assert not re.search(r"pfctl[^;]* -d\b", script)


def test_both_scripts_stop_at_the_first_failing_step():
    assert start_script(validate(**GOOD)).startswith("set -e;")
    assert stop_script().startswith("set -e;")


def test_a_failing_script_is_reported_failed_not_started():
    run = Recorder(returncode=1, stderr="some root-side error text")
    outcome = make_router(run).start()
    assert outcome.startswith("failed:")
    assert "exit 1" in outcome
    assert "root-side error text" not in outcome


def test_a_cancelled_dialog_is_reported_as_cancelled():
    run = Recorder(returncode=1, stderr="execution error: User canceled. (-128)")
    assert make_router(run).start().startswith("cancelled:")


def test_stop_reports_failure_from_the_exit_code():
    run = Recorder(returncode=5)
    assert make_router(run).stop().startswith("failed: exit 5")


def test_a_nat_read_back_failure_is_named_from_osascripts_stderr():
    """osascript itself exits 1 for every `do shell script` error. The script's
    own exit code reaches the caller only inside stderr, as `(5)`.
    """
    run = Recorder(returncode=1, stderr="0:9: execution error: NDM_NAT_STILL_LOADED (5)\n")
    outcome = make_router(run).stop()
    assert outcome.startswith("failed: exit 5; ")
    assert f"still loaded in {PF_ANCHOR}" in outcome
    assert "NDM_NAT_STILL_LOADED" not in outcome


def test_a_bootpd_read_back_failure_is_named_from_its_marker():
    run = Recorder(returncode=1, stderr="0:9: execution error: NDM_BOOTPD_STILL_LOADED (6)")
    outcome = make_router(run).stop()
    assert outcome.startswith("failed: exit 6; ")
    assert "bootpd launchd job is still loaded" in outcome


def test_an_exit_code_without_a_marker_is_not_read_as_a_read_back_failure():
    """`set -e` passes on any failing step's own code, and 5 is a common one."""
    run = Recorder(returncode=1, stderr="0:9: execution error: sysctl: denied for sk-x (5)")
    outcome = make_router(run).stop()
    assert outcome == "failed: exit 5; steps before the failing one may have taken effect"


def test_the_stop_read_backs_write_their_markers_to_stderr():
    stop = stop_script()
    assert "echo NDM_NAT_STILL_LOADED >&2; exit 5; fi" in stop
    assert "echo NDM_BOOTPD_STILL_LOADED >&2; exit 6; fi" in stop


def test_a_runner_that_cannot_start_is_a_failure_with_only_the_class_name():
    run = Recorder(raises=OSError("secret-ish detail"))
    outcome = make_router(run).start()
    assert outcome == "failed: could not run osascript (OSError)"


def test_a_timeout_is_a_failure_that_does_not_claim_nothing_ran():
    run = Recorder(raises=subprocess.TimeoutExpired(cmd="osascript", timeout=1))
    outcome = make_router(run).start()
    assert outcome.startswith("failed:")
    assert "may have partly run" in outcome


def test_start_refuses_while_the_router_stack_daemon_is_installed():
    seen = []
    run = Recorder()
    router = Router(**GOOD, run_fn=run, exists_fn=lambda path: seen.append(path) or True)
    assert router.start() == CONFLICT_MESSAGE
    assert seen == [ROUTER_STACK_DAEMON]
    assert run.calls == []


def test_stop_refuses_while_the_router_stack_daemon_is_installed():
    """Stop sets forwarding to 0, which would cut off the router/ stack's clients."""
    run = Recorder()
    assert make_router(run, exists=True).stop() == CONFLICT_MESSAGE
    assert run.calls == []


def test_an_unreadable_daemon_path_is_treated_as_a_conflict():
    def boom(path):
        raise PermissionError("nope")

    run = Recorder()
    router = Router(**GOOD, run_fn=run, exists_fn=boom)
    assert router.start() == CONFLICT_MESSAGE
    assert run.calls == []


def test_the_constructor_does_not_raise_on_bad_config():
    """The app builds this at launch; a bad config value must not crash it."""
    Router(**{**GOOD, "lan_ip": "not an ip"}, run_fn=Recorder(), exists_fn=lambda p: False)


def test_the_legacy_keyword_constructor_still_works():
    router = Router(
        wan_if="en3",
        lan_if="en0",
        lan_ip="192.168.10.1",
        lan_netmask="255.255.255.0",
        dhcp_start="192.168.10.100",
        dhcp_end="192.168.10.200",
    )
    assert router.run_fn is subprocess.run
    assert router.timeout == router_module.DEFAULT_TIMEOUT_SECONDS


def test_ok_is_only_claimed_after_the_script_reads_its_changes_back():
    start = start_script(validate(**GOOD))
    assert start.index("launchctl load") < start.index("launchctl print")
    assert f"pfctl -a {PF_ANCHOR} -s nat" in start
    stop = stop_script()
    assert "exit 5; fi" in stop and "exit 6; fi" in stop


def test_forwarding_is_turned_on_only_after_nat_and_bootpd_read_back():
    """A read-back that fails under `set -e` must not leave forwarding on with
    no NAT or DHCP behind it.
    """
    start = start_script(validate(**GOOD))
    forwarding = start.index("net.inet.ip.forwarding=1")
    assert forwarding > start.index(f"pfctl -a {PF_ANCHOR} -s nat")
    assert forwarding > start.index("launchctl print")


def _step(script, needle):
    steps = [step for step in script.split("; if ") if needle in step]
    assert len(steps) == 1, steps
    return steps[0]


def test_start_takes_one_pf_reference_only_when_it_holds_none():
    """Every `pfctl -E` adds a reference; without the token check each start
    leaked one and pf could never be released.
    """
    start = start_script(validate(**GOOD))
    assert start.count("pfctl -E") == 1
    enable = _step(start, "pfctl -E")
    assert f"[ ! -s {PF_TOKEN_FILE} ]" in enable
    # A token left from before a `pfctl -d` is void, so pf being off retakes one.
    assert "! /sbin/pfctl -s info 2>/dev/null | /usr/bin/grep -q 'Status: Enabled'" in enable
    assert enable.index("Status: Enabled") < enable.index("pfctl -E")
    assert "s/^Token : //p" in enable
    assert f"> {PF_TOKEN_FILE}" in enable
    # An enable that printed no token fails the start instead of passing silently.
    assert f"; [ -s {PF_TOKEN_FILE} ]" in start
    assert start.index("pfctl -E") < start.index(f"; [ -s {PF_TOKEN_FILE} ]")


def test_stop_releases_the_recorded_pf_reference_and_forgets_it():
    stop = stop_script()
    release = _step(stop, "pfctl -X")
    assert f"[ -s {PF_TOKEN_FILE} ]" in release
    assert f'/sbin/pfctl -X "$(/bin/cat {PF_TOKEN_FILE})" || true' in release
    assert release.index("pfctl -X") < release.index(f"/bin/rm -f {PF_TOKEN_FILE}")


def test_a_start_while_another_start_or_stop_runs_is_refused():
    entered = threading.Event()
    release = threading.Event()
    calls = []

    def blocking_run(argv, **kwargs):
        calls.append(argv)
        entered.set()
        release.wait(5)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    router = make_router(blocking_run)
    results = []
    worker = threading.Thread(target=lambda: results.append(router.start()))
    worker.start()
    try:
        assert entered.wait(5)
        assert router.start() == BUSY_MESSAGE
        assert router.stop() == BUSY_MESSAGE
    finally:
        release.set()
        worker.join(5)
    assert len(calls) == 1
    assert results[0].startswith("ok:")
    assert router.stop().startswith("ok:")


def test_a_raising_runner_does_not_strand_the_lock():
    router = make_router(Recorder(raises=RuntimeError("boom")))
    with pytest.raises(RuntimeError):
        router.start()
    router.run_fn = Recorder()
    assert router.start().startswith("ok:")


@pytest.mark.parametrize(
    "updates",
    [
        {"lan_ip": "192.168.10.0"},
        {"lan_ip": "192.168.10.255"},
        {"dhcp_start": "192.168.10.0"},
        {"dhcp_end": "192.168.10.255"},
        {"dhcp_start": "192.168.10.1"},
        {"lan_ip": "192.168.10.150"},
    ],
)
def test_reserved_or_router_addresses_cannot_be_leased(updates):
    with pytest.raises(ValueError):
        validate(**{**GOOD, **updates})


# --- audit fixes -----------------------------------------------------------


@pytest.mark.parametrize(
    "updates",
    [
        {"lan_netmask": "0.0.0.0"},
        {"lan_netmask": "0"},
        {"lan_netmask": "31"},
        {"lan_netmask": "7"},
        {"lan_netmask": "0.0.0.255"},
        {"lan_ip": "127.0.0.1", "dhcp_start": "127.0.0.100", "dhcp_end": "127.0.0.200"},
        {"lan_ip": "8.8.8.1", "dhcp_start": "8.8.8.100", "dhcp_end": "8.8.8.200"},
        {"lan_ip": "169.254.1.1", "dhcp_start": "169.254.1.100", "dhcp_end": "169.254.1.200"},
    ],
)
def test_absurd_lan_networks_are_refused(updates):
    with pytest.raises(ValueError):
        validate(**{**GOOD, **updates})


@pytest.mark.parametrize("mask", ["255.0.0.0", "255.255.255.252", "30", "8"])
def test_private_networks_at_the_prefix_limits_are_accepted(mask):
    settings = validate(
        **{
            **GOOD,
            "lan_ip": "10.0.0.1",
            "lan_netmask": mask,
            "dhcp_start": "10.0.0.2",
            "dhcp_end": "10.0.0.2",
        }
    )
    assert settings.lan_ip == "10.0.0.1"


def test_a_permission_error_on_the_daemon_path_is_a_conflict(monkeypatch):
    def denied(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(router_module.os, "lstat", denied)
    assert Router(**GOOD)._conflict() is True


def test_a_missing_daemon_path_is_not_a_conflict(tmp_path, monkeypatch):
    monkeypatch.setattr(router_module, "ROUTER_STACK_DAEMON", str(tmp_path / "absent.plist"))
    assert Router(**GOOD)._conflict() is False


def test_start_refuses_when_lan_is_the_default_route_interface():
    run = Recorder()
    router = Router(
        **GOOD, run_fn=run, exists_fn=lambda p: False, primary_interface_fn=lambda: "en0"
    )
    outcome = router.start()
    assert outcome == "refused: lan_interface en0 carries this Mac's default route"
    assert run.calls == []


@pytest.mark.parametrize("primary", [None, "en3", "utun4"])
def test_start_proceeds_when_the_default_route_is_elsewhere_or_unknown(primary):
    run = Recorder()
    router = Router(
        **GOOD, run_fn=run, exists_fn=lambda p: False, primary_interface_fn=lambda: primary
    )
    assert router.start().startswith("ok:")


def test_start_proceeds_when_the_primary_interface_lookup_raises():
    def boom():
        raise RuntimeError("lookup")

    run = Recorder()
    router = Router(**GOOD, run_fn=run, exists_fn=lambda p: False, primary_interface_fn=boom)
    assert router.start().startswith("ok:")


def test_start_records_prior_forwarding_once_and_stop_restores_it():
    start = start_script(validate(**GOOD))
    record = start.index(f"sysctl -n net.inet.ip.forwarding > {router_module.FORWARDING_FILE}")
    assert "if [ ! -s " + router_module.FORWARDING_FILE in start[record - 80 : record]
    assert record < start.index("net.inet.ip.forwarding=1")
    stop = stop_script()
    assert "net.inet.ip.forwarding=0" not in stop
    assert 'net.inet.ip.forwarding="$prior"' in stop
    assert f"rm -f {router_module.FORWARDING_FILE}" in stop


def test_stop_message_says_the_lan_address_is_not_restored():
    assert "LAN interface address" in make_router().stop()
    assert "not restored" in make_router().stop()


@pytest.mark.parametrize(
    "marker, text",
    [
        ("NDM_START_PF_TOKEN", "enable token"),
        ("NDM_START_NAT_NOT_LOADED", "no NAT rule"),
        ("NDM_START_BOOTPD_NOT_LOADED", "bootpd launchd job is not loaded"),
    ],
)
def test_start_readback_markers_map_to_fixed_text(marker, text):
    outcome = make_router(Recorder(returncode=1, stderr=f"x {marker} (5)")).start()
    assert text in outcome
    assert outcome.startswith("failed: exit 5")


def test_start_script_prints_a_marker_for_each_readback():
    start = start_script(validate(**GOOD))
    for marker in ("NDM_START_PF_TOKEN", "NDM_START_NAT_NOT_LOADED", "NDM_START_BOOTPD_NOT_LOADED"):
        assert f"echo {marker} >&2" in start


@pytest.mark.parametrize("script", [start_script(validate(**GOOD)), stop_script()])
def test_the_root_scripts_parse_as_posix_sh(script):
    result = subprocess.run(["/bin/sh", "-n", "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_starting_the_router_never_enables_dhcp_at_boot():
    # `load -w` wrote an enabled override, so bootpd answered DHCP on every
    # boot after one Start, router_enabled or not. DHCP is opt-in: Start loads
    # it for this session only, and Stop writes the disabled override back.
    start = start_script(validate(**GOOD))
    assert "launchctl load -w" not in start
    assert "launchctl unload -w" not in start
    assert f"/bin/launchctl load -F {router_module.BOOTPS_DAEMON}" in start
    assert f"/bin/launchctl unload -w {router_module.BOOTPS_DAEMON}" in stop_script()
