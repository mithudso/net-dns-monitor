"""Tests for the app's bootpd/pf router mode.

Nothing here runs osascript, pfctl or launchctl: `run_fn` and `exists_fn` are
injected, and the root script is asserted on as a string.
"""

import base64
import plistlib
import re
import subprocess
from types import SimpleNamespace

import pytest

from netdnsmonitor import router as router_module
from netdnsmonitor.router import (
    CONFLICT_MESSAGE,
    PF_ANCHOR,
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
    assert "then exit 5" in stop and "then exit 6" in stop
