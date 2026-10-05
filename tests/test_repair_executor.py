from types import SimpleNamespace

from netdnsmonitor import privileges
from netdnsmonitor.ladder import LadderStep
from netdnsmonitor.repair_executor import DSCACHEUTIL, NETSTAT, SCUTIL, make_repair_executor

KILLALL = privileges.KILLALL


def fake_run_factory(returncode=0, stdout="ok output", stderr=""):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)

    return fake_run, calls


def test_flush_dns_cache_runs_flush_and_hup_and_reports_ok():
    run_fn, calls = fake_run_factory(returncode=0)
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert outcome == "ok"
    # Exact argv, not a substring of argv[0]. A membership check on c[0] also
    # accepts `dscacheutil -statistics` (flushes nothing, still reports "ok")
    # and `killall -9 mDNSResponder` (kills the resolver daemon outright
    # instead of signalling it). Both mutations passed the old assertions.
    #
    # Absolute paths: this argv runs from a menu-bar app whose PATH is whatever
    # launchd handed it, and privileges.py already names the same binaries by
    # full path in the sudoers rule it writes.
    assert [DSCACHEUTIL, "-flushcache"] in calls
    assert [KILLALL, "-HUP", "mDNSResponder"] in calls
    assert all(call[0].startswith("/") for call in calls)


def test_flush_dns_cache_flushes_the_cache_before_signalling_the_resolver():
    run_fn, calls = fake_run_factory(returncode=0)
    executor = make_repair_executor(run_fn=run_fn)
    executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert calls.index([DSCACHEUTIL, "-flushcache"]) < calls.index(
        [KILLALL, "-HUP", "mDNSResponder"]
    )


def test_flush_dns_cache_reports_failure_on_nonzero_returncode():
    run_fn, calls = fake_run_factory(returncode=1, stderr="permission denied")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert outcome.startswith("failed")
    assert "permission denied" in outcome


def test_flush_dns_cache_reports_partial_when_only_hup_lacks_privilege():
    # Empirically confirmed: dscacheutil -flushcache succeeds unprivileged, but
    # killall -HUP mDNSResponder can't signal a daemon owned by another user.
    def run_fn(args, **kwargs):
        if args[0] == DSCACHEUTIL:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return SimpleNamespace(
            returncode=1, stdout="", stderr="No matching processes belonging to you were found"
        )

    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert outcome.startswith("partial")
    assert "flushed" in outcome.lower()
    assert "privilege" in outcome.lower()


def test_privileged_repair_steps_are_stubbed_and_never_shell_out():
    run_fn, calls = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert "NEEDS_PRIVILEGE" in outcome
    assert calls == []


# --- with elevated permissions granted -------------------------------------
#
# `is_granted_fn` defaults to "no", so every test above describes an ungranted
# machine and none of them acquired a new subprocess when the grant landed. These
# pass it explicitly. See privileges.py for how narrow the grant is.


def granted_executor(run_fn, interface="en0"):
    return make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: interface,
    )


# Trimmed from a real `ipconfig getpacket en0` on a DHCP-configured interface.
LEASE_PACKET = """op = BOOTREPLY
htype = 1
yiaddr = 192.0.2.10
options:
Options count is 4
dhcp_message_type (uint8): ACK 0x5
lease_time (uint32): 0x15180
router (ip_mult): {192.0.2.1}
end (none):
"""


def getpacket_argv(interface):
    return ["/usr/sbin/ipconfig", "getpacket", interface]


def renewal_run_factory(
    packet=LEASE_PACKET,
    getpacket_returncode=0,
    getpacket_stderr="",
    set_returncode=0,
    set_stderr="",
):
    """`ipconfig getpacket` answers with `packet`; everything else with the set result."""
    calls = []

    def run_fn(args, **kwargs):
        calls.append(args)
        if args[1:2] == ["getpacket"]:
            return SimpleNamespace(
                returncode=getpacket_returncode, stdout=packet, stderr=getpacket_stderr
            )
        return SimpleNamespace(returncode=set_returncode, stdout="", stderr=set_stderr)

    return run_fn, calls


def test_the_ungranted_stub_says_how_to_grant_it():
    """Otherwise the outcome is a dead end: it names a missing capability and no
    way to acquire it, which is what this whole feature was about.
    """
    run_fn, _calls = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert "Grant elevated permissions" in outcome


def test_flush_dns_cache_retries_the_resolver_restart_with_sudo_when_granted():
    calls = []

    def run_fn(args, **kwargs):
        calls.append(args)
        # The unprivileged HUP still fails; the sudo one succeeds.
        if args[0] == KILLALL:
            return SimpleNamespace(returncode=1, stdout="", stderr="not permitted")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    outcome = granted_executor(run_fn)(
        LadderStep("flush_dns_cache", "repair", needs_privilege=False)
    )
    assert outcome.startswith("ok")
    assert ["/usr/bin/sudo", "-n", "/usr/bin/killall", "-HUP", "mDNSResponder"] in calls


def test_flush_dns_cache_does_not_reach_for_sudo_when_the_plain_hup_worked():
    """No point spending an elevated call on something that already succeeded, and
    a spurious sudo invocation shows up in the system's own audit log.
    """
    run_fn, calls = fake_run_factory(returncode=0)
    outcome = granted_executor(run_fn)(
        LadderStep("flush_dns_cache", "repair", needs_privilege=False)
    )
    assert outcome == "ok"
    assert not any("sudo" in " ".join(call) for call in calls)


def test_a_granted_rule_that_still_fails_is_reported_differently_from_no_grant():
    """The two situations need opposite fixes -- grant the permission, versus work
    out why the rule does not match -- so they must not share a message.
    """

    def run_fn(args, **kwargs):
        return SimpleNamespace(returncode=0 if args[0] == DSCACHEUTIL else 1, stdout="", stderr="")

    outcome = granted_executor(run_fn)(
        LadderStep("flush_dns_cache", "repair", needs_privilege=False)
    )
    assert outcome.startswith("partial")
    assert "granted sudo rule did not" in outcome
    assert "Grant elevated permissions" not in outcome


def test_renewing_a_lease_targets_the_default_route_interface():
    run_fn, calls = renewal_run_factory()
    outcome = granted_executor(run_fn, interface="en9")(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("ok")
    assert "en9" in outcome
    assert ["/usr/bin/sudo", "-n", "/usr/sbin/ipconfig", "set", "en9", "DHCP"] in calls


def test_renewing_a_lease_with_no_default_route_does_not_shell_out():
    run_fn, calls = fake_run_factory(returncode=0)
    outcome = granted_executor(run_fn, interface=None)(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert "cannot renew" in outcome
    # `primary_interface` answers None for a default route on a VPN tunnel too, so
    # the outcome must not assert that no route exists.
    assert "Ethernet or Wi-Fi" in outcome
    assert "no interface currently carries" not in outcome
    assert calls == []
    # primary_interface only returns en* names, so None also covers a full
    # tunnel VPN that holds the default route on utun. The old text said no
    # interface carried the route, which is false in that case.
    assert "no interface currently carries" not in outcome
    assert "tunnel" in outcome


def test_renewal_is_refused_when_the_grant_does_not_cover_this_interface():
    """The grant lists `ipconfig set <name> DHCP` per interface. A machine that
    now routes over an interface added after the grant has the mDNSResponder
    rule but not this one, and `sudo -n` would fail with a password prompt.
    """
    run_fn, calls = fake_run_factory(returncode=0)
    asked = []

    def dhcp_granted_fn(interface):
        asked.append(interface)
        return False

    executor = make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en7",
        dhcp_granted_fn=dhcp_granted_fn,
    )
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert outcome.startswith("NEEDS_PRIVILEGE")
    assert asked == ["en7"]
    assert calls == []


def test_renewal_runs_when_the_grant_covers_this_interface():
    run_fn, calls = renewal_run_factory()
    executor = make_repair_executor(
        run_fn=run_fn,
        # The mDNSResponder rule is irrelevant to a DHCP renewal once the
        # per-interface answer is available.
        is_granted_fn=lambda: False,
        primary_interface_fn=lambda: "en7",
        dhcp_granted_fn=lambda interface: interface == "en7",
    )
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert outcome.startswith("ok")
    # The method check is the unprivileged read, and it comes first.
    assert calls == [
        getpacket_argv("en7"),
        ["/usr/bin/sudo", "-n", "/usr/sbin/ipconfig", "set", "en7", "DHCP"],
    ]


def test_a_renewal_on_an_interface_the_grant_does_not_cover_reports_needs_privilege():
    """`is_granted` answers only for the mDNSResponder restart; the DHCP rules are
    separate lines enumerated at grant time. Dock a laptop and the default route
    moves to an interface no rule names -- the sudo call would be refused, and it
    is more honest (and cheaper) to say so than to run it and report the refusal.
    """
    run_fn, calls = fake_run_factory(returncode=0)
    executor = make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en5",
        covered_interfaces_fn=lambda: ["en0", "en9"],
    )
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert outcome.startswith("NEEDS_PRIVILEGE")
    assert "en5" in outcome
    assert calls == []


def test_a_blanket_grant_covers_whatever_interface_carries_the_default_route():
    run_fn, calls = renewal_run_factory()
    executor = make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en5",
        covered_interfaces_fn=lambda: list(privileges.ALL_INTERFACES_SENTINEL),
    )
    outcome = executor(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    assert outcome.startswith("ok")
    assert calls[-1] == ["/usr/bin/sudo", "-n", "/usr/sbin/ipconfig", "set", "en5", "DHCP"]


def test_a_failed_renewal_reports_the_command_and_the_error():
    run_fn, _calls = renewal_run_factory(set_returncode=1, set_stderr="no such interface")
    outcome = granted_executor(run_fn)(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("failed")
    assert "no such interface" in outcome


def is_set_call(args):
    return "set" in args


def test_renew_refuses_an_interface_not_using_dhcp():
    """`ipconfig set <if> DHCP` de-configures the interface's existing IPv4
    service first. On a hand-configured interface that replaces the static
    address with DHCP, and on a network with no DHCP server the interface is
    left without usable IPv4 -- while the report said "ok". `getpacket` prints
    nothing when DHCP is not active on the interface.
    """
    run_fn, calls = renewal_run_factory(packet="")
    outcome = granted_executor(run_fn, interface="en4")(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("cannot renew:")
    assert "en4" in outcome
    assert "Nothing was changed" in outcome
    assert calls == [getpacket_argv("en4")]
    assert not any(is_set_call(c) for c in calls)


def test_renew_refuses_a_packet_that_holds_no_lease():
    """An INFORM service configures its address by hand and only asks the DHCP
    server for options, so any packet it holds carries no lease time (RFC 2131
    4.3.5). Non-empty output is not enough to call the interface DHCP.
    """
    inform_ack = "op = BOOTREPLY\noptions:\ndhcp_message_type (uint8): ACK 0x5\nend (none):\n"
    run_fn, calls = renewal_run_factory(packet=inform_ack)
    outcome = granted_executor(run_fn)(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("cannot renew:")
    assert not any(is_set_call(c) for c in calls)


def test_renew_does_not_guess_when_the_dhcp_state_cannot_be_read():
    """A getpacket that failed says nothing about how the interface is
    configured. Reporting it as "not using DHCP" would be a confident wrong
    diagnosis, and renewing anyway is the hazard the check exists for.
    """
    run_fn, calls = renewal_run_factory(
        packet="", getpacket_returncode=1, getpacket_stderr="interface doesn't exist"
    )
    outcome = granted_executor(run_fn)(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("failed:")
    assert "not using DHCP" not in outcome
    assert "interface doesn't exist" in outcome
    assert "Nothing was changed" in outcome
    assert not any(is_set_call(c) for c in calls)


def test_the_dhcp_method_check_runs_unprivileged_and_bounded():
    seen = []

    def run_fn(args, **kwargs):
        seen.append((args, kwargs))
        stdout = LEASE_PACKET if args[1:2] == ["getpacket"] else ""
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    granted_executor(run_fn)(LadderStep("renew_dhcp_lease", "repair", needs_privilege=True))
    args, kwargs = seen[0]
    assert args == getpacket_argv("en0")
    assert "sudo" not in " ".join(args)
    assert kwargs["timeout"] == 5


def test_toggling_the_interface_is_never_automated_even_when_granted():
    """Down and up cannot be one command, and two means a crash in between leaves
    the machine offline with no network to fix it over. Reported as its own outcome
    rather than as a missing privilege, so granting permissions does not leave
    someone waiting for a step that will never run.
    """
    run_fn, calls = fake_run_factory(returncode=0)
    outcome = granted_executor(run_fn)(
        LadderStep("toggle_network_service", "repair", needs_privilege=True)
    )
    assert outcome.startswith("NOT_AUTOMATED")
    assert "NEEDS_PRIVILEGE" not in outcome
    assert calls == []


def test_check_interface_state_shells_out_to_scutil():
    run_fn, calls = fake_run_factory(stdout="Network reachable via Wi-Fi")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    assert "Network reachable via Wi-Fi" in outcome
    # `calls[0][0] == SCUTIL` also lets this step silently become
    # `scutil --dns`, i.e. a different check entirely.
    assert calls == [[SCUTIL, "--nwi"]]


def test_check_default_route_shells_out_to_netstat():
    """Untested until now, and its output is egressed to the Anthropic API
    inside ladder_results: replacing the command with `true` kept the suite
    green while the ladder reported nothing at all.
    """
    run_fn, calls = fake_run_factory(stdout="default 192.0.2.1 UGScg en0")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_default_route", "check", needs_privilege=False))
    assert "default 192.0.2.1" in outcome
    assert calls == [[NETSTAT, "-rn", "-f", "inet"], [NETSTAT, "-rn", "-f", "inet6"]]


def test_a_failed_check_command_is_reported_as_failed():
    """A check that exits non-zero used to report its (often empty) stdout as the
    finding, so a broken `netstat` looked like "no routes" in the report, the LLM
    bundle and the Slack alert.
    """
    run_fn, _calls = fake_run_factory(returncode=2, stdout="", stderr="")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_default_route", "check", needs_privilege=False))
    assert outcome.startswith("failed")
    assert "exited 2" in outcome


def test_a_check_command_with_no_output_says_so_rather_than_reporting_nothing():
    run_fn, _calls = fake_run_factory(returncode=0, stdout="", stderr="")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    assert outcome.startswith("no output")


def test_check_configured_dns_servers_shells_out_to_scutil_dns():
    run_fn, calls = fake_run_factory(stdout="nameserver[0] : 192.0.2.53")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_configured_dns_servers", "check", needs_privilege=False))
    assert "192.0.2.53" in outcome
    assert calls == [[SCUTIL, "--dns"]]


def test_check_resolver_overrides_reports_failure_instead_of_raising(tmp_path):
    """os.listdir can raise PermissionError, or FileNotFoundError via a TOCTOU
    race with the isdir check. state_machine's per-step guard would keep the
    incident alive, but it can only say the step raised; handling it here keeps
    the path in the outcome.
    """

    def boom(path):
        raise PermissionError(13, "Permission denied", path)

    executor = make_repair_executor(
        run_fn=fake_run_factory()[0],
        resolver_dir_exists_fn=lambda path: True,
        resolver_listdir_fn=boom,
    )
    outcome = executor(LadderStep("check_resolver_overrides", "check", needs_privilege=False))
    assert outcome.startswith("failed")
    assert "/etc/resolver" in outcome


def test_check_resolver_overrides_reports_none_when_dir_absent():
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(
        run_fn=run_fn,
        resolver_dir_exists_fn=lambda path: False,
        resolver_listdir_fn=lambda path: [],
    )
    outcome = executor(LadderStep("check_resolver_overrides", "check", needs_privilege=False))
    assert "no /etc/resolver overrides" in outcome


def test_check_resolver_overrides_lists_files_when_present():
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(
        run_fn=run_fn,
        resolver_dir_exists_fn=lambda path: True,
        resolver_listdir_fn=lambda path: ["corp.local"],
    )
    outcome = executor(LadderStep("check_resolver_overrides", "check", needs_privilege=False))
    assert "corp.local" in outcome


def test_resolve_against_public_resolver_reflects_query_result():
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn, query_fn=lambda domain: True)
    outcome = executor(
        LadderStep("resolve_against_public_resolver", "check", needs_privilege=False)
    )
    assert "resolved" in outcome.lower()


def test_resolve_against_public_resolver_reports_a_real_negative_answer():
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn, query_fn=lambda domain: False)
    outcome = executor(
        LadderStep("resolve_against_public_resolver", "check", needs_privilege=False)
    )
    assert "did NOT resolve" in outcome


def test_an_unreachable_public_resolver_is_not_reported_as_a_failed_name():
    """None means the query got no reply. Reporting it as "did NOT resolve"
    tells someone the name is broken everywhere when nothing was learned.
    """
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn, query_fn=lambda domain: None)
    outcome = executor(
        LadderStep("resolve_against_public_resolver", "check", needs_privilege=False)
    )
    assert "did NOT resolve" not in outcome
    assert "resolved via" not in outcome
    assert outcome.startswith("could not obtain a usable public resolver result")
    assert "example.com" in outcome


def test_unknown_step_name_returns_a_clear_message_instead_of_raising():
    run_fn, calls = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("not_a_real_step", "check", needs_privilege=False))
    assert "unknown step" in outcome.lower()
    # An unrecognised step name must never reach argv. This is the only
    # dispatch path that handles an unmapped name, so it is the one place
    # untrusted data could reach a command; the privileged-stub test asserts
    # `calls == []` and this one did not.
    assert calls == []


def test_subprocess_timeout_is_reported_not_raised():
    import subprocess

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=5)

    executor = make_repair_executor(run_fn=timing_out)
    outcome = executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert outcome == f"failed: {DSCACHEUTIL} did not complete (TimeoutExpired)"


def test_missing_binary_is_reported_not_raised():
    def missing_binary(args, **kwargs):
        raise FileNotFoundError(f"no such file: {args[0]}")

    executor = make_repair_executor(run_fn=missing_binary)
    outcome = executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    # Class name only: an OSError message can carry a path or other detail.
    assert outcome == f"failed: {SCUTIL} did not complete (FileNotFoundError)"


def test_requests_explicit_utf8_decoding_instead_of_relying_on_locale():
    captured = {}

    def run_fn(args, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    executor = make_repair_executor(run_fn=run_fn)
    executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"


def test_unicode_decode_error_is_reported_not_raised():
    def bad_decode(args, **kwargs):
        raise UnicodeDecodeError("ascii", b"\xe2", 0, 1, "ordinal not in range(128)")

    executor = make_repair_executor(run_fn=bad_decode)
    outcome = executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert outcome.startswith("failed")


def test_a_build_without_privileged_repairs_runs_nothing_and_says_why():
    from netdnsmonitor.distribution import is_unavailable, unavailable
    from netdnsmonitor.ladder import LadderStep

    calls = []

    def run_fn(args, **kwargs):
        calls.append(args)
        raise AssertionError("no subprocess may run for an unavailable repair")

    executor = make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en0",
        unavailable_fn=lambda what: unavailable("privileged_repairs", what),
    )
    for name in ("flush_dns_cache", "renew_dhcp_lease"):
        outcome = executor(LadderStep(name, "repair", True))
        assert is_unavailable(outcome)
        assert "Nothing was changed." in outcome
    assert calls == []


# --- the failover step -----------------------------------------------------


FAILOVER = LadderStep("switch_to_backup_network", "repair", needs_privilege=True)


def test_the_failover_step_refuses_to_run_without_a_classification():
    """The policy refuses classifications it was not configured for. Defaulting an
    absent one to "network" -- the value most likely to be permitted -- turns a
    caller's omission into a network switch the operator never authorised.
    """
    seen = []
    executor = make_repair_executor(
        run_fn=fake_run_factory()[0],
        failover_fn=lambda classification: seen.append(classification) or "ok: switched",
    )
    outcome = executor(FAILOVER)
    assert outcome.startswith("refused")
    assert seen == []


def test_a_failover_that_raises_is_reported_as_failed_not_raised():
    """Every other step returns a string whatever happens. state_machine has no
    per-step guard, so an exception here aborts the incident with no report.
    """

    def exploding(classification):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    executor = make_repair_executor(run_fn=fake_run_factory()[0], failover_fn=exploding)
    outcome = executor(FAILOVER, "network")
    assert outcome.startswith("failed")
    assert "UnicodeDecodeError" in outcome


def test_default_route_check_includes_ipv6_and_keeps_each_family_result():
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="route via utun4", stderr="")

    executor = make_repair_executor(run_fn=run)
    outcome = executor(LadderStep("check_default_route", "check", needs_privilege=False))
    assert calls == [
        ["/usr/sbin/netstat", "-rn", "-f", "inet"],
        ["/usr/sbin/netstat", "-rn", "-f", "inet6"],
    ]
    assert "IPv4" in outcome and "IPv6" in outcome


def test_one_unreadable_route_family_is_partial_not_missing_routes():
    def run(args, **kwargs):
        return SimpleNamespace(
            returncode=1 if args[-1] == "inet" else 0,
            stdout="" if args[-1] == "inet" else "default fe80::1 en0",
            stderr="permission denied" if args[-1] == "inet" else "",
        )

    executor = make_repair_executor(run_fn=run)
    outcome = executor(LadderStep("check_default_route", "check", needs_privilege=False))
    assert outcome.startswith("partial:")
    assert "IPv4 routes:\nfailed:" in outcome
    assert "IPv6 routes:\ndefault fe80::1 en0" in outcome


def _step(name, kind="repair"):
    return LadderStep(name, kind, needs_privilege=False)


def _timing_out_on(binary, other_returncode=0, other_stdout=""):
    import subprocess

    def run_fn(args, **kwargs):
        if args[0] == binary:
            raise subprocess.TimeoutExpired(cmd=args, timeout=5)
        return SimpleNamespace(returncode=other_returncode, stdout=other_stdout, stderr="")

    return run_fn


def test_a_hup_that_never_ran_is_not_reported_as_needing_privilege():
    outcome = make_repair_executor(run_fn=_timing_out_on(KILLALL))(_step("flush_dns_cache"))
    assert outcome == (
        "partial: dscacheutil cache flushed; the mDNSResponder HUP did not complete "
        "(TimeoutExpired)"
    )
    assert "requires elevated privilege" not in outcome
    assert "Grant elevated permissions" not in outcome


def test_a_hup_that_ran_and_was_refused_still_points_at_the_grant():
    def run_fn(args, **kwargs):
        if args[0] == KILLALL:
            return SimpleNamespace(returncode=1, stdout="", stderr="not permitted")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    outcome = make_repair_executor(run_fn=run_fn)(_step("flush_dns_cache"))
    assert "requires elevated privilege" in outcome and "Grant elevated" in outcome


def test_a_check_that_timed_out_does_not_claim_an_exit_status():
    outcome = make_repair_executor(run_fn=_timing_out_on(SCUTIL))(
        _step("check_interface_state", "check")
    )
    assert outcome == f"failed: {SCUTIL} did not complete (TimeoutExpired)"
    assert "exited" not in outcome


def test_a_check_that_ran_and_failed_still_reports_its_exit_status():
    run_fn, _ = fake_run_factory(returncode=2, stdout="", stderr="boom")
    outcome = make_repair_executor(run_fn=run_fn)(_step("check_interface_state", "check"))
    assert outcome == f"failed: {SCUTIL} --nwi exited 2 -- boom"


def test_a_timed_out_sudo_ipconfig_is_unknown_not_failed():
    def run_fn(args, **kwargs):
        if args[0] == privileges.SUDO:
            import subprocess

            raise subprocess.TimeoutExpired(cmd=args, timeout=5)
        return SimpleNamespace(returncode=0, stdout="lease_time (uint32): 0x1\n", stderr="")

    ex = make_repair_executor(
        run_fn=run_fn,
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en0",
        dhcp_granted_fn=lambda i: True,
    )
    outcome = ex(_step("renew_dhcp_lease"))
    assert outcome.startswith("unknown:")
    assert "did not complete (TimeoutExpired)" in outcome
    assert "may or may not have been sent" in outcome


def test_the_granted_hup_outcome_says_a_hup_was_sent_not_that_it_restarted():
    def run_fn(args, **kwargs):
        if args[0] == KILLALL:
            return SimpleNamespace(returncode=1, stdout="", stderr="not permitted")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    # The unprivileged HUP fails; the sudo one (also via KILLALL's argv tail) is
    # distinguished by argv[0] == sudo.
    def sudo_ok(args, **kwargs):
        if args[0] == privileges.SUDO:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        return run_fn(args, **kwargs)

    outcome = make_repair_executor(run_fn=sudo_ok, is_granted_fn=lambda: True)(
        _step("flush_dns_cache")
    )
    assert outcome == "ok (HUP sent to mDNSResponder using the granted privilege)"
    assert "restarted" not in outcome


def test_a_timed_out_getpacket_is_a_failed_read_not_a_missing_lease():
    ex = make_repair_executor(
        run_fn=_timing_out_on(privileges.IPCONFIG),
        is_granted_fn=lambda: True,
        primary_interface_fn=lambda: "en0",
        dhcp_granted_fn=lambda i: True,
    )
    outcome = ex(_step("renew_dhcp_lease"))
    assert outcome.startswith("failed: could not read the DHCP state of en0")
    assert "TimeoutExpired" in outcome
