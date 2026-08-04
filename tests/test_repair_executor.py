from types import SimpleNamespace

from netdnsmonitor.ladder import LadderStep
from netdnsmonitor.repair_executor import make_repair_executor


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
    assert ["dscacheutil", "-flushcache"] in calls
    assert ["killall", "-HUP", "mDNSResponder"] in calls


def test_flush_dns_cache_flushes_the_cache_before_signalling_the_resolver():
    run_fn, calls = fake_run_factory(returncode=0)
    executor = make_repair_executor(run_fn=run_fn)
    executor(LadderStep("flush_dns_cache", "repair", needs_privilege=False))
    assert calls.index(["dscacheutil", "-flushcache"]) < calls.index(
        ["killall", "-HUP", "mDNSResponder"]
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
        if args[0] == "dscacheutil":
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
        if args[0] == "killall":
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
        return SimpleNamespace(
            returncode=0 if args[0] == "dscacheutil" else 1, stdout="", stderr=""
        )

    outcome = granted_executor(run_fn)(
        LadderStep("flush_dns_cache", "repair", needs_privilege=False)
    )
    assert outcome.startswith("partial")
    assert "granted sudo rule did not" in outcome
    assert "Grant elevated permissions" not in outcome


def test_renewing_a_lease_targets_the_default_route_interface():
    run_fn, calls = fake_run_factory(returncode=0)
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
    assert calls == []


def test_a_failed_renewal_reports_the_command_and_the_error():
    run_fn, _calls = fake_run_factory(returncode=1, stderr="no such interface")
    outcome = granted_executor(run_fn)(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )
    assert outcome.startswith("failed")
    assert "no such interface" in outcome


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
    # `calls[0][0] == "scutil"` also lets this step silently become
    # `scutil --dns`, i.e. a different check entirely.
    assert calls == [["scutil", "--nwi"]]


def test_check_default_route_shells_out_to_netstat():
    """Untested until now, and its output is egressed to the Anthropic API
    inside ladder_results: replacing the command with `true` kept the suite
    green while the ladder reported nothing at all.
    """
    run_fn, calls = fake_run_factory(stdout="default 192.0.2.1 UGScg en0")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_default_route", "check", needs_privilege=False))
    assert "default 192.0.2.1" in outcome
    assert calls == [["netstat", "-rn", "-f", "inet"]]


def test_check_configured_dns_servers_shells_out_to_scutil_dns():
    run_fn, calls = fake_run_factory(stdout="nameserver[0] : 192.0.2.53")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_configured_dns_servers", "check", needs_privilege=False))
    assert "192.0.2.53" in outcome
    assert calls == [["scutil", "--dns"]]


def test_check_resolver_overrides_reports_failure_instead_of_raising(tmp_path):
    """os.listdir can raise PermissionError, or FileNotFoundError via a TOCTOU
    race with the isdir check. state_machine has no per-step guard, so an
    escape aborts the incident and no report is written at all.
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
    assert outcome.startswith("failed")


def test_missing_binary_is_reported_not_raised():
    def missing_binary(args, **kwargs):
        raise FileNotFoundError(f"no such file: {args[0]}")

    executor = make_repair_executor(run_fn=missing_binary)
    outcome = executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    assert "no such file" in outcome.lower()


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
