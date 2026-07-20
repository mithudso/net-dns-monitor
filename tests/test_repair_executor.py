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
    assert any("dscacheutil" in c[0] for c in calls)
    assert any("killall" in c[0] for c in calls)


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


def test_check_interface_state_shells_out_to_scutil():
    run_fn, calls = fake_run_factory(stdout="Network reachable via Wi-Fi")
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("check_interface_state", "check", needs_privilege=False))
    assert "Network reachable via Wi-Fi" in outcome
    assert calls[0][0] == "scutil"


def test_check_resolver_overrides_reports_none_when_dir_absent():
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(
        run_fn=run_fn, resolver_dir_exists_fn=lambda path: False, resolver_listdir_fn=lambda path: []
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
    run_fn, _ = fake_run_factory()
    executor = make_repair_executor(run_fn=run_fn)
    outcome = executor(LadderStep("not_a_real_step", "check", needs_privilege=False))
    assert "unknown step" in outcome.lower()


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
