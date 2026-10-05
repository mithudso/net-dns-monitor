"""Checks on scripts/*.sh and the router/ scripts that never run the scripts.

Text-level assertions read the code with comments removed. Behavioural ones
lift a function or loop out of the script and run it under bash with stub
commands first on PATH, so no system tool (launchctl, route, sleep) is called.
"""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
START = ROOT / "scripts" / "start.sh"
INSTALL = ROOT / "scripts" / "install.sh"
SERVICE = ROOT / "scripts" / "net-dns-monitor-service"
INDEXER = ROOT / "scripts" / "install_indexer_daemon.sh"
ENABLE_NAT = ROOT / "router" / "scripts" / "enable_nat.sh"
INSTALL_NAT = ROOT / "router" / "scripts" / "install_persistent_nat.sh"
TEST_ROUTER = ROOT / "router" / "scripts" / "test_router.sh"
UNBOUND_INSTALL = ROOT / "unbound" / "install.sh"


def _code(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#"))


def _function(code, name):
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", code, re.MULTILINE | re.DOTALL)
    assert match, f"no {name}() function"
    return match.group(1)


def _stub(directory, name, body):
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


# --- start.sh ----------------------------------------------------------------


def test_start_does_not_claim_escalation_from_the_shell_environment():
    """`open -n` does not pass this shell's environment to the app."""
    code = _code(START)
    assert "escalation enabled" not in code
    assert "this shell only" in code
    assert "Keychain" in code


def test_start_runs_the_verify_heredoc_from_the_repo():
    code = _code(START)
    assert code.index('cd "$REPO_DIR"') < code.index("python - ")


def test_start_tolerates_a_failed_pip_install_but_keeps_the_import_gate():
    code = _code(START)
    pip = re.search(r"python -m pip install -q[^\n]*requirements\.txt[^\n]*\n[^\n]*", code)
    assert pip, "requirements install line missing"
    assert "--retries 1" in pip.group(0) and "--timeout 5" in pip.group(0)
    assert "||" in pip.group(0) and "continuing with the installed set" in pip.group(0)
    assert "importlib.import_module(name)" in code
    py2app = re.search(r"python -m pip install -q[^\n]*py2app[^\n]*\n[^\n]*", code)
    assert py2app and "||" in py2app.group(0)


# --- install.sh ----------------------------------------------------------------


def test_install_does_not_upgrade_pip_unpinned():
    assert "--upgrade" not in _code(INSTALL)


def test_install_only_claims_the_app_is_running_when_launchd_reports_a_pid():
    code = _code(INSTALL)
    check = code.index('launchctl print "gui/$(id -u)/$LABEL"')
    refuse = code.index("the app is not running", check)
    assert check < refuse < code.index("==> Installed.")
    assert "die " in code[refuse - 40 : refuse]


def test_every_pip_install_line_uses_the_constraints_file():
    for path in (START, INSTALL):
        # A trailing backslash joins a command to its continuation line.
        joined = _code(path).replace("\\\n", " ")
        installs = [ln for ln in joined.splitlines() if "pip install" in ln]
        assert installs, path
        for line in installs:
            assert "-c " in line and "CONSTRAINTS" in line, (path.name, line)


def test_both_installers_share_the_python_floor():
    for path in (START, INSTALL):
        assert re.search(r"^MIN_PYTHON_MINOR=13$", path.read_text(), re.MULTILINE), path.name


def test_install_hands_its_bundle_to_the_service_script():
    code = _code(INSTALL)
    assert re.search(r'NDM_SOURCE_BUNDLE="\$BUNDLE" "\$SERVICE_DST" install', code)


# --- net-dns-monitor-service ---------------------------------------------------


def test_service_refuses_an_empty_home():
    code = _code(SERVICE)
    assert code.index('[ -n "${HOME:-}" ]') < code.index('SUPPORT_DIR="$HOME')


def test_service_install_dies_on_an_explicit_bundle_that_does_not_exist():
    body = _function(_code(SERVICE), "cmd_install")
    branch = body[body.index("NDM_SOURCE_BUNDLE:-") :]
    assert branch.index("die ") < branch.index("keeping the already-installed bundle")
    assert body.index('elif [ -n "${NDM_SOURCE_BUNDLE:-}" ]') < body.index('elif [ -x "$EXEC" ]')


def test_service_update_restarts_only_when_supervised():
    body = _function(_code(SERVICE), "cmd_update")
    assert "if is_supervised; then" in body
    gate = body.index("if is_supervised; then")
    assert gate < body.index("cmd_restart") < body.index("else")


def test_service_status_says_not_installed_before_stopped_on_purpose():
    body = _function(_code(SERVICE), "cmd_status")
    assert body.index('[ ! -f "$PLIST" ]') < body.index("stopped on purpose")
    assert "not installed" in body[: body.index("stopped on purpose")]


def test_service_stop_waits_for_the_process_and_reports_a_survivor():
    body = _function(_code(SERVICE), "cmd_stop")
    assert body.index("launchctl kill") < body.index("while ") < body.index("Supervision disabled.")
    assert "still running" in body


def test_service_uninstall_checks_the_agent_is_gone_before_removing_the_plist():
    body = _function(_code(SERVICE), "cmd_uninstall")
    assert body.index("bootout") < body.index("is_loaded") < body.index('rm -f "$PLIST"')


def test_service_plist_is_linted_before_it_replaces_the_working_one():
    body = _function(_code(SERVICE), "write_plist")
    assert 'cat >"$staged"' in body
    assert body.index('plutil -lint "$staged"') < body.index('mv -f "$staged" "$PLIST"')
    assert 'cat >"$PLIST"' not in body


def _running_pid(tmp_path, print_output, calls):
    code = _code(SERVICE)
    fn = "running_pid() {\n" + _function(code, "running_pid") + "}\n"
    _stub(
        tmp_path,
        "launchctl",
        f'echo "$@" >> "{calls}"\n'
        "if [ \"$1\" = print ]; then cat <<'OUT'\n" + print_output + "\nOUT\nexit 0\nfi\nexit 1",
    )
    script = "SERVICE=gui/501/com.example\n" + fn + "running_pid"
    return subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )


def test_running_pid_reads_the_pid_from_launchctl_print_of_the_service(tmp_path):
    calls = tmp_path / "calls"
    out = "gui/501/com.example = {\n\tstate = running\n\tpid = 4242\n\tlast exit code = 0\n}"
    result = _running_pid(tmp_path, out, calls)
    assert result.stdout.strip() == "4242", result.stderr
    assert calls.read_text().split() == ["print", "gui/501/com.example"]


def test_running_pid_is_empty_when_the_job_has_no_pid(tmp_path):
    out = "gui/501/com.example = {\n\tstate = waiting\n\tlast exit code = 0\n}"
    result = _running_pid(tmp_path, out, tmp_path / "calls")
    assert result.stdout.strip() == ""


# --- router/scripts/enable_nat.sh ----------------------------------------------


def test_wan_wait_loop_survives_a_missing_default_route(tmp_path):
    """`route` exits 1 with no default route; under pipefail the unguarded
    pipeline killed the script on the first pass instead of waiting."""
    loop = re.search(r'^WAN="".*?^done$', ENABLE_NAT.read_text(), re.S | re.M)
    assert loop
    _stub(tmp_path, "route", "exit 1")
    _stub(tmp_path, "sleep", f'echo slept >> "{tmp_path}/sleep.log"')
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + loop.group(0) + "\necho FELL_THROUGH"],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert "FELL_THROUGH" in result.stdout, (result.returncode, result.stderr)
    assert len((tmp_path / "sleep.log").read_text().split()) == 30


def test_wan_wait_loop_returns_the_interface_when_a_route_exists(tmp_path):
    loop = re.search(r'^WAN="".*?^done$', ENABLE_NAT.read_text(), re.S | re.M).group(0)
    _stub(tmp_path, "route", "printf '   gateway: 10.0.0.1\\n  interface: en7\\n'")
    _stub(tmp_path, "sleep", "exit 0")
    result = subprocess.run(
        ["bash", "-c", "set -euo pipefail\n" + loop + '\necho "WAN=$WAN"'],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert "WAN=en7" in result.stdout


def test_enable_nat_keeps_the_first_bootpd_backup():
    code = _code(ENABLE_NAT)
    guard = code.index("[[ ! -e /etc/bootpd.plist.bak ]]")
    assert guard < code.index("mv /etc/bootpd.plist /etc/bootpd.plist.bak")


# --- router/scripts/install_persistent_nat.sh ----------------------------------


def test_nat_installer_refuses_while_the_app_router_is_live():
    code = _code(INSTALL_NAT)
    pf = code.index("com.apple/netdnsmonitor_nat")
    bootpd = code.index("launchctl print system/com.apple.bootpd")
    first_write = code.index("/usr/bin/install -d")
    assert pf < first_write and bootpd < first_write
    assert "exit 1" in code[pf:first_write]


def test_nat_installer_installs_the_helper_atomically():
    code = _code(INSTALL_NAT)
    assert 'mktemp "$HELPER_DIR/' in code
    assert code.index('"$SOURCE_PATH" "$HELPER_TMP"') < code.index(
        'mv -f "$HELPER_TMP" "$HELPER_PATH"'
    )
    assert (
        re.search(r'install -o root -g wheel -m 755 "\$SOURCE_PATH" "\$HELPER_PATH"', code) is None
    )


def test_nat_installer_rolls_back_a_failure_after_unloading_the_old_daemon():
    code = _code(INSTALL_NAT)
    assert "trap cleanup EXIT" in code
    cleanup = _function(code, "cleanup")
    assert "ROLLBACK_ARMED" in cleanup and 'launchctl load -w "$PLIST_PATH"' in cleanup
    backup = code.index('cp -p "$PLIST_PATH" "$OLD_PLIST_BACKUP"')
    assert backup < code.index('launchctl unload -w "$PLIST_PATH"') < code.index("ROLLBACK_ARMED=1")
    assert code.index("ROLLBACK_ARMED=1") < code.index(
        'launchctl load -w "$PLIST_PATH"\nROLLBACK_ARMED=0'
    )


# --- unbound/install.sh, test_router.sh ------------------------------------------


def test_unbound_install_verifies_unbound_on_port_53_before_the_banner():
    code = _code(UNBOUND_INSTALL)
    verify = code.index("lsof -nP -iUDP:53")
    banner = code.index("ARCHITECTURE DEPLOYED")
    assert verify < banner and "exit 1" in code[verify:banner]
    assert "grep -q unbound" in code[verify:banner]


def test_diagnostics_nat_check_matches_the_current_upstream():
    code = _code(TEST_ROUTER)
    assert "route -n get default" in code
    assert 'grep -q "nat on $WAN "' in code


def test_diagnostics_exit_nonzero_when_a_check_failed():
    code = _code(TEST_ROUTER)
    assert "FAILURES=$((FAILURES + 1))" in code
    tail = code[code.index('if [ "$FAILURES" -gt 0 ]') :]
    assert "exit 1" in tail


def test_diagnostics_warn_when_dig_is_missing():
    code = _code(TEST_ROUTER)
    block = code[code.index("command -v dig") :]
    first = re.split(r"\n(?:elif|else)\b", block, maxsplit=1)[0]
    assert "warn " in first and "fail " not in first


# --- install_indexer_daemon.sh ---------------------------------------------------


def test_indexer_installer_refuses_a_missing_venv_python():
    code = _code(INDEXER)
    check = code.index('[ -x "$REPO_ROOT/.venv/bin/python3" ]')
    assert check < code.index("cat <<EOF")
    assert "exit 1" in code[check : code.index("mkdir -p")]


def test_indexer_installer_lints_the_plist_before_replacing_the_old_one():
    code = _code(INDEXER)
    assert code.index('plutil -lint "$STAGED_PLIST"') < code.index(
        'mv -f "$STAGED_PLIST" "$PLIST_PATH"'
    )
    assert code.index('mv -f "$STAGED_PLIST"') < code.index("launchctl bootstrap")


def test_the_stale_router_config_duplicate_is_gone():
    assert not (ROOT / "router" / "tests" / "test_configs.py").exists()


def test_install_pid_poll_survives_launchctl_failing_under_pipefail(tmp_path):
    # `launchctl print` exits 113 for a job that is not loaded. Under
    # `set -euo pipefail` that failed the assignment and aborted the script
    # before the "installed but not running" message could print.
    text = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if ln.strip().startswith('INSTALL_PID="$('))
    stub = tmp_path / "launchctl"
    stub.write_text("#!/bin/sh\nexit 113\n")
    stub.chmod(0o755)
    script = f'set -euo pipefail\nLABEL=x\n{line.strip()}\necho "reached:[$INSTALL_PID]"\n'
    result = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{tmp_path}:/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert "reached:[]" in result.stdout, (result.returncode, result.stderr)
