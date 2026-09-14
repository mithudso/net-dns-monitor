"""String and plist checks on the router/ shell scripts.

None of these scripts is executed: they reconfigure pf, launchd and the network
as root. The LaunchDaemon plist is lifted out of its heredoc and parsed.
"""

import plistlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "router" / "scripts"
INSTALL = SCRIPTS / "install_persistent_nat.sh"
TEST_ROUTER = SCRIPTS / "test_router.sh"
UNBOUND_INSTALL = ROOT / "unbound" / "install.sh"


def _code_lines(path):
    """Script lines with comments removed, so a comment cannot satisfy a check."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.lstrip()
        if stripped.startswith("#!") or stripped.startswith("#"):
            continue
        out.append(raw)
    return "\n".join(out)


def _shell_var(text, name):
    match = re.search(rf'^{name}="([^"]*)"', text, re.MULTILINE)
    assert match, f"{name} is not assigned"
    value = match.group(1)
    return re.sub(r"\$\{(\w+)\}", lambda m: _shell_var(text, m.group(1)), value)


def _daemon_plist():
    text = INSTALL.read_text(encoding="utf-8")
    match = re.search(r"<<EOF[^\n]*\n(.*?)\nEOF\n", text, re.DOTALL)
    assert match, "no heredoc plist found"
    body = re.sub(r"\$\{(\w+)\}", lambda m: _shell_var(text, m.group(1)), match.group(1))
    return plistlib.loads(body.encode("utf-8"))


def test_the_daemon_runs_a_root_owned_copy_not_the_checkout():
    program = _daemon_plist()["ProgramArguments"]
    assert program == ["/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh"]
    code = _code_lines(INSTALL)
    assert "install -o root -g wheel -m 755" in code
    assert "SCRIPT_PATH}" not in code


def test_the_install_script_stages_nothing_in_tmp():
    assert "/tmp/" not in INSTALL.read_text(encoding="utf-8")
    assert "mktemp /Library/LaunchDaemons/" in _code_lines(INSTALL)


def test_the_daemon_reruns_every_minute_and_logs():
    plist = _daemon_plist()
    assert plist["Label"] == "com.custom.router.nat"
    assert plist["StartInterval"] == 60
    assert plist["RunAtLoad"] is True
    assert plist["StandardOutPath"] == "/var/log/com.custom.router.nat.out.log"
    assert plist["StandardErrorPath"] == "/var/log/com.custom.router.nat.err.log"


def test_the_dns_check_does_not_pass_on_a_dig_timeout():
    code = _code_lines(TEST_ROUTER)
    assert "+tries=1" in code
    assert "grep -q '^;'" in code
    assert "over DoT" not in code


def test_a_failed_sudo_is_not_reported_as_pf_disabled():
    code = _code_lines(TEST_ROUTER)
    assert "sudo -n pfctl -s info" in code
    assert "PF status not checked" in code
    assert re.search(r"(?<!-n )sudo pfctl", code) is None


def test_diagnostics_do_not_hardcode_the_homebrew_prefix():
    code = _code_lines(TEST_ROUTER)
    assert "brew --prefix" in code
    assert code.count("/opt/homebrew") <= 1  # the single fallback


def test_bridge100_is_a_warning_not_a_failure():
    code = _code_lines(TEST_ROUTER)
    bridge = re.split(r"\bfi\b", code[code.index("ifconfig bridge100") :], maxsplit=1)[0]
    assert "warn " in bridge and "fail " not in bridge


def test_unbound_install_validates_sources_before_copying_and_backs_up():
    code = _code_lines(UNBOUND_INSTALL)
    assert "set -euo pipefail" in code
    check = code.index('unbound-checkconf "$UNBOUND_SRC"')
    test = code.index('dnsmasq --test -C "$DNSMASQ_SRC"')
    first_copy = code.index('cp "$UNBOUND_SRC"')
    assert check < first_copy and test < first_copy
    assert code.index('backup "$UNBOUND_CONF_DIR/unbound.conf"') < first_copy


def test_unbound_install_only_claims_success_after_dnsmasq_holds_udp_67():
    code = _code_lines(UNBOUND_INSTALL)
    verify = code.index("lsof -nP -iUDP:67")
    assert verify < code.index("ARCHITECTURE DEPLOYED")
    assert "exit 1" in code[verify : code.index("ARCHITECTURE DEPLOYED")]
