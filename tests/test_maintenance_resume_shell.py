"""Synthetic regressions: execute only extracted functions or bounded branches."""

import re
import shlex
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def function(path, name):
    source = (ROOT / path).read_text()
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}", source, re.M | re.S)
    assert match
    return match[0] + "\n"


def run(tmp_path, code):
    return subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + code],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=5,
    )


def test_reload_rejects_stale_loaded_job(tmp_path):
    code = (
        'SERVICE=x\nPLIST=x\nLABEL=x\nlaunchctl(){ echo "$1" >> calls; return 1; }\n'
        "is_loaded(){ return 0; }\nsleep(){ :; }\nid(){ echo 1; }\ndie(){ exit 1; }\n"
    )
    assert (
        run(
            tmp_path,
            code + function("scripts/net-dns-monitor-service", "reload_agent") + "reload_agent",
        ).returncode
        != 0
    )

    assert "bootstrap" not in (tmp_path / "calls").read_text().splitlines()


@pytest.mark.parametrize("suffix", ["new", "old", "new/child", "old/child"])
def test_swap_preserves_reserved_source(tmp_path, suffix):
    source = tmp_path / ("app." + suffix)
    source.mkdir(parents=True)
    marker = source / "keep"
    marker.write_text("keep")
    code = (
        f"INSTALLED_APP={shlex.quote(str(tmp_path / 'app'))}\n"
        f"SOURCE_BUNDLE={shlex.quote(str(source))}\nEXEC_NAME=x\n"
        "ditto(){ return 1; }\ndie(){ exit 1; }\n"
    )
    result = run(
        tmp_path,
        code
        + function("scripts/net-dns-monitor-service", "replace_installed_bundle")
        + "replace_installed_bundle",
    )
    assert result.returncode != 0
    assert marker.read_text() == "keep"


def test_missing_required_module_is_fatal(tmp_path):
    source = (ROOT / "scripts/install.sh").read_text()
    branch = source[source.index("for module in app ") : source.index("# --- 5.")]
    code = 'BUNDLE="$PWD/bundle"\nwarn(){ :; }\nok(){ echo verified; }\ndie(){ exit 1; }\n'
    result = run(tmp_path, code + branch)
    assert result.returncode != 0
    assert "verified" not in result.stdout


def test_pending_launch_retains_startup_only(tmp_path):
    source = (ROOT / "scripts/start.sh").read_text()
    tail = source[
        source.index("for _ in 1 2 3 4 5 6 7 8 9 10;", source.index('open -n "$APP_BUNDLE"')) :
    ]
    (tmp_path / "start").mkdir()
    (tmp_path / "build").mkdir()
    code = (
        'START_LOCK="$PWD/start"\nBUILD_LOCK="$PWD/build"\nLOG_FILE=x\n'
        "pgrep(){ return 1; }\nsleep(){ :; }\ninfo(){ :; }\nok(){ :; }\nfail(){ exit 1; }\n"
    )
    code += function("scripts/start.sh", "release_startup_locks")
    result = run(tmp_path, code + "trap release_startup_locks EXIT\n" + tail)
    assert result.returncode != 0
    assert (tmp_path / "start").is_dir()
    assert not (tmp_path / "build").exists()


@pytest.mark.parametrize("loaded", [0, 1])
def test_nat_rollback_restores_files_and_prior_loaded_state(tmp_path, loaded):
    for name in ("old-helper", "old-plist"):
        (tmp_path / name).write_text(name)
    for name in ("helper", "plist"):
        (tmp_path / name).write_text("replacement")
    code = (
        f'WAS_LOADED={loaded}\nINSTALL_LOCK=""\nROLLBACK_ARMED=1\nHELPER_CHANGED=1\nPLIST_CHANGED=1\n'
        'TMP_PLIST=""\nHELPER_TMP=""\nOLD_HELPER_BACKUP="$PWD/old-helper"\n'
        'OLD_PLIST_BACKUP="$PWD/old-plist"\nHELPER_PATH="$PWD/helper"\nPLIST_PATH="$PWD/plist"\n'
        'launchctl(){ echo "$1" >> "$PWD/calls"; }\n'
    )
    result = run(
        tmp_path,
        code
        + function("router/scripts/install_persistent_nat.sh", "cleanup")
        + "trap cleanup EXIT\nfalse\n",
    )
    assert result.returncode != 0
    assert (tmp_path / "helper").read_text() == "old-helper"
    assert (tmp_path / "plist").read_text() == "old-plist"
    assert ("load" in (tmp_path / "calls").read_text().splitlines()) == bool(loaded)


def test_unbound_failed_copy_preserves_destination(tmp_path):
    (tmp_path / "src").write_text("complete")
    (tmp_path / "dst").write_text("working")
    code = (
        'backup(){ :; }\ncp(){ printf partial > "${@: -1}"; return 1; }\n'
        + function("unbound/install.sh", "deploy")
        + 'deploy "$PWD/src" "$PWD/dst"'
    )
    assert run(tmp_path, code).returncode != 0
    assert (tmp_path / "dst").read_text() == "working"


@pytest.mark.parametrize(
    "section,next_section", [("# 2. Apple", "# 2b."), ("# 2b.", "# 2c."), ("# 2c.", "# 3.")]
)
def test_failed_conflict_probe_never_claims_pass(tmp_path, section, next_section):
    source = (ROOT / "router/scripts/test_router.sh").read_text()
    branch = source[source.index(section) : source.index(next_section)]
    stubs = (
        "defaults(){ return 127; }\nlaunchctl(){ return 127; }\n"
        "ifconfig(){ return 127; }\npass(){ echo PASS; }\n"
        "warn(){ echo WARN; }\nfail(){ echo FAIL; }\n"
    )
    result = run(tmp_path, stubs + branch)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "WARN"


@pytest.mark.parametrize("arch,expected", [("arm64", "/opt/homebrew"), ("x86_64", "/usr/local")])
def test_prefix_fallback_matches_architecture(tmp_path, arch, expected):
    source = (ROOT / "router/scripts/test_router.sh").read_text()
    branch = source[source.index("PREFIX=") : source.index("# 1. IP Forwarding")]
    code = (
        f"uname(){{ echo {arch}; }}\nbrew(){{ return 127; }}\nwarn(){{ :; }}\nfail(){{ exit 1; }}\n"
    )
    result = run(tmp_path, code + branch + '\nprintf "%s" "$PREFIX"')
    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


def test_nat_install_lock_spans_transaction_and_cleanup():
    source = (ROOT / "router/scripts/install_persistent_nat.sh").read_text()
    assert source.index('/bin/mkdir "$LOCK_CANDIDATE"') < source.index("/usr/bin/install -d")
    cleanup = function("router/scripts/install_persistent_nat.sh", "cleanup")
    assert cleanup.index("launchctl load -w") < cleanup.index('/bin/rmdir "$INSTALL_LOCK"')
    assert 'INSTALL_LOCK="$LOCK_CANDIDATE"' in source


@pytest.mark.parametrize("nested", [False, True])
def test_swap_refuses_source_ancestor_or_installed_descendant(tmp_path, nested):
    installed = tmp_path / "app"
    installed.mkdir()
    source = installed / "child" if nested else tmp_path
    source.mkdir(exist_ok=True)
    code = (
        f"INSTALLED_APP={shlex.quote(str(installed))}\n"
        f"SOURCE_BUNDLE={shlex.quote(str(source))}\nEXEC_NAME=x\n"
        "rm(){ echo rm >> calls; }\nditto(){ echo ditto >> calls; return 1; }\n"
        "die(){ exit 1; }\n"
    )
    result = run(
        tmp_path,
        code
        + function("scripts/net-dns-monitor-service", "replace_installed_bundle")
        + "replace_installed_bundle",
    )
    assert result.returncode != 0
    assert not (tmp_path / "calls").exists()


def test_nat_cleanup_removal_failure_still_restores_and_releases(tmp_path):
    body = function("router/scripts/install_persistent_nat.sh", "cleanup")
    # Replace absolute operations before evaluating the extracted helper.
    body = (
        body.replace("/bin/rm", "fake_rm")
        .replace("/bin/mv", "fake_mv")
        .replace("/bin/rmdir", "fake_rmdir")
    )
    code = (
        "WAS_LOADED=1; INSTALL_LOCK=lock; ROLLBACK_ARMED=1; HELPER_CHANGED=1; PLIST_CHANGED=1\n"
        "TMP_PLIST=stage; HELPER_TMP=stage2; OLD_HELPER_BACKUP=oldhelper; OLD_PLIST_BACKUP=oldplist\n"
        "HELPER_PATH=helper; PLIST_PATH=plist\n"
        'fake_rm(){ echo "rm $*" >> calls; return 1; }\n'
        'fake_mv(){ echo "mv $*" >> calls; }\n'
        'fake_rmdir(){ echo "rmdir $*" >> calls; }\n'
        'launchctl(){ echo "$*" >> calls; }\n'
    )
    result = run(tmp_path, code + body + "trap cleanup EXIT\nfalse")
    assert result.returncode != 0
    calls = (tmp_path / "calls").read_text()
    assert "mv -f oldhelper helper" in calls
    assert "mv -f oldplist plist" in calls
    assert "load -w plist" in calls
    assert "rmdir lock" in calls
    assert "cleanup failed" in result.stderr


@pytest.mark.parametrize(
    "owner,mode,expected", [(0, "755", 0), (501, "755", 1), (0, "775", 1), (0, "777", 1)]
)
def test_nat_rejects_unsafe_existing_helper_ancestry(tmp_path, owner, mode, expected):
    body = function("router/scripts/install_persistent_nat.sh", "trusted_helper_directory")
    body = body.replace("/usr/bin/stat", "fake_stat")
    code = (
        f"HELPER_DIR={shlex.quote(str(tmp_path))}\n"
        f'fake_stat(){{ if [[ "$2" == %u ]]; then echo {owner}; else echo {mode}; fi; }}\n'
    )
    assert run(tmp_path, code + body + "trusted_helper_directory").returncode == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("192.168.4.50,192.168.4.150,12h", "PASS"),
        ("192.168.4.50,192.168.4.150,255.255.255.0,12h", "PASS"),
        ("192.168.4.50,192.168.5.150,255.255.255.0,12h", "FAIL"),
        ("192.168.4.50,192.168.4.150,255.0.0.0,12h", "FAIL"),
    ],
)
def test_dhcp_range_optional_netmask(tmp_path, value, expected):
    source = (ROOT / "router/scripts/test_router.sh").read_text()
    branch = source[
        source.index("if awk", source.index("# 6.")) : source.index(
            'echo "=========================================', source.index("# 6.")
        )
    ]
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/dnsmasq.conf").write_text("dhcp-range=" + value + "\n")
    result = run(tmp_path, 'PREFIX="$PWD"\npass(){ echo PASS; }\nfail(){ echo FAIL; }\n' + branch)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == expected


def test_start_copies_config_before_validation():
    source = (ROOT / "scripts/start.sh").read_text()
    assert source.index('cp "$REPO_DIR/config.yaml" "$CONFIG_FILE"') < source.index(
        'python - "$CONFIG_FILE"'
    )


def test_build_fingerprint_changes_with_variant(tmp_path):
    source = function("scripts/start.sh", "build_fingerprint")
    # Run only its pure Python heredoc, never the launcher or a build.
    python_source = source.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
    for name in ("setup.py", "requirements.txt", "constraints.txt"):
        (tmp_path / name).write_text("synthetic")
    import sys

    fingerprints = []
    for variant in ("direct", "appstore"):
        result = subprocess.run(
            [sys.executable, "-c", python_source, str(tmp_path)],
            env={"NETDNS_BUILD": variant},
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0, result.stderr
        fingerprints.append(result.stdout)
    assert fingerprints[0] != fingerprints[1]


@pytest.mark.parametrize("existing", [True, False])
def test_paired_deployment_restores_first_when_second_fails(tmp_path, existing):
    (tmp_path / "first").mkdir()
    (tmp_path / "second").mkdir()
    if existing:
        (tmp_path / "first/unbound.conf").write_text("original")
    code = (
        'UNBOUND_CONF_DIR="$PWD/first"; DNSMASQ_CONF_DIR="$PWD/second"; UNBOUND_SRC=source; DNSMASQ_SRC=other\n'
        'CURRENT=original; BACKUP=""\ntrap \'printf "state:%s\\n" "$CURRENT"\' EXIT\n'
        "mktemp(){ echo recovery; }\n"
        'cp(){ echo "copy $*" >> calls; BACKUP=$CURRENT; }\n'
        'mv(){ echo "restore $*" >> calls; CURRENT=$BACKUP; }\n'
        'rm(){ echo "remove $*" >> calls; CURRENT=absent; }\n'
        'deploy(){ echo "deploy $*" >> calls; if [[ "$1" == source ]]; then CURRENT=new; else return 1; fi; }\n'
    )
    result = run(tmp_path, code + function("unbound/install.sh", "deploy_pair") + "deploy_pair")
    assert result.returncode != 0
    calls = (tmp_path / "calls").read_text()
    assert "deploy source" in calls and "deploy other" in calls
    if existing:
        assert "restore -f recovery " in calls
        assert "state:original" in result.stdout
    else:
        assert "remove -f " in calls
        assert "state:absent" in result.stdout


def test_deploy_backup_failure_stops_before_staging(tmp_path):
    (tmp_path / "dst").write_text("working")
    code = (
        "STAMP=x\ncp(){ echo copy >> calls; return 1; }\n"
        "mktemp(){ echo stage >> calls; return 1; }\n"
        + function("unbound/install.sh", "backup")
        + function("unbound/install.sh", "deploy")
        + 'deploy source "$PWD/dst"'
    )
    assert run(tmp_path, code).returncode != 0
    assert (tmp_path / "calls").read_text().splitlines() == ["copy"]
    assert (tmp_path / "dst").read_text() == "working"
