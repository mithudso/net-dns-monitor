"""Synthetic regressions for the parent-owned maintenance tooling iteration.

No complete installer, App Store CLI, daemon, GUI, model or probe runs here.
Shell excerpts include only the selected function/condition and all OS-facing
operations in an excerpt are replaced before bash runs.
"""

import errno
import importlib.util
import json
import os
import plistlib
import re
import shlex
import subprocess
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(SCRIPTS / "appstore"))


def load(relative):
    spec = importlib.util.spec_from_file_location(Path(relative).stem, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


checker = load("scripts/check_docs.py")
dossier = load("scripts/generate_static_dossier.py")
probe = load("scripts/appstore/sandbox_probe.py")
recorder = load("scripts/appstore/record_demo.py")
build = load("scripts/appstore/build_appstore.py")
shoot = load("scripts/appstore/shoot_screenshots.py")
indexer = load("scripts/semantic_indexer.py")
watcher = load("scripts/watch_and_index.py")
rotator = load("scripts/rotate_workflow_logs.py")


def function(relative, name):
    source = (ROOT / relative).read_text()
    match = re.search(rf"^{name}\(\) \{{\n(.*?)^\}}", source, re.M | re.S)
    assert match, name
    return f"{name}() {{\n{match[1]}}}\n"


def shell(code, *, cwd, env=None):
    return subprocess.run(
        ["/bin/bash", "-c", "set -euo pipefail\n" + code],
        cwd=cwd,
        env={"PATH": "/usr/bin:/bin", **(env or {})},
        capture_output=True,
        text=True,
        timeout=5,
    )


@pytest.mark.parametrize("artifact", ["index", "manifest"])
def test_json_null_is_a_validation_error(tmp_path, artifact):
    docs = tmp_path / "docs"
    docs.mkdir()
    index = docs / "high_signal_file_index.json"
    index.write_text("null" if artifact == "index" else '{"files": []}')
    if artifact == "manifest":
        llms = docs / "llms"
        llms.mkdir()
        (llms / "filemap.json").write_text("[]")
        (llms / "manifest.json").write_text("null")
    assert any("expected an object" in e for e in checker.check_paths(tmp_path))


@pytest.mark.parametrize(
    "filename,missing",
    [("notes\tdraft.py", False), ("notes\rdraft.py", False), ("déjà.py", False), ("gone.py", True)],
)
def test_dossier_preserves_literal_git_paths_and_tracked_deletions(
    tmp_path, monkeypatch, filename, missing
):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs/high_signal_file_index.json").write_text('{"files": []}')
    if not missing:
        (tmp_path / filename).write_text("x")
    monkeypatch.setattr(dossier, "ROOT", tmp_path)
    monkeypatch.setattr(dossier, "OUT", tmp_path / "docs/llms")
    monkeypatch.setattr(dossier, "ADDITIONS", ())

    def git_output(argv, **kwargs):
        assert argv[0] == "git"
        if argv[1] == "ls-files":
            if "--ignored" in argv:
                return b""
            if "-z" in argv:
                return os.fsencode(filename + "\0")
            # Git's ordinary display format quotes and escapes these names.
            return json.dumps(filename) + "\n"
        if argv[1] == "rev-parse":
            return "abcdef\n"
        return ""

    monkeypatch.setattr(dossier.subprocess, "check_output", git_output)
    dossier.main()
    cards = json.loads((dossier.OUT / "filemap.json").read_text())
    assert [card["path"] for card in cards] == [filename]
    assert cards[0]["provenance"] == ("[src: git]" if missing else f"[src: {filename}#L1]")


def test_probe_nonzero_ping_is_unknown(monkeypatch):
    monkeypatch.setattr(
        probe.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a, 2, "", "timeout")
    )
    result = probe.run_command(["synthetic-ping"])
    assert result["ok"] is None
    assert result["returncode"] == 2


def test_container_probe_preserves_existing_test_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    folder = tmp_path / "Library/Application Support/net-dns-monitor"
    folder.mkdir(parents=True)
    old = folder / "sandbox-probe-write-test.txt"
    old.write_text("keep")
    assert probe.container_write()["ok"] is True
    assert old.read_text() == "keep"
    assert list(folder.iterdir()) == [old]


@pytest.mark.parametrize(
    "child", ["config.yaml", "app-data", "AppIcon.icns", "ai-consent.json", "01-dashboard.png"]
)
def test_screenshot_isolation_refuses_symlinked_destinations(tmp_path, child):
    outside = tmp_path / "owner"
    outside.mkdir()
    run = tmp_path / "run"
    run.mkdir()
    target = outside / child
    if child == "app-data":
        target.mkdir()
    else:
        target.write_text("keep")
    (run / child).symlink_to(target, target_is_directory=child == "app-data")
    with pytest.raises((ValueError, SystemExit), match="symlink|isolat|unsafe"):
        shoot.write_isolated_config(run)
    if child != "app-data":
        assert target.read_text() == "keep"
    assert not (outside / "history.jsonl").exists()


def test_screenshot_heartbeat_timeout_never_opens_or_diagnoses(tmp_path):
    calls = []
    app = types.SimpleNamespace(ping_stats={}, open_dashboard=lambda: calls.append("open"))
    failures = []
    clock = [0.0]
    driver = shoot.Driver(app, tmp_path, {}, now=lambda: clock[0], fail=failures.append)
    clock[0] = shoot.WARMUP_DEADLINE + 1
    driver.tick()
    assert failures == ["phase 'warm-up' raised"]
    assert calls == []


@pytest.mark.parametrize("failure", ["timeout", "signal"])
def test_recorder_unconfirmed_shutdown_keeps_pid_and_never_transcodes(
    tmp_path, monkeypatch, failure
):
    pid = tmp_path / "pid"
    pid.write_text("123")
    raw = tmp_path / "raw.mov"
    raw.write_bytes(b"not-yet-final")
    monkeypatch.setattr(recorder, "PID_FILE", pid)
    monkeypatch.setattr(recorder, "RAW_VIDEO", raw)
    monkeypatch.setattr(recorder, "is_screencapture", lambda pid: True)
    clock = iter([0, 61])
    monkeypatch.setattr(recorder.time, "monotonic", lambda: next(clock))

    def kill(*args):
        if failure == "signal":
            raise OSError(errno.EPERM, "synthetic")

    monkeypatch.setattr(recorder.os, "kill", kill)
    processed = []
    monkeypatch.setattr(recorder, "process", lambda: processed.append(True))
    with pytest.raises(SystemExit) as exc:
        recorder.stop()
    assert exc.value.code == 1
    assert pid.read_text() == "123"
    assert processed == []


def test_recorder_reserves_pid_before_spawning_and_rejects_overlap(tmp_path, monkeypatch):
    monkeypatch.setattr(recorder, "DEMO_DIR", tmp_path)
    monkeypatch.setattr(recorder, "PID_FILE", tmp_path / "pid")
    monkeypatch.setattr(recorder, "RAW_VIDEO", tmp_path / "raw.mov")
    monkeypatch.setattr(recorder.time, "sleep", lambda _: None)
    launches = []

    def spawn(*a, **k):
        assert recorder.PID_FILE.exists(), "reservation must precede capture side effects"
        if not launches:
            launches.append(True)
            with pytest.raises(SystemExit):
                recorder.start()
        return types.SimpleNamespace(pid=123, poll=lambda: None)

    monkeypatch.setattr(recorder.subprocess, "Popen", spawn)
    recorder.start()
    assert launches == [True]
    assert recorder.PID_FILE.read_text() == "123"


@pytest.mark.parametrize(
    "name",
    [
        "@loader_path/missing.dylib",
        "@loader_path/../../../outside.dylib",
        "@executable_path/missing.dylib",
    ],
)
def test_linkage_rejects_missing_or_escaped_direct_dependencies(tmp_path, monkeypatch, name):
    app = tmp_path / "X.app"
    binary = app / "Contents/MacOS/python"
    binary.parent.mkdir(parents=True)
    (tmp_path / "outside.dylib").write_text("x")

    def capture(argv):
        return (
            "binary:\n\t" + name + " (compatibility version 1.0)\n" if "-L" in argv else "binary:\n"
        )

    monkeypatch.setattr(build, "capture", capture)
    assert build.check_linkage(app, [binary]), name


def test_rpath_cannot_follow_a_symlink_outside_bundle(tmp_path):
    app = tmp_path / "X.app"
    binary = app / "Contents/MacOS/python"
    binary.parent.mkdir(parents=True)
    outside = tmp_path / "outside.dylib"
    outside.write_text("x")
    (binary.parent / "linked.dylib").symlink_to(outside)
    assert (
        build.resolve_rpath_library(binary, "@rpath/linked.dylib", ["@loader_path/"], app) is None
    )


def test_cancelled_debounce_callback_does_not_consume_replacement():
    timers, handled = [], []

    class Timer:
        def __init__(self, delay, fn, args):
            self.fn, self.args = fn, args
            timers.append(self)

        def start(self):
            pass

        def cancel(self):
            pass

    coalescer = watcher.EventCoalescer(lambda *e: handled.append(e), timer_factory=Timer)
    coalescer.add("created", "/r/a.py", "", False)
    coalescer.add("modified", "/r/a.py", "", False)
    timers[0].fn(*timers[0].args)
    assert handled == []
    timers[1].fn(*timers[1].args)
    assert handled == [("modified", "/r/a.py", "", False)]


def test_unsupported_event_does_not_erase_pending_modification():
    timers, handled = [], []

    class Timer:
        def __init__(self, delay, fn, args):
            self.fn, self.args = fn, args
            timers.append(self)

        def start(self):
            pass

        def cancel(self):
            pass

    coalescer = watcher.EventCoalescer(lambda *e: handled.append(e), timer_factory=Timer)
    coalescer.add("modified", "/r/a.py", "", False)
    coalescer.add("closed", "/r/a.py", "", False)
    timers[-1].fn(*timers[-1].args)
    assert handled == [("modified", "/r/a.py", "", False)]


def test_bootstrap_propagates_creation_failure_without_success(tmp_path):
    # Execute only the filesystem scaffold: no daemon, app or installer exists.
    (tmp_path / ".github").write_text("conflict")
    # Invoke a separate shell to test the scaffold's own errexit setting.
    result = subprocess.run(
        ["/bin/bash", str(ROOT / "bootstrap_repo.sh")],
        cwd=tmp_path,
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode != 0
    assert "Bootstrap complete" not in result.stdout


@pytest.mark.parametrize(
    "line,valid",
    [
        ("# dhcp-range=192.168.4.50,192.168.4.150,12h", False),
        ("dhcp-range=192.168.4.500,192.168.4.150,12h", False),
        ("dhcp-range=192.168.4.50,192.168.5.150,12h", False),
        ("dhcp-range=192.168.4.50,192.168.4.49,12h", False),
        ("dhcp-range=192.168.4.50,192.168.4.999,12h", False),
        ("dhcp-range=192.168.4.50,192.168.4.200,48h", True),
        ("  dhcp-range=192.168.4.50,192.168.4.150,12h # LAN", True),
    ],
)
def test_dhcp_diagnostic_checks_active_range_fields(tmp_path, line, valid):
    cfg = tmp_path / "etc/dnsmasq.conf"
    cfg.parent.mkdir()
    cfg.write_text(line + "\n")
    source = (ROOT / "router/scripts/test_router.sh").read_text()
    branch = source.split("# 6. DHCP Configuration Check\n", 1)[1].split('\necho "=', 1)[0]
    result = shell(
        'PREFIX="$PWD"\npass() { echo PASS; }\nfail() { echo FAIL; }\n' + branch, cwd=tmp_path
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == ("PASS" if valid else "FAIL")


def test_rotator_refuses_a_journal_changed_after_read(tmp_path, monkeypatch):
    journal = tmp_path / "memory.md"
    initial = "# journal\n" + "".join(f"## v{i}\nbody {i}\n" for i in range(8))
    journal.write_text(initial)
    original = rotator._write_atomic

    def append_during_archive(path, text, **kwargs):
        original(path, text, **kwargs)
        if path != journal:
            with journal.open("a") as handle:
                handle.write("## v8\nconcurrent entry\n")

    monkeypatch.setattr(rotator, "_write_atomic", append_during_archive)
    result = rotator.rotate(journal, tmp_path / "archive", max_bytes=1, keep=3)
    assert "refused" in result
    assert journal.read_text() == initial + "## v8\nconcurrent entry\n"


def test_rotator_persists_archive_rename_before_journal_replace(tmp_path, monkeypatch):
    journal = tmp_path / "memory.md"
    journal.write_text("".join(f"## v{i}\nbody\n" for i in range(8)))
    events = []
    replace, fsync = rotator.os.replace, rotator.os.fsync

    def replace_record(src, dst):
        events.append(("replace", Path(dst)))
        replace(src, dst)

    def sync(fd):
        import stat

        if stat.S_ISDIR(os.fstat(fd).st_mode):
            events.append(("directory-sync", None))
        fsync(fd)

    monkeypatch.setattr(rotator.os, "replace", replace_record)
    monkeypatch.setattr(rotator.os, "fsync", sync)
    rotator.rotate(journal, tmp_path / "archive", max_bytes=1, keep=3)
    a = events.index(("replace", tmp_path / "archive/memory-archive.md"))
    j = events.index(("replace", journal))
    assert any(kind == "directory-sync" for kind, _ in events[a + 1 : j])
    assert events[j + 1 :] == [("directory-sync", None)]


def test_index_writers_cannot_delete_newer_chunks(tmp_path):
    import threading

    source = tmp_path / "doc.md"
    source.write_text("short")
    first_at_cleanup, release_first, second_upsert = (
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    documents, failures = {}, []

    class Collection:
        def upsert(self, documents: list, metadatas, ids):
            for key, text in zip(ids, documents, strict=True):
                stored[key] = text
            if threading.current_thread().name == "newer":
                second_upsert.set()

        def get(self, **kwargs):
            if threading.current_thread().name == "older":
                first_at_cleanup.set()
                assert release_first.wait(2)
            return {"ids": list(stored)}

        def delete(self, ids):
            for key in ids:
                stored.pop(key, None)

    stored = documents
    collection = Collection()

    def run():
        try:
            indexer.index_file(str(source), collection, root=str(tmp_path))
        except Exception as exc:  # noqa: BLE001 - surface worker failures to the test
            failures.append(exc)

    old = threading.Thread(target=run, name="older")
    new = threading.Thread(target=run, name="newer")
    old.start()
    try:
        assert first_at_cleanup.wait(2)
        source.write_text("x" * 1100)
        new.start()
        second_upsert.wait(0.1)
    finally:
        release_first.set()
        old.join(3)
        if new.ident is not None:
            new.join(3)
    assert not old.is_alive() and not new.is_alive()
    assert failures == []
    assert documents == {"doc.md_chunk_0": "x" * 1000, "doc.md_chunk_1": "x" * 300}


def test_appstore_mode_lock_rejects_overlap_and_releases(tmp_path, monkeypatch):
    monkeypatch.setattr(build, "BUILD_ROOT", tmp_path)
    with build.build_lock("adhoc"):
        artifact = tmp_path / "adhoc/output"
        artifact.parent.mkdir()
        artifact.write_text("in progress")
        with pytest.raises(SystemExit, match="another adhoc build"), build.build_lock("adhoc"):
            pytest.fail("second owner entered")
        assert artifact.read_text() == "in progress"
        with build.build_lock("release"):
            pass
    with build.build_lock("adhoc"):
        assert artifact.read_text() == "in progress"


def test_install_config_heredoc_treats_paths_as_arguments(tmp_path):
    source = (ROOT / "scripts/install.sh").read_text()
    match = re.search(r'^"\$PY" - .*?<<.*?PYEOF.*?\n(.*?)\nPYEOF', source, re.M | re.S)
    assert match
    code = match[1]
    # Inject only the config import; no real config loader or installer runs.
    fake = types.ModuleType("netdnsmonitor.config")
    seen = []
    fake.load_config = seen.append
    previous = sys.modules.get("netdnsmonitor.config")
    argv = sys.argv
    path = str(tmp_path / 'a";print("PATH_CODE_EXECUTED");#')
    try:
        sys.modules["netdnsmonitor.config"] = fake
        sys.argv = ["-", path, path + "/config.yaml"]
        exec(compile(code, "installer-heredoc", "exec"), {})
    finally:
        sys.argv = argv
        if previous is not None:
            sys.modules["netdnsmonitor.config"] = previous
        else:
            sys.modules.pop("netdnsmonitor.config", None)
        if path in sys.path:
            sys.path.remove(path)
    assert seen == [path + "/config.yaml"]


def test_service_plist_roundtrips_special_paths(tmp_path):
    # Only write_plist and xml_escape run. plutil is replaced; all writes and
    # normal file utilities target this test's scratch directory.
    plist = tmp_path / "agent.plist"
    values = [str(tmp_path / 'A&B<"x">/app'), str(tmp_path / "A&B/flag"), str(tmp_path / "A&B/log")]
    code = (
        "LABEL=com.synthetic\nTHROTTLE_SECONDS=15\n"
        + "\n".join(
            f"{name}={shlex.quote(value)}"
            for name, value in zip(["EXEC", "FLAG", "APP_LOG"], values, strict=True)
        )
        + '\nPLIST="$PWD/agent.plist"\nplutil() { :; }\ndie() { echo "$*" >&2; exit 1; }\n'
    )
    source = (ROOT / "scripts/net-dns-monitor-service").read_text()
    if "xml_escape() {" in source:
        code += function("scripts/net-dns-monitor-service", "xml_escape")
    code += function("scripts/net-dns-monitor-service", "write_plist") + "write_plist\n"
    result = shell(code, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    parsed = plistlib.loads(plist.read_bytes())
    assert parsed["ProgramArguments"] == [values[0]]
    assert parsed["KeepAlive"]["PathState"] == {values[1]: True}
    assert parsed["StandardOutPath"] == parsed["StandardErrorPath"] == values[2]


@pytest.mark.parametrize(
    "process,port,line,valid",
    [
        ("unbound", 53, "unbound 1 root 6u IPv4 0t0 UDP 127.0.0.1:53", False),
        ("unbound", 53, "other 1 root 6u IPv4 0t0 UDP 192.168.4.1:53", False),
        ("unbound", 53, "unbound 1 root 6u IPv4 0t0 UDP 192.168.4.1:53->1.1.1.1:53", False),
        ("unbound", 53, "unbound 1 root 6u IPv4 0t0 UDP 192.168.4.1:53", True),
        ("dnsmasq", 67, "dnsmasq 1 root 6u IPv4 0t0 UDP *:67", True),
    ],
)
def test_retired_installer_readiness_requires_lan_listener(tmp_path, process, port, line, valid):
    code = function("unbound/install.sh", "has_lan_udp_listener")
    code += f"has_lan_udp_listener {process} {port} <<<'{line}'\n"
    result = shell(code, cwd=tmp_path)
    assert (result.returncode == 0) is valid, result.stderr


def test_indexer_plist_roundtrips_xml_metacharacters(tmp_path, monkeypatch):
    source = (ROOT / "scripts/install_indexer_daemon.sh").read_text()
    values = [
        str(tmp_path / "agent.plist"),
        "com.synthetic",
        str(tmp_path / 'A&B<"x">'),
        str(tmp_path / "A&B/scripts"),
        str(tmp_path / "A&B/logs"),
    ]
    match = re.search(r"<<'PYEOF'\n(.*?)\nPYEOF", source, re.S)
    if match:
        monkeypatch.setattr(sys, "argv", ["-", *values])
        exec(compile(match[1], "indexer-plist-heredoc", "exec"), {})
    else:
        # Reproduce the old unescaped heredoc, without running its installer.
        match = re.search(r"<<EOF[^\n]*\n(.*?)\nEOF", source, re.S)
        assert match
        body = match[1]
        for key, value in zip(
            ["LABEL", "REPO_ROOT", "SCRIPT_DIR", "LOG_DIR"], values[1:], strict=True
        ):
            body = body.replace("${" + key + "}", value)
        Path(values[0]).write_text(body)
    parsed = plistlib.loads(Path(values[0]).read_bytes())
    assert parsed["ProgramArguments"] == [
        values[2] + "/.venv/bin/python3",
        values[3] + "/watch_and_index.py",
        values[2],
    ]
    assert parsed["StandardOutPath"] == values[4] + "/semantic_indexer.log"


def test_indexer_installer_owns_unique_staging_inode(tmp_path):
    source = (ROOT / "scripts/install_indexer_daemon.sh").read_text()
    assignment = next(
        line
        for line in source.splitlines()
        if line.startswith("STAGED_PLIST=") and line != 'STAGED_PLIST=""'
    )
    code = 'PLIST_PATH="$PWD/agent.plist"\n' + assignment + '\nprintf "%s" "$STAGED_PLIST"'
    first = shell(code, cwd=tmp_path)
    second = shell(code, cwd=tmp_path)
    assert first.returncode == second.returncode == 0
    assert first.stdout != second.stdout
    assert Path(first.stdout).is_file() and Path(second.stdout).is_file()


@pytest.mark.parametrize("fail_restore", [False, True])
def test_nat_rollback_restores_helper_and_preserves_failed_backup(tmp_path, fail_restore):
    # Every command in the extracted cleanup is replaced. The replacement
    # movers/removers validate all operands under scratch before using tools.
    for name, text in [
        ("helper", "new helper"),
        ("helper.old", "old helper"),
        ("plist", "new plist"),
        ("plist.old", "old plist"),
    ]:
        (tmp_path / name).write_text(text)
    cleanup = function("router/scripts/install_persistent_nat.sh", "cleanup")
    cleanup = cleanup.replace("/bin/rm", "safe_rm").replace("/bin/mv", "safe_mv")
    prefix = """
TMP_PLIST=""; HELPER_TMP=""; ROLLBACK_ARMED=1; HELPER_CHANGED=1; PLIST_CHANGED=1
PLIST_PATH="$PWD/plist"; HELPER_PATH="$PWD/helper"
OLD_PLIST_BACKUP="$PWD/plist.old"; OLD_HELPER_BACKUP="$PWD/helper.old"
launchctl() { printf '%s\\n' "$*" >> "$PWD/launch.log"; }
safe_rm() {
    local arg
    for arg in "$@"; do
        case "$arg" in -f|"") continue;; "$PWD"/*) /bin/rm -f "$arg";; *) exit 90;; esac
    done
}
safe_mv() {
    [[ "$1" == "-f" ]] && shift
    [[ "$1" == "$PWD/"* && "$2" == "$PWD/"* ]] || exit 91
    if [[ "$FAIL_RESTORE" == 1 && "$1" == "$OLD_PLIST_BACKUP" ]]; then return 1; fi
    /bin/mv "$1" "$2"
}
"""
    code = (
        prefix
        + cleanup
        + "set +e\nfalse\ncleanup\nresult=$?\nprintf 'cleanup-rc:%s\\n' \"$result\"\n"
    )
    result = shell(code, cwd=tmp_path, env={"FAIL_RESTORE": "1" if fail_restore else "0"})
    assert "cleanup-rc:1" in result.stdout
    assert (tmp_path / "helper").read_text() == "old helper"
    if fail_restore:
        assert (tmp_path / "plist.old").read_text() == "old plist"
        assert str(tmp_path / "plist.old") in result.stderr
        assert "load -w " not in (tmp_path / "launch.log").read_text().replace("unload -w ", "")
    else:
        assert (tmp_path / "plist").read_text() == "old plist"
        assert "load -w " + str(tmp_path / "plist") in (tmp_path / "launch.log").read_text()


def test_start_fingerprint_detects_preserved_timestamps_and_deletions(tmp_path):
    (tmp_path / "netdnsmonitor").mkdir()
    source = tmp_path / "netdnsmonitor/app.py"
    source.write_text("old")
    for name in ["setup.py", "requirements.txt", "constraints.txt"]:
        (tmp_path / name).write_text("input")
    fingerprint = function("scripts/start.sh", "build_fingerprint")
    fingerprint = fingerprint.replace(
        'python - "$REPO_DIR"', shlex.quote(sys.executable) + ' -B - "$REPO_DIR"'
    )
    code = 'REPO_DIR="$PWD"\n' + fingerprint + "build_fingerprint\n"

    def digest():
        result = shell(code, cwd=tmp_path)
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()

    before = digest()
    timestamps = source.stat()
    source.write_text("new")
    os.utime(source, ns=(timestamps.st_atime_ns, timestamps.st_mtime_ns))
    after = digest()
    assert before != after
    source.unlink()
    assert digest() not in (before, after)


def test_service_lock_does_not_release_another_owners_reservation(tmp_path):
    lock = tmp_path / "service-install.lock"
    lock.mkdir()
    (lock / "owner-marker").write_text("keep")
    prefix = 'SUPPORT_DIR="$PWD"\ndie() { echo "$*" >&2; exit 1; }\n'
    code = (
        prefix
        + function("scripts/net-dns-monitor-service", "acquire_service_lock")
        + "acquire_service_lock\n"
    )
    result = shell(code, cwd=tmp_path)
    assert result.returncode == 1
    assert "another service command owns" in result.stderr
    assert (lock / "owner-marker").read_text() == "keep"


@pytest.mark.parametrize("script,fail_fn", [("start.sh", "fail"), ("install.sh", "die")])
def test_startup_reservations_refuse_overlap_without_removing_other_owner(
    tmp_path, script, fail_fn
):
    source = (ROOT / "scripts" / script).read_text()
    assert 'BUILD_LOCK=""' in source
    lock_section = source.split('BUILD_LOCK=""', 1)[1].split(
        'START_LOCK="$START_LOCK_CANDIDATE"', 1
    )[0]
    lock_section = 'BUILD_LOCK=""' + lock_section + 'START_LOCK="$START_LOCK_CANDIDATE"\n'
    (tmp_path / ".netdns-build.lock").mkdir()
    (tmp_path / ".netdns-build.lock/owner-marker").write_text("keep")
    code = 'REPO_DIR="$PWD"\n' + f'{fail_fn}() {{ echo "$*" >&2; exit 1; }}\n' + lock_section
    result = shell(code, cwd=tmp_path, env={"HOME": str(tmp_path / "home")})
    assert result.returncode == 1
    assert "another build owns" in result.stderr
    assert (tmp_path / ".netdns-build.lock/owner-marker").read_text() == "keep"


def test_index_cleanup_constructs_the_current_id_set_once(tmp_path, monkeypatch):
    source = tmp_path / "doc.md"
    source.write_text("x" * 1100)
    builds = []
    real_set = set

    def record_set(values):
        values = list(values)
        if any("_chunk_" in str(value) for value in values):
            builds.append(len(values))
        return real_set(values)

    monkeypatch.setattr(indexer, "set", record_set, raising=False)
    removed = []
    collection = types.SimpleNamespace(
        upsert=lambda **kwargs: None,
        get=lambda **kwargs: {"ids": [f"doc.md_chunk_{n}" for n in range(100)]},
        delete=lambda ids: removed.extend(ids),
    )
    indexer.index_file(str(source), collection, root=str(tmp_path))
    assert builds == [2]
    assert removed == [f"doc.md_chunk_{n}" for n in range(2, 100)]


def test_atomic_journal_write_failure_preserves_old_output_and_existing_symlink(
    tmp_path, monkeypatch
):
    path = tmp_path / "memory.md"
    path.write_text("old")
    target = tmp_path / "owner.txt"
    target.write_text("keep")
    planted = tmp_path / ".memory.md.tmp"
    planted.symlink_to(target)

    def fail_sync(fd):
        raise OSError(errno.EIO, "synthetic")

    before = set(tmp_path.iterdir())
    monkeypatch.setattr(rotator.os, "fsync", fail_sync)
    with pytest.raises(OSError):
        rotator._write_atomic(path, "new")
    assert path.read_text() == "old"
    assert planted.is_symlink() and target.read_text() == "keep"
    assert set(tmp_path.iterdir()) == before


def test_recorder_confirmed_shutdown_transcodes_once_after_pid_removal(tmp_path, monkeypatch):
    pid_file = tmp_path / "pid"
    pid_file.write_text("123")
    raw = tmp_path / "raw.mov"
    raw.write_bytes(b"finalized")
    monkeypatch.setattr(recorder, "PID_FILE", pid_file)
    monkeypatch.setattr(recorder, "RAW_VIDEO", raw)
    monkeypatch.setattr(recorder, "is_screencapture", lambda pid: True)
    signals, processed = [], []

    def kill(pid, sig):
        signals.append(sig)
        if sig == 0:
            raise ProcessLookupError

    monkeypatch.setattr(recorder.os, "kill", kill)

    def process():
        assert not pid_file.exists()
        processed.append(raw.read_bytes())

    monkeypatch.setattr(recorder, "process", process)
    recorder.stop()
    assert signals == [recorder.signal.SIGINT, 0]
    assert processed == [b"finalized"]


def test_recorder_failed_spawn_releases_only_its_own_reservation(tmp_path, monkeypatch):
    monkeypatch.setattr(recorder, "DEMO_DIR", tmp_path)
    monkeypatch.setattr(recorder, "PID_FILE", tmp_path / "pid")
    monkeypatch.setattr(recorder, "RAW_VIDEO", tmp_path / "raw.mov")

    def spawn(*args, **kwargs):
        raise OSError(errno.EIO, "synthetic")

    monkeypatch.setattr(recorder.subprocess, "Popen", spawn)
    with pytest.raises(OSError):
        recorder.start()
    assert not recorder.PID_FILE.exists()


def test_linkage_accepts_existing_relative_and_internal_symlink_dependencies(tmp_path, monkeypatch):
    app = tmp_path / "X.app"
    binary = app / "Contents/MacOS/python"
    binary.parent.mkdir(parents=True)
    library = app / "Contents/Frameworks/libreal.dylib"
    library.parent.mkdir()
    library.write_text("x")
    link = binary.parent / "linked.dylib"
    link.symlink_to(library)
    names = ["@loader_path/linked.dylib", "@executable_path/../Frameworks/libreal.dylib"]

    def capture(argv):
        return (
            "binary:\n" + "".join("\t" + name + " (compatibility version 1.0)\n" for name in names)
            if "-L" in argv
            else "binary:\n"
        )

    monkeypatch.setattr(build, "capture", capture)
    assert build.check_linkage(app, [binary]) == []


def test_service_install_prepares_log_parent_before_reload(tmp_path):
    executable = tmp_path / "home/Applications/Net-DNS-Monitor.app/Contents/MacOS/Net-DNS-Monitor"
    executable.parent.mkdir(parents=True)
    executable.write_text("synthetic executable, never executed")
    executable.chmod(0o755)
    prefix = """
HOME="$PWD/home"; SUPPORT_DIR="$PWD/support"; SOURCE_BUNDLE="$PWD/absent"
INSTALLED_APP="$HOME/Applications/Net-DNS-Monitor.app"
EXEC="$INSTALLED_APP/Contents/MacOS/Net-DNS-Monitor"
APP_LOG="$HOME/Library/Logs/net-dns-monitor.launchd.log"
FLAG="$SUPPORT_DIR/flag"; SOURCE_BUNDLE_ORIGIN=synthetic; RESPAWN_GRACE_SECONDS=0
say() { printf '%s\\n' "$*"; }; warn() { :; }; die() { exit 99; }
write_plist() { :; }; audit() { :; }; cmd_status() { echo STATUS; }
reload_agent() { [[ -d "$HOME/Library/Logs" ]] || exit 98; echo RELOADED; }
wait_for_pid() { echo 42; }
"""
    code = prefix + function("scripts/net-dns-monitor-service", "cmd_install") + "cmd_install\n"
    result = shell(code, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "RELOADED" in result.stdout and "STATUS" in result.stdout
    assert (tmp_path / "home/Library/Logs").is_dir()


def test_nonindexable_source_is_skipped_without_creating_lock_state(tmp_path):
    source = tmp_path / "binary.bin"
    source.write_bytes(b"not eligible")
    indexer.index_file(str(source), collection=object(), root=str(tmp_path))
    assert not (tmp_path / ".semantic-index-locks").exists()
