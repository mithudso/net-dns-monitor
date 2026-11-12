"""Synthetic resume regressions. No GUI, recording, backend or probe runs."""

import ast
import importlib.util
import json
import os
import subprocess
import sys
import threading
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def load(name):
    spec = importlib.util.spec_from_file_location(Path(name).stem, ROOT / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load("scripts/appstore/build_appstore.py")
dossier = load("scripts/generate_static_dossier.py")
recorder = load("scripts/appstore/record_demo.py")
probe = load("scripts/appstore/sandbox_probe.py")
indexer = load("scripts/semantic_indexer.py")
watcher = load("scripts/watch_and_index.py")
shoot = load("scripts/appstore/shoot_screenshots.py")


def test_equivalent_macos_floor_is_not_newer():
    assert build.minimum_system_version((26, 0, 0), (26, 0)) == "26.0"


def test_linkage_is_architecture_specific(tmp_path, monkeypatch):
    app = tmp_path / "app"
    binary = app / "Contents/MacOS/bin"
    binary.parent.mkdir(parents=True)
    binary.write_text("synthetic")
    (binary.parent / "intel").mkdir()
    (binary.parent / "intel/libX.dylib").write_text("synthetic")
    libs = f"{binary} (architecture arm64):\n\t@rpath/libX.dylib (compatibility version 1.0.0, current version 1.0.0)\n{binary} (architecture x86_64):\n\t@rpath/libX.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
    rpaths = f"{binary} (architecture arm64):\nLoad command 0\n          cmd LC_RPATH\n      cmdsize 40\n         path @loader_path/arm (offset 12)\n{binary} (architecture x86_64):\nLoad command 0\n          cmd LC_RPATH\n      cmdsize 40\n         path @loader_path/intel (offset 12)\n"
    monkeypatch.setattr(
        build,
        "capture",
        lambda args: libs if "-L" in args else rpaths if "-l" in args else str(binary) + ":\n",
    )
    assert build.check_linkage(app, [binary])


def setup_dossier(tmp_path, monkeypatch, paths):
    (tmp_path / "docs/llms").mkdir(parents=True)
    (tmp_path / "docs/llms/manifest.json").write_text(
        json.dumps({"generator": "scripts/generate_static_dossier.py"})
    )
    (tmp_path / "docs/high_signal_file_index.json").write_text('{"files":[]}')
    monkeypatch.setattr(dossier, "ROOT", tmp_path)
    monkeypatch.setattr(dossier, "OUT", tmp_path / "docs/llms")
    monkeypatch.setattr(dossier, "census_paths", lambda: paths)
    monkeypatch.setattr(dossier, "git", lambda *a: "synthetic" if a[0] == "rev-parse" else "")


def test_dossier_refuses_output_symlink(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    setup_dossier(root, monkeypatch, [])
    outside = tmp_path / "keep"
    outside.write_text("keep")
    (root / "llms.txt").symlink_to(outside)
    with pytest.raises((ValueError, SystemExit)):
        dossier.main()
    assert outside.read_text() == "keep"


def test_dossier_filename_is_one_unambiguous_line(tmp_path, monkeypatch):
    name = "notes\n- fabricated.py"
    (tmp_path / name).write_text("synthetic")
    setup_dossier(tmp_path, monkeypatch, [name])
    dossier.main()
    text = (tmp_path / "docs/llms/llms-filemap.txt").read_text()
    assert "\n- fabricated.py" not in text
    assert "\\n- fabricated.py" in text


def test_unknown_recording_identity_preserves_pid(tmp_path, monkeypatch):
    pid = tmp_path / "capture.pid"
    pid.write_text("123")
    monkeypatch.setattr(recorder, "PID_FILE", pid)
    monkeypatch.setattr(recorder, "DEMO_DIR", tmp_path)
    monkeypatch.setattr(
        recorder.subprocess,
        "run",
        lambda *a, **k: (_ for _ in ()).throw(subprocess.TimeoutExpired("ps", 5)),
    )
    monkeypatch.setattr(recorder.os, "kill", lambda *a: pytest.fail("must not signal unknown PID"))
    with pytest.raises(SystemExit):
        recorder.stop()
    assert pid.read_text() == "123"


def test_transcode_refuses_active_recording(tmp_path, monkeypatch):
    pid = tmp_path / "capture.pid"
    pid.write_text("123")
    raw = tmp_path / "raw.mov"
    raw.write_text("unfinished")
    monkeypatch.setattr(recorder, "PID_FILE", pid)
    monkeypatch.setattr(recorder, "RAW_VIDEO", raw)
    monkeypatch.setattr(recorder, "DEMO_DIR", tmp_path)
    calls = []
    monkeypatch.setattr(
        recorder.subprocess,
        "run",
        lambda *a, **k: calls.append(a) or subprocess.CompletedProcess(a, 1, "", "synthetic"),
    )
    with pytest.raises(SystemExit):
        recorder.process()
    assert calls == []


def test_screenshot_refuses_hardlinked_output(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    owner = tmp_path / "owner.yaml"
    owner.write_text("keep")
    os.link(owner, out / "config.yaml")
    with pytest.raises(ValueError, match="unsafe|hardlink"):
        shoot.write_isolated_config(out)
    assert owner.read_text() == "keep"


def screenshot_main(monkeypatch, tmp_path):
    # Extract only main; all application factories/imports are synthetic.
    node = next(
        n
        for n in ast.parse((ROOT / "scripts/appstore/shoot_screenshots.py").read_text()).body
        if isinstance(n, ast.FunctionDef) and n.name == "main"
    )
    app = types.ModuleType("netdnsmonitor.app")
    app.main = lambda **kw: None
    monkeypatch.setitem(sys.modules, "netdnsmonitor.app", app)
    import netdnsmonitor

    monkeypatch.setattr(netdnsmonitor, "app", app, raising=False)
    calls = []

    class Timer:
        daemon = False

        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def cancel(self):
            pass

    env = dict(vars(shoot))
    env.update(
        threading=types.SimpleNamespace(Timer=Timer),
        subprocess=types.SimpleNamespace(run=lambda *a, **k: calls.append(k)),
        write_isolated_config=lambda out: out / "config.yaml",
        refuse_owner_dir=lambda out: None,
    )
    exec(compile(ast.Module(body=[node], type_ignores=[]), "<synthetic-main>", "exec"), env)
    return env["main"], calls


def test_screenshot_early_app_return_fails(tmp_path, monkeypatch):
    main, _ = screenshot_main(monkeypatch, tmp_path)
    assert main(["shoot", str(tmp_path)]) == 1


def test_screenshot_startup_child_has_deadline(tmp_path, monkeypatch):
    main, calls = screenshot_main(monkeypatch, tmp_path)
    main(["shoot", str(tmp_path)])
    assert 0 < calls[0].get("timeout", 0) <= shoot.RUN_DEADLINE


def test_indexer_rejects_swapped_parent_symlink(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    folder = root / "docs"
    folder.mkdir(parents=True)
    source = folder / "note.txt"
    source.write_text("public")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "note.txt").write_text("private")
    original = indexer.os.open
    swapped = False

    def open_at_boundary(path, flags, *args, **kwargs):
        nonlocal swapped
        if str(path) == str(root) and not swapped:
            swapped = True
            folder.rename(root / "old")
            folder.symlink_to(outside, target_is_directory=True)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(indexer.os, "open", open_at_boundary)
    writes = []
    collection = types.SimpleNamespace(
        upsert=lambda **kw: writes.append(kw), get=lambda **kw: {"ids": []}
    )
    with pytest.raises(OSError):
        indexer.index_file(str(source), collection, str(root))
    assert swapped
    assert writes == []


class FakeTimer:
    timers = []

    def __init__(self, delay, callback, args=()):
        self.callback, self.args = callback, args
        self.timers.append(self)

    def start(self):
        pass

    def cancel(self):
        pass

    def fire(self):
        self.callback(*self.args)


def test_watcher_preserves_distinct_move_destinations():
    FakeTimer.timers = []
    seen = []
    c = watcher.EventCoalescer(lambda *a: seen.append(a), timer_factory=FakeTimer)
    c.add("moved", "a.py", "b.py", False)
    c.add("moved", "a.py", "c.py", False)
    for timer in list(FakeTimer.timers):
        timer.fire()
    assert {e[2] for e in seen} == {"b.py", "c.py"}


def test_watcher_revalidates_after_execution_lock():
    FakeTimer.timers = []
    seen = []
    c = watcher.EventCoalescer(lambda *a: seen.append(a), timer_factory=FakeTimer)
    c.add("deleted", "a.py", "", False)
    old = FakeTimer.timers[-1]

    class Gate:
        def __enter__(self):
            c.add("created", "a.py", "", False)

        def __exit__(self, *a):
            pass

    c._run_lock = Gate()
    old.fire()
    assert seen == []


def test_probe_keychain_uses_unique_accounts(monkeypatch):
    from netdnsmonitor import credentials

    accounts = []

    class Backend:
        def add(self, account, value):
            accounts.append(account)
            return 0

        def read(self, account):
            return 0, b"probe-value"

        def delete(self, account):
            return 0

    monkeypatch.setattr(credentials, "make_keychain_backend", lambda **kw: Backend())
    assert probe.keychain_round_trip()["ok"] is True
    assert probe.keychain_round_trip()["ok"] is True
    assert len(set(accounts)) == 2


def test_probe_stalled_resolution_returns_unknown(monkeypatch):
    # Synthetic thread never supplies a result; no resolver or worker runs.
    class Thread:
        def __init__(self, *a, **k):
            pass

        def start(self):
            pass

        def join(self, *a):
            pass

        def is_alive(self):
            return True

    monkeypatch.setattr(threading, "Thread", Thread)
    monkeypatch.setattr(
        probe.socket,
        "getaddrinfo",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("synthetic stalled resolver")),
    )
    assert probe.getaddrinfo()["ok"] is None


def test_watcher_burst_has_one_live_timer():
    active = set()
    peak = []

    class Timer:
        def __init__(self, *a, **k):
            pass

        def start(self):
            active.add(self)
            peak.append(len(active))

        def cancel(self):
            active.discard(self)

    c = watcher.EventCoalescer(lambda *a: None, timer_factory=Timer)
    for i in range(2000):
        c.add("modified", f"{i}.py", "", False)
    assert max(peak) <= 1


def test_transcoding_lock_prevents_raw_replacement(tmp_path, monkeypatch):
    raw = tmp_path / "raw.mov"
    final = tmp_path / "final.mp4"
    raw.write_text("finalized original")
    monkeypatch.setattr(recorder, "DEMO_DIR", tmp_path)
    monkeypatch.setattr(recorder, "PID_FILE", tmp_path / "pid")
    monkeypatch.setattr(recorder, "RAW_VIDEO", raw)
    monkeypatch.setattr(recorder, "FINAL_VIDEO", final)
    monkeypatch.setattr(
        recorder.subprocess, "Popen", lambda *a, **k: pytest.fail("capture must not start")
    )

    def transcode(*a, **k):
        with pytest.raises(SystemExit, match="already in progress"):
            recorder.start()
        assert raw.read_text() == "finalized original"
        final.write_text("encoded")
        return subprocess.CompletedProcess(a, 0, "", "")

    monkeypatch.setattr(recorder.subprocess, "run", transcode)
    recorder.process()
    assert final.read_text() == "encoded"


def test_watcher_changes_during_handler_allocate_no_waiting_threads():
    FakeTimer.timers = []

    def handle(*args):
        for i in range(2000):
            c.add("modified", f"{i}.py", "", False)
        assert len(FakeTimer.timers) == 1

    c = watcher.EventCoalescer(handle, timer_factory=FakeTimer)
    c.add("modified", "first.py", "", False)
    FakeTimer.timers[0].fire()
    assert len(FakeTimer.timers) == 2


def test_watcher_filters_excluded_bursts_before_scheduling(tmp_path):
    FakeTimer.timers = []
    seen = []
    c = watcher.EventCoalescer(
        lambda *a: seen.append(a), timer_factory=FakeTimer, root=str(tmp_path)
    )
    for i in range(2000):
        c.add("modified", str(tmp_path / ".venv" / f"{i}.py"), "", False)
    assert FakeTimer.timers == []
    c.add("moved", str(tmp_path / ".venv/a.py"), str(tmp_path / "a.py"), False)
    FakeTimer.timers[-1].fire()
    assert seen == [("moved", str(tmp_path / ".venv/a.py"), str(tmp_path / "a.py"), False)]


@pytest.mark.parametrize(
    "answer", [[("synthetic",)], PermissionError(13, "synthetic"), OSError(5, "synthetic")]
)
def test_probe_resolution_keeps_tristate_with_synthetic_worker(monkeypatch, answer):
    class Thread:
        def __init__(self, target, daemon):
            assert daemon is True
            self.target = target

        def start(self):
            self.target()

        def join(self, timeout):
            assert timeout == 5

        def is_alive(self):
            return False

    def lookup(*a, **kw):
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(threading, "Thread", Thread)
    monkeypatch.setattr(probe.socket, "getaddrinfo", lookup)
    expected = (
        False
        if isinstance(answer, PermissionError)
        else None
        if isinstance(answer, Exception)
        else True
    )
    assert probe.getaddrinfo()["ok"] is expected


def test_icns_rejects_chunk_beyond_container():
    data = (
        b"icns"
        + (24).to_bytes(4, "big")
        + b"ic09"
        + (8).to_bytes(4, "big")
        + b"ic10"
        + (1000).to_bytes(4, "big")
    )
    with pytest.raises(ValueError):
        build.icns_types(data)


def test_nested_module_import_is_checked(tmp_path):
    (tmp_path / "kept.py").write_text("if True:\n    from netdnsmonitor import router\n")
    assert build.module_level_imports_of_omitted(tmp_path, ("router",)) == ["kept.py:2 -> router"]


def test_duplicate_slice_rpaths_deleted_once(monkeypatch):
    calls = []
    monkeypatch.setattr(build, "capture", lambda *a: "")
    monkeypatch.setattr(build, "parse_rpaths", lambda *a: ["/external", "/external"])
    monkeypatch.setattr(build, "run", lambda args: calls.append(args))
    assert build.strip_external_rpaths(Path("app"), [Path("synthetic")]) == 1
    assert len(calls) == 1


def test_screenshot_refuses_fifo(tmp_path):
    os.mkfifo(tmp_path / "config.yaml")
    # Check rejection before write_text, so the regression cannot block.
    monkey = pytest.MonkeyPatch()
    monkey.setattr(Path, "write_text", lambda *a, **k: pytest.fail("FIFO reached writer"))
    try:
        with pytest.raises(ValueError, match="unsafe"):
            shoot.write_isolated_config(tmp_path)
    finally:
        monkey.undo()


def test_unavailable_keychain_is_unknown(monkeypatch):
    from netdnsmonitor import credentials

    backend = types.SimpleNamespace(
        add=lambda *a: -25291, read=lambda *a: (-25291, None), delete=lambda *a: -25291
    )
    monkeypatch.setattr(credentials, "make_keychain_backend", lambda **k: backend)
    assert probe.keychain_round_trip()["ok"] is None


def test_https_complete_operation_has_deadline(monkeypatch):
    class Thread:
        def __init__(self, **kwargs):
            pass

        def start(self):
            pass

        def join(self, timeout):
            assert timeout == 8

        def is_alive(self):
            return True

    monkeypatch.setattr(probe.threading, "Thread", Thread)
    monkeypatch.setattr(
        probe.urllib.request, "urlopen", lambda *a, **k: pytest.fail("unbounded HTTPS")
    )
    assert probe.https_request()["ok"] is None


def test_watcher_pending_timer_cannot_be_postponed_forever():
    FakeTimer.timers = []
    c = watcher.EventCoalescer(lambda *a: None, timer_factory=FakeTimer)
    for i in range(100):
        c.add("modified", f"{i}.py", "", False)
    assert len(FakeTimer.timers) == 1


def test_watcher_propagates_selected_root(tmp_path):
    args = watcher.indexer_argv("modified", str(tmp_path / "a.py"), "", str(tmp_path))
    assert args[2:4] == ["--root", str(tmp_path)]


def test_pid_write_failure_reaps_owned_child(tmp_path, monkeypatch):
    events = []
    proc = types.SimpleNamespace(
        pid=123,
        send_signal=lambda sig: events.append("signal"),
        wait=lambda timeout: events.append("wait"),
    )
    monkeypatch.setattr(recorder, "RAW_VIDEO", tmp_path / "raw.mov")
    monkeypatch.setattr(recorder.subprocess, "Popen", lambda *a, **k: proc)
    reservation = types.SimpleNamespace(
        write=lambda *a: (_ for _ in ()).throw(OSError("synthetic full disk"))
    )
    with pytest.raises(OSError):
        recorder._start_recording(reservation)
    assert events == ["signal", "wait"]


def test_legacy_capture_pid_never_signalled(tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    pid.write_text("4242")
    monkeypatch.setattr(recorder, "PID_FILE", pid)
    monkeypatch.setattr(recorder, "is_screencapture", lambda p: True)
    monkeypatch.setattr(recorder.os, "kill", lambda *a: pytest.fail("unverified capture signalled"))
    with pytest.raises(SystemExit):
        recorder._stop()
    assert pid.read_text() == "4242"


def test_reused_capture_identity_never_signalled(tmp_path, monkeypatch):
    pid = tmp_path / "pid"
    pid.write_text(json.dumps({"pid": 4242, "identity": "original capture"}))
    monkeypatch.setattr(recorder, "PID_FILE", pid)
    monkeypatch.setattr(recorder, "is_screencapture", lambda p: True)
    monkeypatch.setattr(recorder, "recording_identity", lambda p: "different capture")
    monkeypatch.setattr(recorder.os, "kill", lambda *a: pytest.fail("reused capture signalled"))
    with pytest.raises(SystemExit):
        recorder._stop()
    assert pid.exists()


def test_directory_move_reconciles_both_paths_without_running_indexer(tmp_path):
    calls = []
    old, new = str(tmp_path / "pkg"), str(tmp_path / "renamed")
    run = lambda args, **k: calls.append(args) or types.SimpleNamespace(returncode=0)
    watcher.handle_event("moved", old, new, True, str(tmp_path), run)
    assert [a[-2:] for a in calls] == [["--reconcile", old], ["--reconcile", new]]
    assert all(a[2:4] == ["--root", str(tmp_path)] for a in calls)


def test_directory_reconcile_removes_missing_descendant_only(tmp_path):
    calls = []
    collection = types.SimpleNamespace(
        get=lambda **k: {"metadatas": [{"source": "gone/a.py"}, {"source": "other.py"}]},
        delete=lambda **k: calls.append(k),
    )
    indexer.reconcile_directory(str(tmp_path / "gone"), collection, str(tmp_path))
    assert calls == [{"where": {"source": "gone/a.py"}}]


def test_indexer_never_reads_newly_excluded_canonical_source(tmp_path, monkeypatch):
    safe = tmp_path / "safe.py"
    safe.write_text("public")
    secret = tmp_path / "credentials.json"
    secret.write_text("synthetic private")
    link = tmp_path / "link.py"
    link.symlink_to(safe)
    original = indexer.eligible_source
    swapped = []

    def eligibility(source):
        answer = original(source)
        if not swapped:
            link.unlink()
            link.symlink_to(secret)
            swapped.append(True)
        return answer

    monkeypatch.setattr(indexer, "eligible_source", eligibility)
    writes = []
    collection = types.SimpleNamespace(
        upsert=lambda **k: writes.append(k), get=lambda **k: {"ids": []}
    )
    indexer.index_file(str(link), collection, str(tmp_path))
    assert swapped == [True]
    assert writes[0]["documents"] == ["public"]
    assert writes[0]["metadatas"] == [{"source": "safe.py"}]


@pytest.mark.parametrize("fail_on", ["write", "flush"])
def test_pid_persistence_failure_confirms_child_exit(tmp_path, monkeypatch, fail_on):
    events = []
    proc = types.SimpleNamespace(
        pid=123,
        send_signal=lambda sig: events.append("signal"),
        wait=lambda timeout: events.append("reaped"),
    )
    monkeypatch.setattr(recorder, "RAW_VIDEO", tmp_path / "raw.mov")
    monkeypatch.setattr(recorder.subprocess, "Popen", lambda *a, **k: proc)

    def operation(name):
        if name == fail_on:
            raise OSError("synthetic full disk")

    reservation = types.SimpleNamespace(
        write=lambda *a: operation("write"), flush=lambda: operation("flush")
    )
    with pytest.raises(OSError):
        recorder._start_recording(reservation)
    assert events == ["signal", "reaped"]


def test_type_checking_import_remains_deferred(tmp_path):
    (tmp_path / "kept.py").write_text(
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from netdnsmonitor import router\n"
    )
    assert build.module_level_imports_of_omitted(tmp_path, ("router",)) == []


def test_directory_reconcile_keeps_old_chunks_when_upsert_fails(tmp_path):
    folder = tmp_path / "pkg"
    folder.mkdir()
    (folder / "a.py").write_text("synthetic public")
    deleted = []

    def upsert(**kwargs):
        raise RuntimeError("synthetic unavailable embedder")

    collection = types.SimpleNamespace(
        get=lambda **k: {"metadatas": [{"source": "pkg/a.py"}]},
        delete=lambda **k: deleted.append(k),
        upsert=upsert,
    )
    with pytest.raises(RuntimeError):
        indexer.reconcile_directory(str(folder), collection, str(tmp_path))
    assert deleted == []


@pytest.mark.parametrize("operation", ["index", "remove", "reconcile"])
def test_selected_index_root_selects_its_collection(tmp_path, monkeypatch, operation):
    source = tmp_path / "source.py"
    source.write_text("synthetic")
    roots = []

    class Collection:
        def upsert(self, **kwargs):
            pass

        def get(self, **kwargs):
            return {"ids": [], "metadatas": []}

        def delete(self, **kwargs):
            pass

    def opened(root=None):
        roots.append(root)
        return Collection()

    monkeypatch.setattr(indexer, "open_collection", opened)
    if operation == "index":
        indexer.index_file(str(source), root=str(tmp_path))
    elif operation == "remove":
        indexer.remove_file(str(source), root=str(tmp_path))
    else:
        indexer.reconcile_directory(str(tmp_path), root=str(tmp_path))
    assert roots == [str(tmp_path)]


def test_collection_factory_keeps_explicit_root_separate(tmp_path, monkeypatch):
    paths = []
    fake_embedding = object()
    collection = object()
    client = types.SimpleNamespace(get_or_create_collection=lambda **kwargs: collection)
    monkeypatch.setitem(
        sys.modules,
        "chromadb",
        types.SimpleNamespace(
            PersistentClient=lambda **kwargs: paths.append(kwargs["path"]) or client
        ),
    )
    monkeypatch.setitem(
        sys.modules,
        "chromadb.utils",
        types.SimpleNamespace(
            embedding_functions=types.SimpleNamespace(
                OllamaEmbeddingFunction=lambda **kwargs: fake_embedding
            )
        ),
    )
    assert indexer.open_collection(str(tmp_path)) is collection
    assert indexer.open_collection() is collection
    assert paths == [str(tmp_path / ".chroma_db"), indexer.DB_PATH]
