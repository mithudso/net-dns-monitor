import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "record_demo", ROOT / "scripts" / "appstore" / "record_demo.py"
)
rd = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rd)


def test_is_screencapture_matches_basename_only():
    assert rd.is_screencapture(1, ps_fn=lambda pid: "/usr/sbin/screencapture")
    assert not rd.is_screencapture(1, ps_fn=lambda pid: "/usr/bin/vim")
    assert not rd.is_screencapture(1, ps_fn=lambda pid: "notscreencapture")
    assert not rd.is_screencapture(1, ps_fn=lambda pid: None)


def test_stop_never_signals_a_recycled_pid(monkeypatch, tmp_path):
    pid_file = tmp_path / "pid"
    pid_file.write_text("4242")
    monkeypatch.setattr(rd, "PID_FILE", pid_file)
    monkeypatch.setattr(rd, "RAW_VIDEO", tmp_path / "raw.mov")
    monkeypatch.setattr(rd, "process_command", lambda pid: "/usr/bin/vim")
    monkeypatch.setattr(rd, "is_screencapture", lambda pid: False)
    killed = []
    monkeypatch.setattr(rd.os, "kill", lambda pid, sig: killed.append((pid, sig)))
    with pytest.raises(SystemExit) as exc:
        rd.stop()
    assert exc.value.code == 1
    assert killed == []
    assert not pid_file.exists()


def test_start_fails_when_screencapture_exits_immediately(monkeypatch, tmp_path):
    monkeypatch.setattr(rd, "DEMO_DIR", tmp_path)
    monkeypatch.setattr(rd, "PID_FILE", tmp_path / "pid")
    monkeypatch.setattr(rd, "RAW_VIDEO", tmp_path / "raw.mov")
    monkeypatch.setattr(rd, "START_POLL_SECONDS", 0)

    class Dead:
        pid = 99
        returncode = 1

        def poll(self):
            return 1

    monkeypatch.setattr(rd.subprocess, "Popen", lambda *a, **k: Dead())
    with pytest.raises(SystemExit) as exc:
        rd.start()
    assert exc.value.code == 1
    assert not (tmp_path / "pid").exists()
