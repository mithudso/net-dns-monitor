"""Parity: the plist scripts/net-dns-monitor-service writes vs launchd-supervisor's render.

The service script is the production supervisor of the live app, so it is NOT
replaced by macos-launchd-supervisor. This test records that the library renders
the same LaunchAgent (same keys and values; only key order and XML comments
differ), which is the precondition for ever delegating the plist half to it.

Safe by construction: HOME points into tmp_path, only `write_plist` is sourced
from the script (no launchctl call, no install/bootstrap), and the library side
is a pure render.
"""

from __future__ import annotations

import plistlib
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("launchd_supervisor")
from launchd_supervisor import ServiceSpec  # noqa: E402
from launchd_supervisor.plist import plist_dict  # noqa: E402

SERVICE = Path(__file__).resolve().parent.parent / "scripts" / "net-dns-monitor-service"
LABEL = "com.mitchhudson.net-dns-monitor"


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    contents = home / "Applications" / "Net-DNS-Monitor.app" / "Contents"
    (contents / "MacOS").mkdir(parents=True)
    exe = contents / "MacOS" / "Net-DNS-Monitor"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Net-DNS-Monitor"}))
    return home


def _script_plist(home: Path) -> dict:
    code = SERVICE.read_text(encoding="utf-8")
    lib = code[: code.index("\nusage()")]  # everything before the command dispatch
    done = subprocess.run(
        ["bash", "-c", f"{lib}\nwrite_plist"],
        env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    return plistlib.loads((home / "Library" / "LaunchAgents" / f"{LABEL}.plist").read_bytes())


def test_library_renders_the_same_launchagent_as_the_service_script(tmp_path):
    home = _fake_home(tmp_path)
    support = home / "Library" / "Application Support" / "net-dns-monitor"
    log = home / "Library" / "Logs" / "net-dns-monitor.launchd.log"
    spec = ServiceSpec(
        label=LABEL,
        program=str(home / "Applications" / "Net-DNS-Monitor.app"),
        supervise=True,
        throttle_interval=15,
        state_dir=str(support),
        stdout_path=str(log),
        stderr_path=str(log),
    )
    assert plist_dict(spec, strict=True) == _script_plist(home)
