"""Shared test setup.

The one thing here is a guard rather than a convenience. Several config defaults
point into `~/Library/Application Support/net-dns-monitor/` -- the resolution
log, the incident reports, and now the forensic journal and episode documents.
Any test that builds a `NetDnsMonitorApp` with a nonexistent config file gets
those defaults, so a test that drives a ping failure would append to the real
journal on the developer's own machine and interleave fake outages with real
ones. Redirecting HOME makes `os.path.expanduser` resolve into a per-test
temporary directory, so the whole suite is inert against real user data.
"""

import pytest


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture(autouse=True)
def no_real_dock_icon(monkeypatch):
    """Keep the test suite off the real Dock.

    `setApplicationIconImage_` is a synchronous AppKit call measured at ~2 seconds
    each, and it pushes a tile to the developer's actual Dock -- a visible side
    effect no test asks for. With ~100 constructed apps that alone took the suite
    from 7 seconds to over 200.

    The tile's own rendering is covered directly and quickly by test_dock_icon.py
    (build_status_icon, offscreen), and the throttling decision is covered by
    app-level tests that assert on the call, not on the Dock.
    """
    monkeypatch.setattr("netdnsmonitor.dock_icon.set_dock_icon", lambda *a, **k: None)
    monkeypatch.setattr("netdnsmonitor.app.set_dock_icon", lambda *a, **k: None)
