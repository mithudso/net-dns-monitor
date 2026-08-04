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
