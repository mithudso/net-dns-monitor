"""sandbox_probe records tri-state results: denied is False, could-not-run is None."""

import errno
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "appstore"))
import sandbox_probe as sp  # noqa: E402


def _raise(exc):
    def fn():
        raise exc

    return fn


def test_permission_errors_are_measured_denials():
    assert sp.timed(_raise(PermissionError(1, "no")))["ok"] is False
    assert sp.timed(_raise(OSError(errno.EPERM, "no")))["ok"] is False
    assert sp.timed(_raise(OSError(errno.EACCES, "no")))["ok"] is False


def test_network_unreachable_is_not_probed():
    result = sp.timed(_raise(OSError(errno.ENETUNREACH, "down")))
    assert result["ok"] is None
    assert result["errno"] == errno.ENETUNREACH


def test_timeout_is_not_probed():
    assert sp.timed(_raise(TimeoutError("t")))["ok"] is None


def test_run_command_timeout_and_missing_binary_are_not_probed(monkeypatch):
    def timeout(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)

    monkeypatch.setattr(sp.subprocess, "run", timeout)
    assert sp.run_command(["x"])["ok"] is None

    def missing(*a, **k):
        raise FileNotFoundError(errno.ENOENT, "nope")

    monkeypatch.setattr(sp.subprocess, "run", missing)
    assert sp.run_command(["x"])["ok"] is None


def test_run_command_nonzero_exit_stays_false(monkeypatch):
    done = subprocess.CompletedProcess(["x"], 2, "", "bad\n")
    monkeypatch.setattr(sp.subprocess, "run", lambda *a, **k: done)
    assert sp.run_command(["x"])["ok"] is False


def test_udp_dns_follows_the_answer(monkeypatch):
    import netdnsmonitor.dns_query as dq

    for answer in (True, False, None):
        monkeypatch.setattr(dq, "query_public_dns", lambda d, a=answer: a)
        assert sp.udp_dns()["ok"] is answer


def test_keychain_item_is_deleted_when_read_raises(monkeypatch):
    import netdnsmonitor.credentials as cred

    calls = []

    class Backend:
        def delete(self, account):
            calls.append("delete")
            return 0

        def add(self, account, value):
            return 0

        def read(self, account):
            raise OSError(errno.EIO, "boom")

    monkeypatch.setattr(cred, "make_keychain_backend", lambda service: Backend())
    with pytest.raises(OSError):
        sp.keychain_round_trip()
    assert calls == ["delete", "delete"]
