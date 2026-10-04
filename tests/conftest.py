"""Shared test setup.

Everything here is a guard rather than a convenience: each fixture keeps the
suite from reaching something real on the developer's machine.

The first is user data. Several config defaults point into
`~/Library/Application Support/net-dns-monitor/` -- the resolution log, the
incident reports, and now the forensic journal and episode documents. Any test
that builds a `NetDnsMonitorApp` with a nonexistent config file gets those
defaults, so a test that drives a ping failure would append to the real journal
on the developer's own machine and interleave fake outages with real ones.
Redirecting HOME makes `os.path.expanduser` resolve into a per-test temporary
directory, so the whole suite is inert against real user data.
"""

import sys

import pytest

# Test modules whose unit under test IS one of the functions stubbed below. They
# call the real function with an injected run_fn, so stubbing the module
# attribute there would replace the thing being tested with a lambda.
_REAL_PRIVILEGE_PROBES = frozenset({"test_privileges"})
_REAL_LOG_READERS = frozenset({"test_system_log", "test_log_watcher"})


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


def _keep_out_of_dock():
    """Make this process background-only before AppKit can register it.

    The first `NSApplication.sharedApplication()` in a bare Python process registers
    it as a Foreground app, and the Dock shows a transient Python tile until the
    process exits. Setting `setActivationPolicy_(Prohibited)` afterwards does not
    help: the type is already Foreground for the moment between the two calls, which
    is exactly the flicker. Transforming the process first makes it BackgroundOnly
    from birth, and `sharedApplication()` then leaves it that way. Windows and menus
    stay constructible. Runs at conftest import, ahead of collection and any fixture.
    """
    if sys.platform != "darwin":
        return
    import ctypes
    import ctypes.util

    class ProcessSerialNumber(ctypes.Structure):
        _fields_ = [("high", ctypes.c_uint32), ("low", ctypes.c_uint32)]

    path = ctypes.util.find_library("ApplicationServices")
    if not path:
        return
    k_current_process = 2
    k_transform_to_background_application = 2
    ctypes.CDLL(path).TransformProcessType(
        ctypes.byref(ProcessSerialNumber(0, k_current_process)),
        k_transform_to_background_application,
    )


_keep_out_of_dock()


class _MemoryKeychain:
    """An empty Keychain that lives for one test. Same status codes as the real one."""

    def __init__(self):
        self.items: dict = {}

    def read(self, account):
        from netdnsmonitor.credentials import ERR_SEC_ITEM_NOT_FOUND

        if account not in self.items:
            return ERR_SEC_ITEM_NOT_FOUND, None
        return 0, self.items[account]

    def add(self, account, value):
        from netdnsmonitor.credentials import ERR_SEC_DUPLICATE_ITEM

        if account in self.items:
            return ERR_SEC_DUPLICATE_ITEM
        self.items[account] = value
        return 0

    def update(self, account, value):
        self.items[account] = value
        return 0

    def delete(self, account):
        from netdnsmonitor.credentials import ERR_SEC_ITEM_NOT_FOUND

        if self.items.pop(account, None) is None:
            return ERR_SEC_ITEM_NOT_FOUND
        return 0


@pytest.fixture(autouse=True)
def no_real_keychain_or_distribution(monkeypatch):
    """Keep the suite off the developer's Keychain, and on the direct build.

    The app builds a CredentialStore at construction and reads all three
    credentials from it, so without this every constructed app would query the
    real login Keychain, and a key saved there would change what a test sees.
    `app.default_credential_store` looks `make_keychain_backend` up on the
    credentials module at call time, which is the seam patched here. A test that
    wants a populated Keychain passes its own CredentialStore instead.

    The two variables that select the Mac App Store build are removed for the
    same reason: exported in a developer's shell, they would switch every
    direct-build test onto the gated paths. Tests of the store build pass
    `capabilities=` explicitly.
    """
    monkeypatch.setattr(
        "netdnsmonitor.credentials.make_keychain_backend", lambda *a, **k: _MemoryKeychain()
    )
    monkeypatch.delenv("APP_SANDBOX_CONTAINER_ID", raising=False)
    monkeypatch.delenv("NETDNS_DISTRIBUTION", raising=False)
    # Synthetic incidents must never use credentials inherited from the shell.
    # Credential tests set their own values after this fixture runs.
    for name in ("SLACK_WEBHOOK_URL", "ANTHROPIC_API_KEY", "SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)


def _empty_log_reader(window: str = "1m", errors_only: bool = True) -> dict:
    return {"entries": [], "error": None}


@pytest.fixture(autouse=True)
def no_real_system_probes(request, monkeypatch):
    """Keep app-wiring tests from spawning `sudo`, `ifconfig`, `route` and `log show`.

    The app calls these without an injected runner. `launch_tick` and opening the
    dashboard start the privilege probe (`sudo -n -k -l`, `ifconfig -l`,
    `route -n get default`) and a system-log backfill, and `build_state_machine`
    wires a real `log show` watcher that an incident tick then runs. Before this
    fixture the suite ran each privilege probe 37 times across six test modules,
    and the answers depended on whichever machine ran the suite.

    The privilege functions and `make_log_reader` are patched on their own modules
    because the app looks them up through those modules at call time; there is no
    narrower seam. `make_log_watcher` is patched where `netdnsmonitor.app` bound it,
    which touches nothing else. The privilege defaults describe an ungranted
    machine whose interfaces were not read -- the same machine
    `make_repair_executor` assumes when given no probes. A test that needs other
    answers patches over these, as test_app_privilege_wiring.py does.

    The probe and the log read run on daemon threads, so a thread that is slow to
    start can outlive its test's patch and reach the real function. The stubs
    return at once, which keeps that window small; it is not closed.
    """
    module = request.path.stem
    if module not in _REAL_PRIVILEGE_PROBES:
        monkeypatch.setattr("netdnsmonitor.privileges.granted_commands_now", lambda *a, **k: [])
        monkeypatch.setattr("netdnsmonitor.privileges.is_granted", lambda *a, **k: False)
        monkeypatch.setattr("netdnsmonitor.privileges.dhcp_interfaces", lambda *a, **k: [])
        monkeypatch.setattr("netdnsmonitor.privileges.primary_interface", lambda *a, **k: None)
    if module not in _REAL_LOG_READERS:
        monkeypatch.setattr("netdnsmonitor.app.make_log_watcher", lambda *a, **k: lambda: [])
        monkeypatch.setattr(
            "netdnsmonitor.system_log.make_log_reader", lambda *a, **k: _empty_log_reader
        )
