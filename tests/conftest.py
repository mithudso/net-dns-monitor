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

import os
import sys
import tempfile

import pytest

# Collection imports application modules before autouse fixtures run. Keep
# import-time path defaults inside a synthetic home as well as per-test paths.
_SESSION_HOME = tempfile.TemporaryDirectory(prefix="netdns-test-home-")
os.environ["HOME"] = _SESSION_HOME.name
os.environ["XDG_CACHE_HOME"] = os.path.join(_SESSION_HOME.name, "cache")
os.environ["XDG_DATA_HOME"] = os.path.join(_SESSION_HOME.name, "data")

# Test modules whose unit under test IS one of the functions stubbed below. They
# call the real function with an injected run_fn, so stubbing the module
# attribute there would replace the thing being tested with a lambda.
_REAL_PRIVILEGE_PROBES = frozenset({"test_privileges"})
_REAL_LOG_READERS = frozenset({"test_system_log", "test_log_watcher"})
_REAL_USER_NOTIFY = frozenset({"test_user_notify"})


@pytest.fixture(autouse=True)
def isolate_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture(autouse=True)
def no_real_notifications(monkeypatch, request):
    """Keep the test suite out of Notification Centre.

    App wiring tests drive fake ping failures through the real `alert` module,
    and `rumps.notification` posts a real "network failed" banner from the
    pytest process -- indistinguishable from the menu bar app reporting a real
    outage. Delivery now goes through `user_notify.post`
    (UNUserNotificationCenter), so that is stubbed to report `queued`; the
    framework loader and bundle probe are stubbed too, so a test that injects
    only one of them still cannot reach the real centre. `rumps.notification`
    stays stubbed in case anything outside the app still calls it. The osascript
    fallback runs only when `post` reports a non-queued status, and the tests
    that want it inject their own `post_fn` and `run_fn`. `test_user_notify`
    is exempt: it tests the real `post` with injected fakes.
    """
    import rumps

    from netdnsmonitor import user_notify

    monkeypatch.setattr(rumps, "notification", lambda *args, **kwargs: None)
    if request.module.__name__.rsplit(".", 1)[-1] not in _REAL_USER_NOTIFY:
        monkeypatch.setattr(user_notify, "post", lambda *args, **kwargs: user_notify.STATUS_QUEUED)
    monkeypatch.setattr(user_notify, "load_backend", lambda: None)
    monkeypatch.setattr(user_notify, "_main_bundle", lambda: (None, None))


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


# A default argument captures its callable at function definition. Fixture
# teardown can also outlive a daemon worker. Establish synthetic fallbacks
# before collecting test modules so neither path can reach a real framework.
from netdnsmonitor import credentials, user_notify  # noqa: E402


def _memory_keychain(*args, **kwargs):
    return _MemoryKeychain()


for _credential_name in credentials.NAMES:
    os.environ.pop(_credential_name, None)
credentials.make_keychain_backend = _memory_keychain
credentials.CredentialStore.__init__.__defaults__ = (None, _memory_keychain)
user_notify.load_backend = lambda: None
user_notify._main_bundle = lambda: (None, None)
user_notify.post.__defaults__ = (user_notify.load_backend, user_notify._main_bundle)
user_notify.has_app_bundle.__defaults__ = (user_notify._main_bundle,)


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
    from netdnsmonitor.credentials import NAMES

    for name in NAMES:
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

    The privilege functions and `make_log_reader` are patched on their own modules.
    The app captures the privilege providers before scheduling the worker and the
    log reader at construction, so delayed workers retain the fakes after fixture
    teardown. `make_log_watcher` is patched where `netdnsmonitor.app` bound it,
    which touches nothing else. The privilege defaults describe an ungranted
    machine whose interfaces were not read -- the same machine
    `make_repair_executor` assumes when given no probes. A test that needs other
    answers patches over these, as test_app_privilege_wiring.py does.

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
