"""Post a banner through UserNotifications (`UNUserNotificationCenter`).

`rumps.notification` goes through `NSUserNotificationCenter`, deprecated since
macOS 11 and the thing a reviewer can cite under Guideline 2.4.5(viii). This
module replaces it. `requirements.txt` stays at four packages, so there is no
`pyobjc-framework-UserNotifications`: the framework is loaded with
`objc.loadBundle` from the system path, which `pyobjc-framework-Cocoa`'s `objc`
already provides.

**The status is what was handed over, never "delivered".** `post` returns one
of the `STATUS_*` codes or `failed:<ExceptionClassName>`:

- `queued` -- the request reached UserNotifications, or is waiting for the
  authorisation answer and will be sent if it is granted. Whether macOS then
  draws a banner (Focus mode, per-app settings) is not observable here.
- `denied` -- the user refused notifications for this app. Nothing is sent, and
  the caller must not report the alert as delivered.
- `no-bundle` -- the process is not running from an `.app` bundle with a bundle
  identifier. `UNUserNotificationCenter.currentNotificationCenter()` raises or
  crashes the process in that case (plain `python3`, the CLI, pytest), so it is
  never called.
- `unavailable` -- the framework or its classes could not be loaded.

**Authorisation is asynchronous.** `requestAuthorizationWithOptions:` answers on
a background queue, and `post` runs on the main run loop inside a tick, so it
cannot wait. The first call starts the request and holds its notification; the
completion handler sends it on a grant and records `denied` otherwise. Later
calls read the recorded answer.

Every side effect enters as a parameter with a real default (`backend_fn`,
`bundle_fn`), so each path is testable offline. Nothing here raises, and no
status carries an exception message.
"""

import sys
import threading
import uuid
from typing import Callable, Optional, Protocol

STATUS_QUEUED = "queued"
STATUS_DENIED = "denied"
STATUS_NO_BUNDLE = "no-bundle"
STATUS_UNAVAILABLE = "unavailable"

FRAMEWORK_PATH = "/System/Library/Frameworks/UserNotifications.framework"
# UNAuthorizationOptionAlert | UNAuthorizationOptionSound (4 | 2).
AUTH_OPTIONS = 4 | 2

_AUTH_UNKNOWN = "unknown"
_AUTH_PENDING = "pending"
_AUTH_GRANTED = "granted"
_AUTH_DENIED = "denied"


class Backend(Protocol):
    """The two calls this module needs from UserNotifications."""

    def request_authorization(self, handler: Callable[[bool, Optional[str]], None]) -> None: ...

    def deliver(
        self,
        title: str,
        subtitle: str,
        message: str,
        identifier: str,
        handler: Callable[[Optional[str]], None],
    ) -> None: ...


BackendFn = Callable[[], Optional[Backend]]
# (bundle identifier, bundle path) of the running process.
BundleFn = Callable[[], tuple[Optional[str], Optional[str]]]

_lock = threading.Lock()
_auth_state = _AUTH_UNKNOWN
_held: list[tuple[str, str, str]] = []
_last_outcome = ""


def _log(message: str) -> None:
    print(f"[user_notify] {message}", file=sys.stderr, flush=True)


def _main_bundle() -> tuple[Optional[str], Optional[str]]:
    import AppKit

    bundle = AppKit.NSBundle.mainBundle()
    identifier = bundle.bundleIdentifier()
    path = bundle.bundlePath()
    return (str(identifier) if identifier else None, str(path) if path else None)


def has_app_bundle(bundle_fn: BundleFn = _main_bundle) -> bool:
    """True only for an `.app` bundle with an identifier.

    Measured: under a Homebrew framework `python3`, `NSBundle.mainBundle()`
    reports `org.python.python` at `.../Python.framework/.../Python.app`. That
    passes an identifier-and-`.app` test, yet it is the interpreter's launcher,
    not this application: banners would carry Python's identity and the
    authorisation prompt would be for Python. It is treated as no bundle.
    """
    try:
        identifier, path = bundle_fn()
    except Exception:  # noqa: BLE001 - unknown means no bundle
        return False
    if not identifier or not path or not str(path).endswith(".app"):
        return False
    return not (str(identifier).startswith("org.python.") or "/Python.framework/" in str(path))


class _PyObjCBackend:
    """The real UserNotifications calls. Built only inside an app bundle."""

    def __init__(self, center, content_cls, request_cls) -> None:
        self._center = center
        self._content_cls = content_cls
        self._request_cls = request_cls

    def request_authorization(self, handler) -> None:
        def completion(granted, error):
            # The error is an NSError; only its presence is reported.
            handler(bool(granted), "error" if error is not None else None)

        self._center.requestAuthorizationWithOptions_completionHandler_(AUTH_OPTIONS, completion)

    def deliver(self, title, subtitle, message, identifier, handler) -> None:
        content = self._content_cls.alloc().init()
        content.setTitle_(title)
        content.setSubtitle_(subtitle)
        content.setBody_(message)
        request = self._request_cls.requestWithIdentifier_content_trigger_(
            identifier, content, None
        )

        def completion(error):
            handler("error" if error is not None else None)

        self._center.addNotificationRequest_withCompletionHandler_(request, completion)


def load_backend() -> Optional[Backend]:
    """Load UserNotifications from the system path, or None when it cannot be.

    The completion-handler block signatures are registered by hand: loading a
    framework with `objc.loadBundle` brings no PyObjC metadata, so without it a
    Python callable cannot be turned into the block the selector expects.
    """
    try:
        import objc

        namespace: dict = {}
        objc.loadBundle("UserNotifications", namespace, bundle_path=FRAMEWORK_PATH)
        center_cls = objc.lookUpClass("UNUserNotificationCenter")
        content_cls = objc.lookUpClass("UNMutableNotificationContent")
        request_cls = objc.lookUpClass("UNNotificationRequest")
        objc.registerMetaDataForSelector(
            b"UNUserNotificationCenter",
            b"requestAuthorizationWithOptions:completionHandler:",
            {
                "arguments": {
                    3: {
                        "callable": {
                            "retval": {"type": b"v"},
                            "arguments": {0: {"type": b"^v"}, 1: {"type": b"Z"}, 2: {"type": b"@"}},
                        }
                    }
                }
            },
        )
        objc.registerMetaDataForSelector(
            b"UNUserNotificationCenter",
            b"addNotificationRequest:withCompletionHandler:",
            {
                "arguments": {
                    3: {
                        "callable": {
                            "retval": {"type": b"v"},
                            "arguments": {0: {"type": b"^v"}, 1: {"type": b"@"}},
                        }
                    }
                }
            },
        )
        return _PyObjCBackend(center_cls.currentNotificationCenter(), content_cls, request_cls)
    except Exception as exc:  # noqa: BLE001 - unavailable is a status, not a crash
        _log(f"UserNotifications unavailable ({type(exc).__name__})")
        return None


def _record(outcome: str) -> None:
    global _last_outcome
    _last_outcome = outcome
    _log(outcome)


def last_outcome() -> str:
    """The most recent asynchronous result, for the log and the owner's check."""
    return _last_outcome


def _send(backend: Backend, title: str, subtitle: str, message: str) -> None:
    def done(error: Optional[str]) -> None:
        if error:
            _record("delivery request failed")

    backend.deliver(title, subtitle, message, str(uuid.uuid4()), done)


def post(
    title: str,
    subtitle: str,
    message: str,
    backend_fn: BackendFn = load_backend,
    bundle_fn: BundleFn = _main_bundle,
) -> str:
    """Hand a banner to UserNotifications and return a status code. Never raises."""
    global _auth_state
    try:
        if not has_app_bundle(bundle_fn):
            return STATUS_NO_BUNDLE
        with _lock:
            if _auth_state == _AUTH_DENIED:
                return STATUS_DENIED
            if _auth_state == _AUTH_PENDING:
                _held.append((title, subtitle, message))
                return STATUS_QUEUED
            state = _auth_state

        backend = backend_fn()
        if backend is None:
            return STATUS_UNAVAILABLE

        if state == _AUTH_GRANTED:
            _send(backend, title, subtitle, message)
            return STATUS_QUEUED

        with _lock:
            _auth_state = _AUTH_PENDING
            _held.append((title, subtitle, message))

        def answered(granted: bool, error: Optional[str]) -> None:
            global _auth_state
            with _lock:
                _auth_state = _AUTH_GRANTED if granted else _AUTH_DENIED
                held = list(_held)
                _held.clear()
            if not granted:
                _record("notification authorization denied" + (" (error)" if error else ""))
                return
            try:
                for held_title, held_subtitle, held_message in held:
                    _send(backend, held_title, held_subtitle, held_message)
            except Exception as exc:  # noqa: BLE001 - runs on a framework thread
                _record(f"delivery failed ({type(exc).__name__})")

        try:
            backend.request_authorization(answered)
        except Exception:
            # Left pending forever would swallow every later alert silently.
            with _lock:
                _auth_state = _AUTH_UNKNOWN
                _held.clear()
            raise
        return STATUS_QUEUED
    except Exception as exc:  # noqa: BLE001 - nothing may raise out of a tick
        return f"failed:{type(exc).__name__}"


def _reset_for_tests() -> None:
    global _auth_state, _last_outcome
    with _lock:
        _auth_state = _AUTH_UNKNOWN
        _held.clear()
    _last_outcome = ""
