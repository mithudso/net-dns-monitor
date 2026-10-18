"""Raise the user's attention when the ping heartbeat fails: bounce the Dock
tile and post a notification saying the network failed.

Three deliberate choices here.

**Dock bounce, not a modal alert.** `rumps.alert` puts up an NSAlert, which is
modal and blocks the run loop until someone dismisses it. During an outage with
the user away from the machine that would freeze all three timers -- the
incident poll, the resolution batch, and this heartbeat -- for as long as the
dialog sits there. So the attention-getter is
`NSApplication.requestUserAttention_`, which is what "bounce the icon"
means in AppKit terms and does not block anything.

`NSCriticalRequest` (verified to be 0 on macOS 26.4) bounces until the app is
activated or the request is cancelled, as opposed to `NSInformationalRequest`
which bounces once for a second. Critical is the right reading of the request,
but it means a two-second Wi-Fi blip would otherwise leave the Dock bouncing
forever, so `stop_bouncing` cancels the request on recovery. The user still
gets the notification as the durable record of what happened.

**Failures are logged, not swallowed.** dock_icon.py's `except Exception: pass`
is right for a cosmetic tint, but this module *is* the feature -- a silent
no-op here (a renamed selector, a notification API that has finally been
removed) would look exactly like a network that never failed. Everything is
still caught, because every caller is on the main run loop -- the ping drain
in `App` and the "Test network alert" menu callback -- and an exception that
escapes there kills the rumps timer for the rest of the session. It goes to
stderr instead, which the LaunchAgent redirects to
~/Library/Logs/net-dns-monitor.launchd.log.

**Notification path.** `user_notify.post` goes first: UserNotifications
(`UNUserNotificationCenter`), which replaced the deprecated
`NSUserNotificationCenter` that `rumps.notification` wraps. Its status is
"handed to the framework", never "delivered" -- see user_notify.py. A `denied`
status is final: the user refused notifications for this app, so the alert is
logged as not delivered and osascript is not used to go around that choice.
`no-bundle` (plain `python3`), `unavailable` and `failed:*` fall through to
osascript outside the sandboxed build. Whether a banner is actually drawn
depends on notification authorisation for the bundle; `Test network alert` in
the menu is the manual check.
"""

import subprocess
import sys
import traceback
from typing import Callable, Mapping, Optional

from . import distribution, user_notify

APP_NAME = "Net-DNS-Monitor"
OSASCRIPT_BIN = "/usr/bin/osascript"

RunFn = Callable[..., object]
AppFn = Callable[[], object]
PostFn = Callable[[str, str, str], str]

# Every request id bounce_dock has been handed and not yet cancelled. A list,
# not one slot: with ping_alert_repeat_seconds set the alert re-fires during an
# outage, and each call is a separate critical request that AppKit keeps
# bouncing until it is cancelled by its own id.
_attention_requests: list[int] = []


def _shared_application():
    import AppKit

    return AppKit.NSApplication.sharedApplication()


def _log(message: str) -> None:
    print(f"[alert] {message}", file=sys.stderr, flush=True)


def bounce_dock(app_fn: AppFn = _shared_application) -> None:
    """Bounce the Dock tile until the app is activated or the request is cancelled."""
    try:
        import AppKit

        _attention_requests.append(app_fn().requestUserAttention_(AppKit.NSCriticalRequest))
    except Exception:  # noqa: BLE001 - must not kill the rumps timer
        traceback.print_exc()


def stop_bouncing(app_fn: AppFn = _shared_application) -> None:
    """Cancel every outstanding bounce, so a transient blip doesn't leave the
    Dock bouncing indefinitely after the network comes back.
    """
    while _attention_requests:
        request_id = _attention_requests.pop()
        try:
            app_fn().cancelUserAttentionRequest_(request_id)
        except Exception:  # noqa: BLE001 - must not kill the rumps timer
            traceback.print_exc()


def notify(
    message: str,
    title: str = APP_NAME,
    subtitle: str = "",
    run_fn: RunFn = subprocess.run,
    env: Optional[Mapping[str, str]] = None,
    post_fn: Optional[PostFn] = None,
) -> str:
    """Post a banner and return the status code, never raising.

    `post_fn` is resolved at call time so the test fixture's stand-in on
    `user_notify.post` is what runs by default.
    """
    try:
        status = (post_fn or user_notify.post)(title, subtitle, message)
    except Exception as exc:  # noqa: BLE001 - a status, never a message
        status = f"failed:{type(exc).__name__}"
    if status == user_notify.STATUS_QUEUED:
        return status
    if status == user_notify.STATUS_DENIED:
        _log("notification not delivered: authorization denied")
        return status
    _log(f"notification not posted through UserNotifications: {status}")

    # The sandboxed build stops here. osascript sends Apple Events, which that
    # build holds no entitlement for, and spawning a scripting host is a surface
    # App Review would ask about -- app.py avoids it for URLs for the same reason.
    if distribution.detect(env).is_app_store:
        return status

    # Reached only when UserNotifications could not be used. The banner then
    # comes from the scripting host rather than this app, which is why it is
    # the fallback.
    try:
        script = f"display notification {_as_applescript_string(message)} with title {_as_applescript_string(title)}"
        result = run_fn(
            [OSASCRIPT_BIN, "-e", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            # This blocks the main run loop, so the timeout is how long every
            # timer in the app stalls if osascript hangs. A banner is not worth
            # more than a few seconds of a frozen monitor.
            timeout=3,
        )
        # Exit code only: stderr can echo the message text.
        returncode = getattr(result, "returncode", 0)
        if returncode:
            print(f"osascript fallback exited {returncode}", file=sys.stderr)
    except (subprocess.SubprocessError, OSError, UnicodeError):
        traceback.print_exc()
    return status


def _as_applescript_string(value: str) -> str:
    """Quote a Python string as an AppleScript literal.

    The message carries ping's own error text (`ping: cannot resolve ...`), so
    an embedded quote or backslash would otherwise produce a syntax error and
    lose the whole notification.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def network_failed(
    host: str,
    error: Optional[str] = None,
    app_fn: AppFn = _shared_application,
    run_fn: RunFn = subprocess.run,
) -> None:
    """The alert itself: bounce, notify, and leave a line in the log.

    The log line is what makes this verifiable after the fact -- whether macOS
    drew the banner is not observable from here, but whether the app decided to
    alert is.
    """
    message = f"Ping to {host} failed"
    if error:
        message += f" -- {error}"
    _log(message)
    bounce_dock(app_fn=app_fn)
    notify(message, title=f"{APP_NAME}: network failed", run_fn=run_fn)


def network_recovered(host: str, app_fn: AppFn = _shared_application) -> None:
    """Stop the bouncing once pings are answered again. Deliberately silent
    otherwise: a recovery banner for every dropped packet would be noise.
    """
    _log(f"Ping to {host} recovered")
    stop_bouncing(app_fn=app_fn)


def _reset_for_tests() -> None:
    _attention_requests.clear()
