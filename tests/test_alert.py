"""The alert path. NSApplication is injected rather than faked out with a mock
library, matching how every other external effect in this project is tested.

The one thing these cannot prove is that macOS actually draws a notification
banner -- that depends on notification authorisation for the bundle and is not
observable from inside the process. What they do pin is that the app decides to
alert, bounces with the right request type, cancels on recovery, and never lets
an AppKit failure escape into the rumps timer that called it.
"""

import subprocess

import AppKit
import pytest

from netdnsmonitor import alert


class FakeApp:
    def __init__(self):
        self.attention_requests = []
        self.cancelled = []

    def requestUserAttention_(self, request_type):
        self.attention_requests.append(request_type)
        return 4242  # AppKit returns a request id

    def cancelUserAttentionRequest_(self, request_id):
        self.cancelled.append(request_id)


@pytest.fixture(autouse=True)
def _clean_module_state():
    alert._reset_for_tests()
    yield
    alert._reset_for_tests()


def test_bounce_uses_the_critical_request_so_it_keeps_bouncing():
    """NSInformationalRequest bounces once for a second and is easy to miss;
    the request was for the icon to bounce. Literal 0 on purpose -- reading
    AppKit.NSCriticalRequest here would pass even if the code used the wrong
    constant name and got None.
    """
    app = FakeApp()
    alert.bounce_dock(app_fn=lambda: app)
    assert app.attention_requests == [0]
    assert AppKit.NSCriticalRequest == 0


def test_recovery_cancels_the_outstanding_bounce():
    """Without this a two-second Wi-Fi blip leaves the Dock bouncing forever,
    because a critical request only stops on activation or cancellation.
    """
    app = FakeApp()
    alert.bounce_dock(app_fn=lambda: app)
    alert.stop_bouncing(app_fn=lambda: app)
    assert app.cancelled == [4242]


def test_recovery_with_no_outstanding_bounce_does_nothing():
    app = FakeApp()
    alert.stop_bouncing(app_fn=lambda: app)
    assert app.cancelled == []


def test_a_second_recovery_does_not_cancel_a_stale_request_id():
    """Cancelling an already-cancelled id is meaningless, and re-cancelling on
    every healthy tick would cancel the *next* outage's bounce.
    """
    app = FakeApp()
    alert.bounce_dock(app_fn=lambda: app)
    alert.stop_bouncing(app_fn=lambda: app)
    alert.stop_bouncing(app_fn=lambda: app)
    assert app.cancelled == [4242]


def test_a_new_outage_after_recovery_bounces_again():
    app = FakeApp()
    alert.bounce_dock(app_fn=lambda: app)
    alert.stop_bouncing(app_fn=lambda: app)
    alert.bounce_dock(app_fn=lambda: app)
    assert app.attention_requests == [0, 0]


def test_every_outstanding_bounce_is_cancelled_when_the_network_returns():
    """With `ping_alert_repeat_seconds` set, the alert re-fires while the outage
    lasts, and each `requestUserAttention_` is a separate request with its own
    id. Cancelling only the last one leaves the earlier critical requests
    bouncing the Dock forever after recovery.
    """

    class CountingApp(FakeApp):
        def requestUserAttention_(self, request_type):
            self.attention_requests.append(request_type)
            return len(self.attention_requests)

    app = CountingApp()
    alert.bounce_dock(app_fn=lambda: app)
    alert.bounce_dock(app_fn=lambda: app)
    alert.stop_bouncing(app_fn=lambda: app)
    assert sorted(app.cancelled) == [1, 2]


def test_an_appkit_failure_is_logged_not_raised(capsys):
    """This runs on the main run loop, from the ping drain and from a menu
    callback. An escaping exception kills the rumps timer for the rest of the
    session while the menu bar keeps showing the last good reading.
    """

    def boom():
        raise RuntimeError("NSApplication is unavailable")

    alert.bounce_dock(app_fn=boom)
    assert "NSApplication is unavailable" in capsys.readouterr().err


def test_network_failed_names_the_host_and_the_error(capsys):
    app = FakeApp()
    alert.network_failed(
        "8.8.8.8", error="no reply from 8.8.8.8", app_fn=lambda: app, run_fn=lambda *a, **k: None
    )
    err = capsys.readouterr().err
    assert "8.8.8.8" in err
    assert "failed" in err.lower()
    assert app.attention_requests == [0]


def test_network_failed_logs_even_without_an_error_string(capsys):
    app = FakeApp()
    alert.network_failed("8.8.8.8", error=None, app_fn=lambda: app, run_fn=lambda *a, **k: None)
    assert "8.8.8.8" in capsys.readouterr().err


def test_network_recovered_logs_and_cancels(capsys):
    app = FakeApp()
    alert.bounce_dock(app_fn=lambda: app)
    alert.network_recovered("8.8.8.8", app_fn=lambda: app)
    assert "recovered" in capsys.readouterr().err.lower()
    assert app.cancelled == [4242]


# --- notification fallback -------------------------------------------------


def test_osascript_fallback_runs_only_when_rumps_raises(monkeypatch, capsys):
    calls = []

    def exploding_notification(*args, **kwargs):
        raise RuntimeError("notification centre unavailable")

    monkeypatch.setattr("rumps.notification", exploding_notification)
    alert.notify("net down", run_fn=lambda args, **kwargs: calls.append(args))

    assert len(calls) == 1
    assert calls[0][0] == alert.OSASCRIPT_BIN
    assert "display notification" in calls[0][2]
    # The rumps failure has to leave a trace; otherwise a permanently broken
    # primary path is invisible.
    assert "notification centre unavailable" in capsys.readouterr().err


def test_no_osascript_when_rumps_succeeds(monkeypatch):
    calls = []
    monkeypatch.setattr("rumps.notification", lambda *a, **k: None)
    alert.notify("net down", run_fn=lambda args, **kwargs: calls.append(args))
    assert calls == []


def test_quotes_in_the_message_cannot_break_the_applescript(monkeypatch):
    """ping's own error text ends up in this message. An unescaped quote makes
    osascript fail to compile and the notification is lost silently.
    """
    calls = []
    monkeypatch.setattr("rumps.notification", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    alert.notify('say "hi" \\ bye', run_fn=lambda args, **kwargs: calls.append(args))
    script = calls[0][2]
    assert '\\"hi\\"' in script
    assert "\\\\" in script


def test_osascript_failure_is_logged_not_raised(monkeypatch, capsys):
    monkeypatch.setattr("rumps.notification", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))

    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    alert.notify("net down", run_fn=timing_out)
    assert "TimeoutExpired" in capsys.readouterr().err


def test_osascript_fallback_cannot_freeze_the_run_loop_for_long(monkeypatch):
    """The fallback runs on the main run loop, so its timeout is the longest
    every timer in the app can stall if osascript hangs.
    """
    calls = []
    monkeypatch.setattr("rumps.notification", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    alert.notify("net down", run_fn=lambda args, **kwargs: calls.append(kwargs))
    assert calls[0]["timeout"] <= 3


def test_osascript_uses_an_absolute_path(monkeypatch):
    calls = []
    monkeypatch.setattr("rumps.notification", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    alert.notify("net down", run_fn=lambda args, **kwargs: calls.append(args))
    assert calls[0][0].startswith("/")
