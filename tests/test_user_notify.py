"""UserNotifications delivery, with the framework and the bundle injected.

Nothing here touches Notification Centre: the backend is a fake and the bundle
probe is a lambda. What these cannot prove is that macOS draws a banner from the
signed app -- that needs the GUI session and is the owner's manual check.
"""

import pytest

from netdnsmonitor import user_notify

APP_BUNDLE = ("com.example.netdnsmonitor", "/Applications/Net-DNS-Monitor.app")


@pytest.fixture(autouse=True)
def fresh_state():
    user_notify._reset_for_tests()
    yield
    user_notify._reset_for_tests()


class FakeBackend:
    """Holds the authorisation handler so a test decides when and how it answers."""

    def __init__(self, deliver_error=None, raise_on_authorize=None):
        self.auth_handler = None
        self.auth_requests = 0
        self.delivered = []
        self.deliver_error = deliver_error
        self.raise_on_authorize = raise_on_authorize

    def request_authorization(self, handler):
        self.auth_requests += 1
        if self.raise_on_authorize:
            raise self.raise_on_authorize
        self.auth_handler = handler

    def deliver(self, title, subtitle, message, identifier, handler):
        self.delivered.append((title, subtitle, message, identifier))
        handler(self.deliver_error)


def post(backend, bundle=APP_BUNDLE, title="T", subtitle="S", message="net down"):
    return user_notify.post(
        title, subtitle, message, backend_fn=lambda: backend, bundle_fn=lambda: bundle
    )


def test_granted_authorization_sends_the_held_banner():
    backend = FakeBackend()
    assert post(backend) == user_notify.STATUS_QUEUED
    # Nothing is sent until the user answers.
    assert backend.delivered == []
    backend.auth_handler(True, None)
    assert [d[:3] for d in backend.delivered] == [("T", "S", "net down")]
    assert backend.delivered[0][3]  # a request identifier


def test_a_second_post_after_a_grant_sends_without_asking_again():
    backend = FakeBackend()
    post(backend)
    backend.auth_handler(True, None)
    assert post(backend, message="again") == user_notify.STATUS_QUEUED
    assert backend.auth_requests == 1
    assert [d[2] for d in backend.delivered] == ["net down", "again"]
    assert backend.delivered[0][3] != backend.delivered[1][3]


def test_posts_while_the_answer_is_pending_are_held_not_dropped_or_duplicated_requests():
    backend = FakeBackend()
    post(backend, message="one")
    assert post(backend, message="two") == user_notify.STATUS_QUEUED
    assert backend.auth_requests == 1
    backend.auth_handler(True, None)
    assert [d[2] for d in backend.delivered] == ["one", "two"]


def test_denied_authorization_sends_nothing_and_later_posts_report_denied(capsys):
    backend = FakeBackend()
    assert post(backend) == user_notify.STATUS_QUEUED  # handed over, answer still unknown
    backend.auth_handler(False, None)
    assert backend.delivered == []
    assert "denied" in user_notify.last_outcome()
    # From here on the answer is known, so the status is never "queued".
    assert post(backend, message="later") == user_notify.STATUS_DENIED
    assert backend.delivered == []
    assert "denied" in capsys.readouterr().err


def test_authorization_error_without_a_grant_counts_as_denied():
    backend = FakeBackend()
    post(backend)
    backend.auth_handler(False, "error")
    assert post(backend) == user_notify.STATUS_DENIED


def test_unavailable_framework_is_a_status_not_an_exception():
    status = user_notify.post("T", "S", "m", backend_fn=lambda: None, bundle_fn=lambda: APP_BUNDLE)
    assert status == user_notify.STATUS_UNAVAILABLE


@pytest.mark.parametrize(
    "bundle",
    [
        (None, None),
        ("org.python.python", "/opt/homebrew/bin"),  # identifier but not an .app
        # Measured under Homebrew python3: the interpreter's own launcher bundle.
        (
            "org.python.python",
            "/opt/homebrew/Cellar/python@3.14/3.14.8/Frameworks/Python.framework/Versions/3.14/Resources/Python.app",
        ),
        (None, "/Applications/Net-DNS-Monitor.app"),  # .app but no identifier
        ("", "/Applications/Net-DNS-Monitor.app"),
    ],
)
def test_no_app_bundle_never_loads_or_calls_the_framework(bundle):
    def backend_fn():
        raise AssertionError("the framework must not be loaded without an app bundle")

    status = user_notify.post("T", "S", "m", backend_fn=backend_fn, bundle_fn=lambda: bundle)
    assert status == user_notify.STATUS_NO_BUNDLE


def test_a_bundle_probe_that_raises_means_no_bundle():
    def exploding():
        raise RuntimeError("no NSBundle")

    status = user_notify.post("T", "S", "m", backend_fn=lambda: FakeBackend(), bundle_fn=exploding)
    assert status == user_notify.STATUS_NO_BUNDLE


def test_backend_exception_becomes_a_class_name_never_the_message(capsys):
    backend = FakeBackend(raise_on_authorize=ValueError("webhook https://secret.example/token"))
    status = post(backend)
    assert status == "failed:ValueError"
    assert "secret.example" not in status
    assert "secret.example" not in capsys.readouterr().err


def test_a_failed_authorization_request_does_not_wedge_later_alerts():
    broken = FakeBackend(raise_on_authorize=RuntimeError())
    assert post(broken) == "failed:RuntimeError"
    healthy = FakeBackend()
    assert post(healthy) == user_notify.STATUS_QUEUED
    healthy.auth_handler(True, None)
    assert len(healthy.delivered) == 1


def test_backend_factory_that_raises_is_a_class_name_status():
    def exploding():
        raise OSError("dlopen failed")

    status = user_notify.post("T", "S", "m", backend_fn=exploding, bundle_fn=lambda: APP_BUNDLE)
    assert status == "failed:OSError"


def test_delivery_error_is_recorded_without_its_text():
    backend = FakeBackend(deliver_error="error")
    post(backend)
    backend.auth_handler(True, None)
    assert user_notify.last_outcome() == "delivery request failed"


def test_an_exception_while_sending_after_a_grant_stays_off_the_framework_thread():
    class ExplodingDeliver(FakeBackend):
        def deliver(self, *args):
            raise KeyError("detail that must not leak")

    backend = ExplodingDeliver()
    post(backend)
    backend.auth_handler(True, None)  # must not raise
    assert user_notify.last_outcome() == "delivery failed (KeyError)"


def test_has_app_bundle_requires_an_app_path_and_identifier():
    assert user_notify.has_app_bundle(lambda: APP_BUNDLE)
    assert not user_notify.has_app_bundle(lambda: ("com.example", "/usr/local/bin"))


def test_the_test_suite_stub_keeps_the_real_loader_unreachable():
    """conftest swaps the loader and bundle probe; this proves the swap is live."""
    assert user_notify.load_backend() is None
    assert user_notify._main_bundle() == (None, None)
