import http.client
import smtplib
import ssl
import urllib.error

import pytest

from netdnsmonitor.notifications import (
    format_notification,
    make_email_notifier,
    make_notifier,
    make_slack_notifier,
)

REPORT = {
    "classification": "dns",
    "started_at": "2026-08-05T12:00:00+00:00",
    "duration_seconds": 12.4,
    "resolved": False,
    "summary": "DNS-layer incident detected, unresolved after the ladder ran.",
    "repair_outcome": "flush_dns_cache: partial",
    "probe_results": {"domain_results": {"internal.corp.local": False}},
    "log_excerpts": ["mDNSResponder: query for internal.corp.local timed out"],
    "escalation": {"model": "claude-haiku-4-5-20251001", "analysis": "Resolver is down."},
}


def test_format_notification_includes_classification_summary_and_path():
    text = format_notification(REPORT, "/tmp/report.md")
    assert "dns" in text
    assert "unresolved" in text
    assert "/tmp/report.md" in text
    assert "Resolver is down." in text


def test_format_notification_omits_raw_probe_results_and_log_excerpts():
    text = format_notification(REPORT, "/tmp/report.md")
    assert "internal.corp.local" not in text
    assert "log_excerpts" not in text


def test_format_notification_without_a_report_path():
    text = format_notification({"classification": "network", "summary": "s"})
    assert "Full report" not in text


def test_format_notification_does_not_claim_a_repair_it_cannot_know_happened():
    """`resolved` is only bool(recheck_ok). An UNCLASSIFIED incident runs no
    ladder at all, and a blip that clears while every repair returned
    NEEDS_PRIVILEGE is also "resolved" -- neither was fixed by a local repair.
    """
    text = format_notification({"classification": "unclassified", "resolved": True})
    assert "by local repair" not in text
    assert "Healthy on recheck: True" in text


def test_format_notification_labels_the_claude_analysis_as_unverified():
    """The analysis is model output derived from local log lines that any
    process can write, so a reader must not take it as a verified diagnosis.
    """
    text = format_notification(REPORT)
    assert "Claude analysis (unverified, derived from local logs): Resolver is down." in text


def test_slack_notifier_escapes_slack_control_sequences():
    """Slack parses <!channel> and <url|label> in `text`; the Claude analysis
    flows into this text and is derived from untrusted log lines.
    """
    calls = []

    def post_fn(url, payload, timeout):
        calls.append(payload)
        return 200, "ok"

    make_slack_notifier("https://hooks.slack.test/x", post_fn=post_fn)(
        "<!channel> see <https://evil.test|report> & more"
    )
    payload = calls[0].decode("utf-8")
    assert "<!channel>" not in payload
    assert "&lt;!channel&gt;" in payload
    assert "&lt;https://evil.test|report&gt;" in payload
    assert "&amp; more" in payload


def test_slack_notifier_reports_delivered_only_on_200_and_body_ok():
    calls = []

    def post_fn(url, payload, timeout):
        calls.append((url, payload, timeout))
        return 200, "ok"

    notify = make_slack_notifier("https://hooks.slack.test/secret", post_fn=post_fn)
    assert notify("hello") == {"channel": "slack", "delivered": True}
    assert calls[0][0] == "https://hooks.slack.test/secret"
    assert b"hello" in calls[0][1]


def test_slack_notifier_treats_200_with_non_ok_body_as_failure():
    notify = make_slack_notifier(
        "https://hooks.slack.test/secret", post_fn=lambda *_: (200, "invalid_payload")
    )
    result = notify("hello")
    assert "error" in result
    assert result.get("delivered") is None


def test_slack_notifier_never_leaks_the_webhook_url_on_http_error():
    url = "https://hooks.slack.test/T000/B000/supersecrettoken"

    def post_fn(*_):
        raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)

    result = make_slack_notifier(url, post_fn=post_fn)("hello")
    assert "supersecrettoken" not in str(result)
    assert "403" in result["error"]


def test_slack_notifier_handles_unreachable_network_without_raising():
    def post_fn(*_):
        raise urllib.error.URLError("no route to host")

    result = make_slack_notifier("https://hooks.slack.test/x", post_fn=post_fn)("hello")
    assert result["error"] == "Slack webhook unreachable"


def test_slack_notifier_survives_a_truncated_response_body():
    def post_fn(*_):
        raise http.client.IncompleteRead(b"partial")

    result = make_slack_notifier("https://hooks.slack.test/x", post_fn=post_fn)("hello")
    assert result["error"] == "Slack webhook unreachable"


@pytest.mark.parametrize(
    "url", ["http://hooks.slack.test/secret", "file:///etc/passwd", "ftp://hooks.slack.test/x"]
)
def test_slack_notifier_refuses_a_webhook_url_that_is_not_https(url):
    """The webhook URL is the credential. Over http:// it crosses the network in
    cleartext, and urlopen would honour file:// and ftp:// just as readily.
    """
    calls = []

    def post_fn(*args):
        calls.append(args)
        return 200, "ok"

    result = make_slack_notifier(url, post_fn=post_fn)("hello")
    assert result["error"] == "webhook URL is not https"
    assert calls == []
    assert "secret" not in str(result)


class FakeSMTP:
    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.logged_in = None
        self.sent = []
        self.quit_called = False
        self.tls_context = None

    def starttls(self, *, context=None):
        self.started_tls = True
        self.tls_context = context

    def login(self, username, password):
        self.logged_in = (username, password)

    def send_message(self, message):
        self.sent.append(message)
        return {}

    def quit(self):
        self.quit_called = True


def test_email_notifier_sends_with_starttls_login_and_timeout():
    created = []

    def factory(host, port, timeout=None):
        client = FakeSMTP(host, port, timeout)
        created.append(client)
        return client

    notify = make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["it@example.com"],
        sender="mon@example.com",
        username="mon",
        password="pw",
        smtp_factory=factory,
        timeout=3.0,
    )
    result = notify("incident text")
    client = created[0]
    assert result["delivered"] is True
    assert client.started_tls is True
    assert client.logged_in == ("mon", "pw")
    assert client.timeout == 3.0
    assert client.quit_called is True
    assert client.sent[0]["To"] == "it@example.com"
    assert "incident text" in client.sent[0].get_content()


def test_email_notifier_starttls_verifies_the_server_certificate():
    """smtplib.starttls() with no context uses an unverified context, so a
    rogue Wi-Fi MITM could accept the login and read SMTP_PASSWORD.
    """
    created = []

    def factory(host, port, timeout=None):
        client = FakeSMTP(host, port, timeout)
        created.append(client)
        return client

    make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["it@example.com"],
        sender="mon@example.com",
        username="mon",
        password="pw",
        smtp_factory=factory,
    )("text")
    context = created[0].tls_context
    assert context is not None
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


def test_email_notifier_refuses_to_log_in_without_tls():
    created = []

    def factory(host, port, timeout=None):
        client = FakeSMTP(host, port, timeout)
        created.append(client)
        return client

    result = make_email_notifier(
        host="smtp.test",
        port=25,
        recipients=["it@example.com"],
        sender="mon@example.com",
        username="mon",
        password="supersecretpw",
        use_starttls=False,
        smtp_factory=factory,
    )("text")
    assert result == {"channel": "email", "error": "refusing SMTP login without TLS"}
    assert all(client.logged_in is None for client in created)
    assert all(not client.sent for client in created)


def test_email_notifier_sends_without_tls_when_no_credentials_are_configured():
    created = []

    def factory(host, port, timeout=None):
        client = FakeSMTP(host, port, timeout)
        created.append(client)
        return client

    result = make_email_notifier(
        host="smtp.test",
        port=25,
        recipients=["it@example.com"],
        sender="mon@example.com",
        use_starttls=False,
        smtp_factory=factory,
    )("text")
    assert result["delivered"] is True
    assert created[0].started_tls is False


def test_email_notifier_reports_recipients_the_server_refused():
    """send_message returns the refused recipients instead of raising when at
    least one was accepted; ignoring that reported a refused address delivered.
    """

    class PartialRefusalSMTP(FakeSMTP):
        def send_message(self, message):
            self.sent.append(message)
            return {"b@example.com": (550, b"no such user")}

    result = make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["a@example.com", "b@example.com"],
        sender="mon@example.com",
        smtp_factory=lambda h, p, timeout=None: PartialRefusalSMTP(h, p, timeout),
    )("text")
    assert result["delivered"] is True
    assert result["recipients"] == ["a@example.com"]
    assert result["refused"] == ["b@example.com"]


def test_email_notifier_skips_when_no_recipients_configured():
    notify = make_email_notifier(
        host="smtp.test", port=587, recipients=[], sender="mon@example.com"
    )
    assert "skipped" in notify("text")


def test_email_notifier_reports_connect_failure_without_raising():
    def factory(*_a, **_kw):
        raise OSError("connection refused")

    notify = make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["it@example.com"],
        sender="mon@example.com",
        smtp_factory=factory,
    )
    assert "error" in notify("text")


def test_email_notifier_never_leaks_the_password_on_auth_failure():
    class AuthFailSMTP(FakeSMTP):
        def login(self, username, password):
            raise smtplib.SMTPAuthenticationError(535, f"bad creds for {username}:{password}")

    notify = make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["it@example.com"],
        sender="mon@example.com",
        username="mon",
        password="supersecretpw",
        smtp_factory=lambda h, p, timeout=None: AuthFailSMTP(h, p, timeout),
    )
    result = notify("text")
    assert "supersecretpw" not in str(result)
    assert result["error"] == "SMTP authentication rejected"


def test_notifier_fans_out_and_one_failing_channel_does_not_stop_the_other():
    calls = []

    def ok_channel(text):
        calls.append("ok")
        return {"channel": "a", "delivered": True}

    def failing_channel(text):
        calls.append("fail")
        return {"channel": "b", "error": "boom"}

    results = make_notifier([failing_channel, ok_channel])("text")
    assert calls == ["fail", "ok"]
    assert results[0]["error"] == "boom"
    assert results[1]["delivered"] is True


def test_notifier_with_no_channels_is_a_noop():
    assert make_notifier([])("text") == []


def test_notifier_contains_a_channel_that_raises_instead_of_returning():
    def raising_channel(text):
        raise RuntimeError("secret-bearing message")

    results = make_notifier([raising_channel, lambda t: {"delivered": True}])("text")
    assert results[0] == {"error": "channel raised RuntimeError"}
    assert results[1]["delivered"] is True


def test_email_notifier_closes_the_socket_when_quit_itself_fails():
    class QuitFailsSMTP(FakeSMTP):
        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.closed = False

        def quit(self):
            raise smtplib.SMTPServerDisconnected("connection already gone")

        def close(self):
            self.closed = True

    created = []

    def factory(host, port, timeout=None):
        client = QuitFailsSMTP(host, port, timeout)
        created.append(client)
        return client

    notify = make_email_notifier(
        host="smtp.test",
        port=587,
        recipients=["it@example.com"],
        sender="mon@example.com",
        smtp_factory=factory,
    )
    assert notify("text")["delivered"] is True
    assert created[0].closed is True
