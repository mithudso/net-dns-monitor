"""Push an incident notification to Slack and/or email once a report exists.

Both channels are *outbound*, so the same rule that governs LLM escalation
applies: only redacted, low-detail material leaves the machine. The full
probe results and log excerpts stay in the on-disk report -- a Slack message
is a pointer to that artifact, not a copy of it.

Both notifiers take an injected transport so tests never open a socket, and
neither ever raises: a delivery failure returns {"error": ...} so the report
still gets written and the menu bar keeps ticking. Timeouts are short and
mandatory. app.py normally sends from a worker thread, not the rumps main
thread, but it falls back to sending inline when a thread cannot be started;
an unbounded send at the exact moment the network is known to be broken would
then freeze the UI during the very incident it is reporting.

Secrets (the Slack webhook URL, the SMTP password) come from the environment,
never from config.yaml, and are never echoed into an error string: urllib's
HTTPError/URLError text can embed the full request URL, which for a webhook
*is* the credential.
"""

import contextlib
import http.client
import json
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from typing import Callable, Optional

DEFAULT_TIMEOUT = 5.0


def format_notification(report: dict, report_path: Optional[str] = None) -> str:
    """One short, human-readable block. Deliberately omits probe_results and
    log_excerpts: those are unredacted by design because the report is local.
    """
    lines = [
        f"Net/DNS incident: {report.get('classification', 'unknown')}",
        f"Started: {report.get('started_at')}",
        f"Duration: {report.get('duration_seconds', 0):.0f}s",
        # `resolved` is only the recheck result. It is also True for an
        # UNCLASSIFIED incident, which runs no ladder, and for a blip that
        # cleared while every repair returned NEEDS_PRIVILEGE -- so it must not
        # be worded as a repair having worked.
        f"Healthy on recheck: {report.get('resolved')}",
        f"Summary: {report.get('summary')}",
    ]
    repair_outcome = report.get("repair_outcome")
    if repair_outcome:
        lines.append(f"Repair outcome: {repair_outcome}")
    escalation = report.get("escalation") or {}
    analysis = escalation.get("analysis") if isinstance(escalation, dict) else None
    if analysis:
        # Model output over log lines any local process can write: labelled so
        # nobody acts on it as a verified diagnosis.
        lines.append(f"Claude analysis (unverified, derived from local logs): {analysis}")
    if report_path:
        lines.append(f"Full report: {report_path}")
    return "\n".join(lines)


def _post_json(url: str, payload: bytes, timeout: float) -> tuple[int, str]:
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.status, response.read().decode("utf-8", "replace")


def make_slack_notifier(
    webhook_url: str,
    post_fn: Callable[[str, bytes, float], tuple[int, str]] = _post_json,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], dict]:
    def notify(text: str) -> dict:
        # Slack parses <!channel>, <@user> and <url|label> inside `text`, and
        # the Claude analysis in this text derives from untrusted log lines.
        # These three are the only characters Slack requires escaped.
        escaped = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        payload = json.dumps({"text": escaped}).encode("utf-8")
        try:
            status, body = post_fn(webhook_url, payload, timeout)
        except urllib.error.HTTPError as exc:
            # str(exc) can contain the webhook URL, which is the secret.
            return {"channel": "slack", "error": f"HTTP {exc.code} from Slack webhook"}
        except (
            urllib.error.URLError,
            # A truncated body on a degrading link raises IncompleteRead /
            # BadStatusLine, which are HTTPException and are NOT OSError.
            http.client.HTTPException,
            OSError,
            ValueError,
        ):
            return {"channel": "slack", "error": "Slack webhook unreachable"}
        # A 200 alone is not success: Slack answers a well-formed post with the
        # literal body "ok" and signals rejection in the body, not the status.
        if status == 200 and body.strip() == "ok":
            return {"channel": "slack", "delivered": True}
        return {
            "channel": "slack",
            "error": f"Slack webhook returned status {status} body {body.strip()[:80]!r}",
        }

    return notify


def make_email_notifier(
    host: str,
    port: int,
    recipients: list[str],
    sender: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    use_starttls: bool = True,
    smtp_factory: Optional[Callable[..., object]] = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], dict]:
    def notify(text: str) -> dict:
        if not recipients:
            return {"channel": "email", "skipped": "no recipients configured"}
        if username and password and not use_starttls:
            # Checked before connecting: AUTH over a cleartext session hands
            # SMTP_PASSWORD to anyone on the path, and this alert goes out over
            # whatever network the Mac is on, untrusted Wi-Fi included.
            return {"channel": "email", "error": "refusing SMTP login without TLS"}
        message = EmailMessage()
        message["Subject"] = "Net/DNS incident detected"
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message.set_content(text)

        factory = smtp_factory or smtplib.SMTP
        try:
            client = factory(host, port, timeout=timeout)
        except (OSError, smtplib.SMTPException):
            return {"channel": "email", "error": f"SMTP connect to {host}:{port} failed"}
        try:
            if use_starttls:
                # Without an explicit context smtplib uses an unverified one
                # (no hostname check, CERT_NONE), so a MITM could complete the
                # handshake and read the login that follows.
                client.starttls(context=ssl.create_default_context())
            if username and password:
                client.login(username, password)
            # send_message raises only when every recipient is refused; a
            # partial refusal comes back as a dict and is otherwise invisible.
            refused = client.send_message(message) or {}
        except smtplib.SMTPAuthenticationError:
            # Never echo the exception: it can carry the credential back.
            return {"channel": "email", "error": "SMTP authentication rejected"}
        except (OSError, smtplib.SMTPException) as exc:
            return {"channel": "email", "error": f"SMTP send failed ({type(exc).__name__})"}
        finally:
            try:
                client.quit()
            except Exception:  # noqa: BLE001 - closing a dead socket must not mask the result
                # quit() sends "QUIT" *before* closing, so on an already-dropped
                # connection it raises and never closes the socket -- a real fd
                # leak in a process that lives for weeks.
                # Suppressed deliberately: this is the fallback close, and a
                # failure here has nowhere useful to go.
                with contextlib.suppress(Exception):
                    client.close()
        result = {
            "channel": "email",
            "delivered": True,
            "recipients": [r for r in recipients if r not in refused],
        }
        if refused:
            result["refused"] = sorted(refused)
        return result

    return notify


def make_notifier(channels: list[Callable[[str], dict]]) -> Callable[[str], list[dict]]:
    """Fan one already-redacted text block out to every configured channel;
    one channel failing must not stop the others.
    """

    def notify(text: str) -> list[dict]:
        results = []
        for channel in channels:
            try:
                results.append(channel(text))
            except Exception as exc:  # noqa: BLE001 - one channel must never abort the fan-out
                # Belt and braces: each channel already converts its own
                # failures to data, so reaching here means an unforeseen
                # exception class. The type name is safe to surface; the
                # message could carry a URL or credential, so it is dropped.
                results.append({"error": f"channel raised {type(exc).__name__}"})
        return results

    return notify
