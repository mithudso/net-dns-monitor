"""Push an incident notification to Slack and/or email once a report exists.

Both channels are *outbound*, so the same rule that governs LLM escalation
applies: only redacted, low-detail material leaves the machine. The full
probe results and log excerpts stay in the on-disk report -- a Slack message
is a pointer to that artifact, not a copy of it.

Both notifiers take an injected transport so tests never open a socket, and
neither ever raises: a delivery failure returns {"error": ...} so the report
still gets written and the menu bar keeps ticking. Timeouts are short and
mandatory -- this code runs on the rumps main thread at the exact moment the
network is known to be broken, and a blocking send would freeze the UI
during the very incident it is reporting.

Secrets (the Slack webhook URL, the SMTP password) come from the environment,
never from config.yaml, and are never echoed into an error string: urllib's
HTTPError/URLError text can embed the full request URL, which for a webhook
*is* the credential.
"""

import contextlib
import http.client
import json
import smtplib
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
        f"Resolved by local repair: {report.get('resolved')}",
        f"Summary: {report.get('summary')}",
    ]
    repair_outcome = report.get("repair_outcome")
    if repair_outcome:
        lines.append(f"Repair outcome: {repair_outcome}")
    escalation = report.get("escalation") or {}
    analysis = escalation.get("analysis") if isinstance(escalation, dict) else None
    if analysis:
        lines.append(f"Claude analysis: {analysis}")
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
        # Bounded: the caller only ever looks at the first few bytes of the
        # body, and an endpoint that drips an endless response would otherwise
        # hold this worker (and the memory) for as long as it liked.
        return response.status, response.read(65536).decode("utf-8", "replace")


def make_slack_notifier(
    webhook_url: str,
    post_fn: Callable[[str, bytes, float], tuple[int, str]] = _post_json,
    timeout: float = DEFAULT_TIMEOUT,
) -> Callable[[str], dict]:
    # The URL is the credential. Over http:// it would cross the network in
    # cleartext, and urlopen honours file:// and ftp:// just as readily -- so
    # anything but https is refused up front, as data, before a single post.
    if not webhook_url.startswith("https://"):
        return lambda _text: {"channel": "slack", "error": "webhook URL is not https"}

    def notify(text: str) -> dict:
        payload = json.dumps({"text": text}).encode("utf-8")
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
        message = EmailMessage()
        message["Subject"] = "Net/DNS incident detected"
        message["From"] = sender
        message["To"] = ", ".join(recipients)
        message.set_content(text)

        # login() over a plain connection puts SMTP_PASSWORD on the wire in
        # cleartext. Refused before connecting, so no socket is opened either.
        if username and password and not use_starttls:
            return {
                "channel": "email",
                "error": "refusing to send SMTP credentials without STARTTLS",
            }

        factory = smtp_factory or smtplib.SMTP
        try:
            client = factory(host, port, timeout=timeout)
        except (OSError, smtplib.SMTPException):
            return {"channel": "email", "error": f"SMTP connect to {host}:{port} failed"}
        try:
            if use_starttls:
                client.starttls()
            if username and password:
                client.login(username, password)
            # send_message raises only when the server refused EVERY recipient;
            # a partial refusal comes back as a dict of the refused addresses,
            # and swallowing it would report a delivery to people who never got
            # the message.
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
        delivered_to = [r for r in recipients if r not in refused]
        if not delivered_to:
            return {"channel": "email", "error": "SMTP refused every recipient"}
        # Addresses only: the server's refusal text is not copied out.
        return {
            "channel": "email",
            "delivered": True,
            "recipients": delivered_to,
            "refused": sorted(refused),
        }

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
