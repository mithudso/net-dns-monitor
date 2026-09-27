"""Explicit permission before any incident data goes to Anthropic.

App Review Guideline 5.1.2(i), as amended in November 2025: "You must clearly
disclose where personal data will be shared with third parties, including with
third-party AI, and obtain explicit permission before doing so." The escalation
bundle carries probe results keyed by hostname, unified-log excerpts and the
classification, and `sensitive_strings` is empty by default, so it counts.

Consent lives in its own file in the app's support directory rather than in
config.yaml. The config file is hand-edited, copied between machines and
rewritten by the settings window. A permission has to be given by the person at
this Mac, inside the app, after reading what is sent.

CONSENT_VERSION is part of the record. Guideline 5.1.2(ii) says data collected
for one purpose may not be repurposed without further consent, so when the
contents of the bundle change, bump the version and every earlier grant stops
counting until the user agrees again.
"""

import json
import os
from datetime import datetime, timezone
from typing import Callable, Optional

from netdnsmonitor.report_storage import _atomic_write

CONSENT_VERSION = 1

DEFAULT_PATH = "~/Library/Application Support/net-dns-monitor/ai-consent.json"

RECIPIENT = "Anthropic (the Claude API)"

DISCLOSURE = (
    "When the offline troubleshooting ladder cannot resolve a network or DNS incident, "
    "Net-DNS-Monitor can ask Claude, an AI model run by Anthropic, for a diagnosis.\n\n"
    "If you allow this, each such incident sends Anthropic:\n"
    "  - the incident classification (for example 'dns' or 'network')\n"
    "  - the probe results, including the names of the domains that were checked\n"
    "  - the outcome text of each troubleshooting step\n"
    "  - recent network-related lines from the macOS system log, when this build can read "
    "them (the Mac App Store build cannot, and sends a note saying so instead)\n\n"
    "Strings you list under 'sensitive_strings' in Settings are replaced with [REDACTED] "
    "before sending. Nothing is sent while the network is healthy, and nothing is sent "
    "until you allow it here. Anthropic processes the request under its own privacy "
    "policy. You can withdraw permission at any time from the app menu."
)


class ConsentStore:
    def __init__(
        self,
        path: str = DEFAULT_PATH,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self.path = os.path.expanduser(path)
        self.clock = clock

    def _read(self) -> Optional[dict]:
        try:
            with open(self.path, encoding="utf-8") as handle:
                record = json.load(handle)
        except (OSError, ValueError):
            # Unreadable or corrupt means no recorded permission. Treating it as
            # granted would send data on the strength of a file we cannot read.
            return None
        return record if isinstance(record, dict) else None

    def granted(self) -> bool:
        record = self._read()
        return bool(
            record
            and record.get("granted") is True
            and record.get("version") == CONSENT_VERSION
            and record.get("recipient") == RECIPIENT
        )

    def grant(self) -> str:
        return self._write(True)

    def revoke(self) -> str:
        return self._write(False)

    def _write(self, granted: bool) -> str:
        record = {
            "granted": granted,
            "version": CONSENT_VERSION,
            "recipient": RECIPIENT,
            "at": self.clock().isoformat(),
        }
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            _atomic_write(self.path, json.dumps(record, indent=2))
        except OSError as exc:
            return f"failed: could not record the choice ({type(exc).__name__})"
        return "ok: permission granted" if granted else "ok: permission withdrawn"


def gate_escalator(escalator: Callable[[dict], dict], granted_fn: Callable[[], bool]):
    """Wrap an escalator so it sends nothing without a current grant.

    The check runs on every call, not once at startup, so withdrawing
    permission takes effect for the very next incident.
    """

    def gated(bundle: dict) -> dict:
        if not granted_fn():
            return {
                "error": "skipped: permission to send incident data to Anthropic has not been "
                "given in this app"
            }
        return escalator(bundle)

    return gated
