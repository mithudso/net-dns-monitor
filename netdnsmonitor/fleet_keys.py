"""The server's list of enrolled machines and the key each one signs with.

A machine authenticates as the name it was enrolled under, and only with the key
generated for that name. A report that claims another name fails the signature
check, so one compromised or misconfigured box cannot speak for the rest.
`revoke` ends a machine's access at once; enrolling the same name again after a
revoke is how a key is rotated.

**The key is a symmetric HMAC key, not an asymmetric key pair.** The project's
runtime dependencies are fixed at four (requirements.txt), and public-key
signatures are not in the standard library. The server therefore holds every
machine's key, so the registry file is as sensitive as the keys themselves:
written mode 0600, never printed except once when a machine is enrolled, and
never logged. A compromised server exposes the keys; a compromised machine
exposes only its own.

The file is re-read when it changes (checked at most once a second), so enrolling
or revoking a machine takes effect without restarting the server.

No sockets here.
"""

import json
import os
import secrets
import threading
import time
from typing import Optional

from netdnsmonitor import fleet_protocol as proto

KEY_BYTES = 32
RECHECK_SECONDS = 1.0


class EnrollmentError(ValueError):
    """An enrollment the registry refuses; the message says why."""


class KeyRegistry:
    def __init__(self, path: str, now_fn=time.monotonic):
        self.path = os.path.expanduser(path)
        self.now_fn = now_fn
        self._lock = threading.Lock()
        self._keys: dict[str, str] = {}
        self._mtime: Optional[float] = None
        self._checked_at = float("-inf")

    # --- reading -----------------------------------------------------------

    def _refresh(self) -> None:
        now = self.now_fn()
        if now - self._checked_at < RECHECK_SECONDS:
            return
        self._checked_at = now
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError:
            self._keys, self._mtime = {}, None
            return
        if mtime == self._mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, ValueError):
            # A half-written or damaged file must not log every machine out:
            # keep what was loaded last time and look again next check.
            return
        machines = raw.get("machines") if isinstance(raw, dict) else None
        self._keys = (
            {
                name: key
                for name, key in machines.items()
                if isinstance(name, str) and isinstance(key, str) and key
            }
            if isinstance(machines, dict)
            else {}
        )
        self._mtime = mtime

    def key_for(self, machine_id: str) -> Optional[str]:
        with self._lock:
            self._refresh()
            return self._keys.get(machine_id)

    def names(self) -> list[str]:
        with self._lock:
            self._checked_at = float("-inf")
            self._refresh()
            return sorted(self._keys)

    # --- changing ----------------------------------------------------------

    def enroll(self, name: str) -> str:
        """Create a key for `name` and return it. This is the only time it is shown."""
        if not name or proto.clean(name, 64) != name or not name.strip():
            raise EnrollmentError("a machine name must be 1 to 64 printable characters")
        with self._lock:
            self._checked_at = float("-inf")
            self._refresh()
            if name in self._keys:
                raise EnrollmentError(
                    f"{name!r} is already enrolled; revoke it first to rotate its key"
                )
            key = secrets.token_hex(KEY_BYTES)
            self._write({**self._keys, name: key})
            return key

    def revoke(self, name: str) -> bool:
        """Remove `name`. False if it was not enrolled."""
        with self._lock:
            self._checked_at = float("-inf")
            self._refresh()
            if name not in self._keys:
                return False
            self._write({k: v for k, v in self._keys.items() if k != name})
            return True

    def _write(self, keys: dict[str, str]) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        temporary = f"{self.path}.tmp"
        # Created 0600 from the start: writing then chmod-ing leaves a window in
        # which the keys are readable by other accounts.
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"machines": keys}, handle, indent=2, sort_keys=True)
        os.replace(temporary, self.path)
        self._keys = dict(keys)
        self._mtime = os.stat(self.path).st_mtime
