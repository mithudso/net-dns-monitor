"""The wire format between a reporting machine and the central fleet server.

Pure functions: no sockets, no clock of their own. `fleet_client.py` and
`fleet_server.py` do the talking and call in here, which is what lets the
signing, the replay window and the size cap be tested without opening a port.

**Messages**, all JSON in one UDP datagram:

    hello      a machine's heartbeat: "I am here, and my network is healthy/incident"
    incident   a declared incident: classification, evidence summary, steps run
    resolved   the network recovered: how long, and the steps that had run
    ack        server -> machine: "event <eid> is logged"

**Signed, because the server log is what an administrator trusts.** Every
message carries `sig`, an HMAC-SHA256 over the canonical JSON of the rest of
the message, keyed by that machine's own key (credential FLEET_MACHINE_KEY,
enrolled on the server by fleet_keys.py). The
signed `ts` is the moment of *sending*, not of the event: a report queued
through a long outage is re-signed when it is finally sent, so the replay
window below never refuses an honest late report. The event's own time travels
inside `data` as `occurred_at`.

The window is `MAX_SKEW_SECONDS` either side of the receiver's clock. A machine
with a wrong clock is therefore refused, loudly (the server counts refusals by
reason); an old captured datagram cannot be replayed beyond the window, and a
replay inside it is caught by the server's per-machine event-id memory.

**Not encrypted.** The payload is a hostname, a classification and the names
and outcomes of ladder steps. The signature stops forgery, not eavesdropping on
the local network. Outbound text is redacted with `sensitive_strings` by the
sender before it gets here (CLAUDE.md non-negotiable 6).

**Unsigned mode** exists for a first trial on a trusted network
(`fleet_allow_unsigned`). A signed message is always verified, even then.
"""

import hashlib
import hmac
import json
from collections.abc import Callable
from typing import Any, Optional

PROTOCOL = "ndm-fleet/1"
HELLO = "hello"
INCIDENT = "incident"
RESOLVED = "resolved"
ACK = "ack"
KINDS = (HELLO, INCIDENT, RESOLVED, ACK)
EVENT_KINDS = (HELLO, INCIDENT, RESOLVED)

# One datagram. Below a typical 1500-byte MTU with headers, so it is never
# fragmented; fragments are the first thing a lossy network drops.
MAX_SEND_BYTES = 1400
# What the server reads. Larger than anything the client sends, so a datagram
# over this is not ours and is dropped unparsed.
MAX_RECEIVE_BYTES = 4096
MAX_SKEW_SECONDS = 600

STATUS_HEALTHY = "healthy"
STATUS_INCIDENT = "incident"
STATUS_UNKNOWN = "unknown"

MAX_STEPS = 12
MAX_STEP_TEXT = 140
MAX_FIELD_TEXT = 200

# Why a datagram was refused. Counted by the server, never logged per packet:
# the port is reachable by anything on the network, and a log line per stray
# packet would hand a remote host control of the log file's size.
REFUSED_MALFORMED = "malformed"
REFUSED_UNSIGNED = "unsigned"
REFUSED_BAD_SIGNATURE = "bad_signature"
REFUSED_STALE = "clock_skew"
REFUSED_UNKNOWN_MACHINE = "unknown_machine"


def clean(value, limit: int = MAX_FIELD_TEXT) -> str:
    """Printable, bounded text. Newlines and escapes are dropped, not escaped."""
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    return "".join(ch for ch in value if ch.isprintable())[:limit]


def canonical(message: dict[str, Any]) -> bytes:
    return json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign(message: dict[str, Any], secret: str) -> str:
    unsigned = {key: value for key, value in message.items() if key != "sig"}
    return hmac.new(secret.encode("utf-8"), canonical(unsigned), hashlib.sha256).hexdigest()


def build_message(
    kind: str,
    machine_id: str,
    host: str,
    event_id: str,
    now: float,
    data: Optional[dict[str, Any]] = None,
    secret: Optional[str] = None,
) -> bytes:
    """Encode one message, signed when a secret is configured.

    Raises ValueError if the result cannot fit one datagram even after the steps
    are dropped, which would be a bug in the caller, not a network condition.
    """
    message: dict[str, Any] = {
        "proto": PROTOCOL,
        "t": kind,
        "id": clean(machine_id, 64),
        "host": clean(host, 100),
        "eid": clean(event_id, 64),
        "ts": int(now),
        "data": data or {},
    }
    payload = _encode(message, secret)
    if len(payload) > MAX_SEND_BYTES and "steps" in message["data"]:
        # Steps are the longest field. Say so rather than silently shortening.
        trimmed = dict(message["data"])
        trimmed["steps"] = []
        trimmed["steps_omitted"] = "too long for one datagram"
        message["data"] = trimmed
        payload = _encode(message, secret)
    if len(payload) > MAX_SEND_BYTES:
        raise ValueError("message does not fit in one datagram")
    return payload


def _encode(message: dict[str, Any], secret: Optional[str]) -> bytes:
    if secret:
        message["sig"] = sign(message, secret)
    return canonical(message)


def parse_message(
    payload: bytes,
    now: float,
    secret: Optional[str] = None,
    allow_unsigned: bool = False,
    key_for: Optional[Callable[[str], Optional[str]]] = None,
) -> tuple[Optional[dict[str, Any]], Optional[str]]:
    """(message, None) when accepted; (None, reason) when refused.

    `secret` is the one key to check against (the client verifying an ack).
    `key_for` looks the key up by the claimed machine id (the server), and takes
    precedence: one machine's key never verifies another machine's message.

    Refusal reasons are the REFUSED_* constants. Nothing in the message is ever
    used as a path, a command or an argument; strings are cleaned and bounded.
    """
    if not payload or len(payload) > MAX_RECEIVE_BYTES:
        return None, REFUSED_MALFORMED
    try:
        raw = json.loads(payload.decode("utf-8", errors="replace"))
    except ValueError:
        return None, REFUSED_MALFORMED
    if not isinstance(raw, dict) or raw.get("proto") != PROTOCOL or raw.get("t") not in KINDS:
        return None, REFUSED_MALFORMED
    ts = raw.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)):
        return None, REFUSED_MALFORMED

    signature = raw.get("sig")
    if key_for is not None:
        # The server: each machine signs with its own key, found by the name it
        # claims. A name with no key (never enrolled, or revoked) cannot be
        # verified at all, whatever else is true of the message.
        secret = key_for(clean(raw.get("id"), 64))
        if secret is None and isinstance(signature, str):
            return None, REFUSED_UNKNOWN_MACHINE
    if secret:
        if not isinstance(signature, str):
            if not allow_unsigned:
                return None, REFUSED_UNSIGNED
        elif not hmac.compare_digest(signature, sign(raw, secret)):
            return None, REFUSED_BAD_SIGNATURE
    elif not allow_unsigned:
        # No secret to check against, and unsigned is not allowed: nothing here
        # can be trusted, so nothing is accepted.
        return None, REFUSED_UNSIGNED
    if abs(now - ts) > MAX_SKEW_SECONDS:
        return None, REFUSED_STALE

    data = raw.get("data")
    return {
        "t": raw["t"],
        "id": clean(raw.get("id"), 64),
        "host": clean(raw.get("host"), 100),
        "eid": clean(raw.get("eid"), 64),
        "ts": ts,
        "data": _clean_data(data if isinstance(data, dict) else {}),
        "signed": bool(secret) and isinstance(signature, str),
    }, None


def _clean_data(data: dict[str, Any]) -> dict[str, Any]:
    """Keep only the fields the server knows, bounded and printable."""
    out: dict[str, Any] = {}
    for key in ("status", "classification", "recovery", "steps_omitted", "occurred_at", "version"):
        if key in data:
            out[key] = clean(data[key])
    for key in ("recheck_ok", "external_reachable", "dns_ok", "escalated"):
        if key in data and (data[key] is None or isinstance(data[key], bool)):
            out[key] = data[key]
    duration = data.get("duration_seconds")
    if isinstance(duration, (int, float)) and not isinstance(duration, bool) and duration >= 0:
        out["duration_seconds"] = round(float(duration), 1)
    steps = data.get("steps")
    if isinstance(steps, list):
        out["steps"] = [
            {
                "name": clean(step.get("name"), 60),
                "outcome": clean(step.get("outcome"), MAX_STEP_TEXT),
            }
            for step in steps[:MAX_STEPS]
            if isinstance(step, dict)
        ]
    return out


def step_summaries(ladder_results, redact_fn) -> list[dict[str, str]]:
    """The ladder steps as (name, outcome) pairs, redacted then bounded.

    Redaction runs before truncation for the reason `_outbound_bundle` gives: a
    cut can split a sensitive string into a fragment that no longer matches.
    """
    out = []
    for step in list(ladder_results or [])[:MAX_STEPS]:
        if not isinstance(step, dict):
            continue
        out.append(
            {
                "name": clean(redact_fn(str(step.get("name", "?"))), 60),
                "outcome": clean(redact_fn(str(step.get("outcome", ""))), MAX_STEP_TEXT),
            }
        )
    return out
