"""Which other copies of this monitor are on the network, and how recently each
one was heard from.

Pure bookkeeping: no sockets, no threads, an injected clock. peer_net.py does the
talking and calls in here. Splitting it that way is what makes the bucketing and
the eviction policy testable without opening a port.

**The three buckets.** A peer is filed by how recently it was last heard from,
not by a flag anyone sets, so a peer that goes away is reclassified by the
passage of time alone and nothing has to notice it left:

  current   heard from within `current_seconds` (default two announce
            intervals, so one missed announcement is not a demotion)
  recent    heard from within `recent_seconds` (default a day) -- was here,
            isn't answering now
  other     known, but longer ago than that -- kept as history

**What is trusted from the wire: nothing.** Every field arriving from another
host is treated as hostile input. Strings are truncated and stripped of control
characters, unknown fields are dropped, the table is capped so a flood cannot
exhaust memory, and our own id is ignored so an instance never counts itself as
its own peer. Nothing from a packet is ever used as a path, a command, or a
format string.
"""

import json
import os
from datetime import datetime, timezone
from typing import Callable, Optional

CURRENT = "current"
RECENT = "recent"
OTHER = "other"
BUCKETS = (CURRENT, RECENT, OTHER)

# A hostname is at most 253 characters; anything longer is not a hostname. The
# cap exists so a peer cannot push megabytes of text into the record file.
MAX_FIELD = 253
MAX_PEERS = 200


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sanitise(value, limit: int = MAX_FIELD) -> str:
    """Make an arbitrary value from the network safe to store and display.

    Control characters are stripped rather than escaped: these end up in a
    monospaced window and in a JSON record, and an embedded newline or ANSI
    escape in a "hostname" would corrupt both.
    """
    if not isinstance(value, str):
        value = "" if value is None else str(value)
    cleaned = "".join(ch for ch in value if ch.isprintable())
    return cleaned[:limit]


class PeerRegistry:
    def __init__(
        self,
        self_id: str,
        current_seconds: float = 600,
        recent_seconds: float = 86400,
        max_peers: int = MAX_PEERS,
        clock: Callable[[], datetime] = _utc_now,
    ):
        self.self_id = self_id
        self.current_seconds = current_seconds
        self.recent_seconds = recent_seconds
        self.max_peers = max_peers
        self.clock = clock
        self.peers: dict = {}

    # --- updating ----------------------------------------------------------

    def observe(
        self,
        peer_id,
        host="",
        address="",
        status="",
        via="announce",
        external_reachable=None,
        dns_ok=None,
    ) -> bool:
        """Record that a peer was heard from. Returns True if it is newly seen.

        Called for announcements and for pongs alike -- being heard from at all
        is what "healthy" means for a peer, so there is no separate liveness
        flag to drift out of step with the timestamps.
        """
        peer_id = sanitise(peer_id, 64)
        if not peer_id or peer_id == self.self_id:
            return False

        now = self.clock().isoformat()
        existing = self.peers.get(peer_id)
        is_new = existing is None

        if is_new:
            self._evict_if_full()
            existing = {"first_seen": now, "missed_healthchecks": 0}
            self.peers[peer_id] = existing

        existing.update(
            {
                "id": peer_id,
                "host": sanitise(host) or existing.get("host", ""),
                "address": sanitise(address, 64) or existing.get("address", ""),
                "status": sanitise(status, 32) or existing.get("status", ""),
                "last_seen": now,
                "last_seen_via": sanitise(via, 32),
            }
        )
        # Tri-state and only overwritten when the peer actually said something.
        # A peer running an older build sends neither, and "didn't say" must stay
        # distinguishable from "said no" -- localize.py treats them completely
        # differently.
        for field, value in (("external_reachable", external_reachable), ("dns_ok", dns_ok)):
            if value is not None:
                existing[field] = bool(value)
            else:
                existing.setdefault(field, None)
        existing["missed_healthchecks"] = 0
        return is_new

    def note_healthcheck_miss(self, peer_id: str) -> None:
        """A probe went out and nothing came back before the next sweep."""
        peer = self.peers.get(peer_id)
        if peer is not None:
            peer["missed_healthchecks"] = int(peer.get("missed_healthchecks", 0)) + 1

    def _evict_if_full(self) -> None:
        """Drop the least recently heard-from peer to make room.

        Without a cap, a host spraying announcements with a fresh id each time
        would grow this table and the record file without limit.
        """
        while len(self.peers) >= self.max_peers:
            oldest = min(self.peers.values(), key=lambda p: p.get("last_seen", ""))
            self.peers.pop(oldest["id"], None)

    # --- reading -----------------------------------------------------------

    def age_seconds(self, peer: dict) -> Optional[float]:
        try:
            return (self.clock() - datetime.fromisoformat(peer["last_seen"])).total_seconds()
        except (KeyError, ValueError, TypeError):
            return None

    def bucket(self, peer: dict) -> str:
        age = self.age_seconds(peer)
        if age is None:
            return OTHER
        if age <= self.current_seconds:
            return CURRENT
        if age <= self.recent_seconds:
            return RECENT
        return OTHER

    def buckets(self) -> dict:
        grouped = {name: [] for name in BUCKETS}
        for peer in self.peers.values():
            grouped[self.bucket(peer)].append(peer)
        for entries in grouped.values():
            entries.sort(key=lambda p: p.get("last_seen", ""), reverse=True)
        return grouped

    def to_dict(self) -> dict:
        """The on-disk record.

        The bucket is written out even though it is derivable from `last_seen`:
        the file is meant to be readable on its own, and re-deriving it requires
        knowing what "now" was when it was written.
        """
        grouped = self.buckets()
        return {
            "self_id": self.self_id,
            "written_at": self.clock().isoformat(),
            "counts": {name: len(entries) for name, entries in grouped.items()},
            "peers": {
                name: [dict(peer, bucket=name) for peer in entries]
                for name, entries in grouped.items()
            },
        }

    def load(self, record: dict) -> None:
        """Restore known peers from a previous run's record.

        This is what makes "attempt to connect to them when starting" possible at
        all: without it, a fresh process knows nobody until somebody else happens
        to announce.
        """
        if not isinstance(record, dict):
            return
        groups = record.get("peers")
        if not isinstance(groups, dict):
            return
        for entries in groups.values():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                peer_id = sanitise(entry.get("id"), 64)
                if not peer_id or peer_id == self.self_id or peer_id in self.peers:
                    continue
                if len(self.peers) >= self.max_peers:
                    return
                self.peers[peer_id] = {
                    "id": peer_id,
                    "host": sanitise(entry.get("host")),
                    "address": sanitise(entry.get("address"), 64),
                    "status": sanitise(entry.get("status"), 32),
                    "first_seen": sanitise(entry.get("first_seen"), 64),
                    "last_seen": sanitise(entry.get("last_seen"), 64),
                    "last_seen_via": sanitise(entry.get("last_seen_via"), 32),
                    "missed_healthchecks": _as_int(entry.get("missed_healthchecks")),
                    "external_reachable": _as_tristate(entry.get("external_reachable")),
                    "dns_ok": _as_tristate(entry.get("dns_ok")),
                }

    def localization_view(self, fresh_seconds: float = 30) -> list:
        """Peers as localize.py wants them: each tagged with whether it has been
        heard from recently enough to count as answering *now*.

        `fresh_seconds` is much shorter than the `current` bucket on purpose.
        During an outage the question is "did this peer answer in the last few
        seconds", not "was it around this morning" -- a peer last heard from nine
        minutes ago is still `current` but tells you nothing about right now.
        """
        view = []
        for peer in self.peers.values():
            age = self.age_seconds(peer)
            view.append(
                {
                    "id": peer.get("id"),
                    "host": peer.get("host"),
                    "address": peer.get("address"),
                    "answered": age is not None and age <= fresh_seconds,
                    "external_reachable": peer.get("external_reachable"),
                    "dns_ok": peer.get("dns_ok"),
                }
            )
        return view

    def addresses_to_probe(self) -> list:
        """Every known peer address, most recently heard from first.

        Includes peers in every bucket on purpose: a machine that was last seen
        yesterday is exactly the one worth probing on startup.
        """
        seen = set()
        ordered = []
        for name in BUCKETS:
            for peer in self.buckets()[name]:
                address = peer.get("address")
                if address and address not in seen:
                    seen.add(address)
                    ordered.append((peer["id"], address))
        return ordered


def _as_tristate(value):
    """None stays None; anything else becomes a real bool.

    A record file is hand-editable, and a string "false" is truthy in Python --
    which would silently invert a localization verdict.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return bool(value)


def _as_int(value) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def save_record(registry: PeerRegistry, path: str, writer=None) -> bool:
    """Write the record file. False on any failure -- a peer file that cannot be
    written must not take the monitor down.
    """
    if writer is None:
        from netdnsmonitor.report_storage import _atomic_write

        writer = _atomic_write
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        writer(path, json.dumps(registry.to_dict(), indent=2))
        return True
    except Exception:  # noqa: BLE001 - bookkeeping must never be fatal
        return False


def load_record(path: str) -> dict:
    """Read a previous record, or an empty dict. Never raises: a truncated or
    hand-edited file must not stop the app from starting.
    """
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}
