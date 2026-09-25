"""Grow the monitored-domain list automatically from evidence already on the
machine: any domain the unified log shows *failing* DNS resolution is, by
definition, a domain this user actually tried to reach and could not. That is
a better source than browser history (which would mean reading another app's
data) and it needs no user action. On a stock macOS install this finds nothing:
the unified log masks hostnames (`<mask.hash: …>` or an opaque token), measured
758 error-like lines → 0 learnable. `domains` is the real probe list; this is
opportunistic. See docs/known-issues.md.

Two hazards this module exists to contain:

1. **A permanently dead name would pin the app in a false incident.** dns_ok
   is an all()-across-domains signal, so one typo'd or decommissioned host
   scraped out of a log line would report DNS as broken forever. So learned
   domains are *prunable*: a learned domain that fails while some other
   probed domain resolves is domain-specific, not systemic, and gets evicted.
   Configured domains are never pruned -- the user asked for those explicitly.

2. **Log lines are not a trustworthy source of hostnames.** Everything is
   validated as a real dotted name before it is stored: no IP literals, no
   reverse-lookup zones, no bare labels, length-capped, lowercased, and the
   store is capped so a log flood cannot grow the probe list without bound.

Learned domains are stored on disk locally, and they leave the machine by one
path. Every probed name is a key of `probe_results["domain_results"]`, and the
LLM escalation bundle carries `probe_results`, so a learned domain is sent to
the LLM whenever an incident escalates. The bundle is redacted, but a learned
domain is masked only if the user lists it in `sensitive_strings`. Slack and
email omit probe results (see `notifications.format_notification`), so a
learned domain does not reach them.

The log scan runs on a worker thread, not in the caller. The prober asks for
the domain list inside the rumps timer, `log show` took 2.25s measured and may
run to its 10s timeout, and the menu bar is frozen for as long as a tick runs.
"""

import json
import os
import queue
import re
import threading
import time
from typing import Callable, Optional

from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX
from netdnsmonitor.report_storage import _atomic_write

# A DNS failure line has to look like a *resolution* failure, not merely a
# line that happens to mention a hostname; matching on "error" alone pulled
# in unrelated network chatter.
FAILURE_MARKERS = (
    "no such host",
    "nxdomain",
    "name or service not known",
    "could not resolve",
    "cannot resolve",
    "unable to resolve",
    "resolution failed",
    "dns query failed",
    "getaddrinfo failed",
    "getaddrinfo error",
    "lookup failed",
    "servfail",
    "timed out",
)

# A line that reports a *completed* lookup is not evidence of failure even when
# it mentions a timeout value ("... completed, timeout was 5000ms"), so success
# phrasing vetoes the failure markers above.
SUCCESS_MARKERS = ("completed", "succeeded", " success", "resolved to", "answer received")

# The leading lookbehind replaces `\b`: `\b` lets the engine restart a label match
# at every dot inside a long dotted run, which made a 10 KB "a.a.a..." line take
# a second on the main thread and a 50 KB one over fifteen. Anchoring the start to
# "not preceded by a hostname character" gives each position one attempt.
# re.ASCII because IGNORECASE alone folds "İ", "ı", "ſ" and "K" (Kelvin sign) into
# ASCII letters; a lookalike name would pass here, then fail idna encoding in the
# probe worker.
_HOSTNAME_RE = re.compile(
    r"(?<![a-z0-9_.-])((?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\.?\b",
    re.IGNORECASE | re.ASCII,
)

_REJECTED_SUFFIXES = (".arpa", ".in-addr.arpa", ".ip6.arpa")

# Unified-log scaffolding lives in brackets: "[com.apple.mdns:resolver]", "[Q65460]",
# "[com.apple.WiFiManager:]". Those are subsystem labels and query IDs, never a queried
# hostname -- but "com.apple.mdns" has the exact shape of a domain, and was being
# learned as one, probed, pruned, then learned again on the next scan. Angle brackets
# are the log's redaction placeholders -- "<mask.hash: '...'>", "<private>" -- and
# "mask.hash" has the same domain shape and the same phantom lifecycle. Strip both
# kinds of span before looking for hostnames. The character classes exclude the
# opening bracket too, so an unclosed one cannot make the match scan to the line end.
_BRACKETED_RE = re.compile(r"\[[^\[\]]*\]|<[^<>]*>")

# Reverse-DNS bundle identifiers survive the bracket strip when they appear in free
# text (com.apple.foo, org.mozilla.bar) and are not resolvable names. A real hostname
# does not start with a TLD label.
_REVERSE_DNS_FIRST_LABELS = ("com", "org", "net", "io", "co", "edu", "gov", "uk", "us")


def is_probeable_domain(candidate: str) -> bool:
    domain = candidate.strip().strip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    # lower() can *lengthen* a non-ASCII name ("İ" becomes two code points), and
    # the result is not something encode("idna") accepts; a probe of it would
    # raise UnicodeError in the worker.
    if not domain.isascii():
        return False
    if domain.endswith(_REJECTED_SUFFIXES):
        return False
    # An IPv4 literal matches the hostname shape only if the last label is
    # alphabetic, but guard explicitly rather than rely on that coincidence.
    labels = domain.split(".")
    if not labels[-1].isalpha():
        return False
    if labels[0] in _REVERSE_DNS_FIRST_LABELS:
        return False
    return all(0 < len(label) <= 63 for label in labels)


def extract_failed_domains(log_lines: list[str]) -> list[str]:
    """Domains named on log lines that describe a failed resolution, in first
    -seen order (order matters: it decides what survives the store's cap).
    """
    found: list[str] = []
    seen: set[str] = set()
    for line in log_lines:
        # The watcher's own "no log evidence" note is not a log line, and a
        # timeout note contains "timed out" -- one of the failure markers.
        if line.startswith(NO_EVIDENCE_PREFIX):
            continue
        lowered = line.lower()
        if not any(marker in lowered for marker in FAILURE_MARKERS):
            continue
        if any(marker in lowered for marker in SUCCESS_MARKERS):
            continue
        for match in _HOSTNAME_RE.finditer(_BRACKETED_RE.sub(" ", line)):
            domain = match.group(1).strip(".").lower()
            if domain in seen or not is_probeable_domain(domain):
                continue
            seen.add(domain)
            found.append(domain)
    return found


class LearnedDomainStore:
    """A capped, de-duplicated, JSON-backed set of learned domains. A missing
    or corrupt file is treated as empty rather than fatal -- this is a cache
    of an inference, not user data.

    Safe to share between threads. The rumps tick and the dashboard's worker
    thread both run the prober, so both add and prune. Unlocked, add() could
    insert a name twice or pass the cap, and two saves could land out of order
    and leave an older list on disk.
    """

    def __init__(self, path: str, max_domains: int = 20):
        self.path = os.path.expanduser(path)
        self.max_domains = max_domains
        self._domains: list[str] = []
        # Re-entrant because add() and remove() call save() while holding it.
        self._lock = threading.RLock()
        self.load()

    def load(self) -> list[str]:
        with self._lock:
            try:
                with open(self.path) as f:
                    data = json.load(f)
            except (OSError, ValueError):
                self._domains = []
                return []
            if not isinstance(data, list):
                self._domains = []
                return []
            # Normalize on load, not just on add: a hand-edited file holding
            # "Example.COM." would otherwise dodge the dedup in add() and burn a
            # second cap slot on the same name.
            normalized = []
            for entry in data:
                if not isinstance(entry, str):
                    continue
                domain = entry.strip().strip(".").lower()
                if is_probeable_domain(domain) and domain not in normalized:
                    normalized.append(domain)
            self._domains = normalized[: self.max_domains]
            return list(self._domains)

    def save(self) -> None:
        with self._lock:
            try:
                directory = os.path.dirname(self.path)
                if directory:
                    os.makedirs(directory, exist_ok=True)
                # Temp file plus rename: truncating in place and then failing
                # part-way left a file load() reads as empty, losing every
                # learned domain.
                _atomic_write(self.path, json.dumps(self._domains, indent=2))
            except OSError:
                # A cache we cannot persist is still usable in memory. makedirs
                # has to be inside the try: exist_ok=True only forgives an
                # existing *directory*, and a read-only volume or a path
                # component that is a file would otherwise raise all the way
                # into the UI thread.
                pass

    @property
    def domains(self) -> list[str]:
        with self._lock:
            return list(self._domains)

    def add(self, candidates: list[str]) -> list[str]:
        """Add valid, unseen domains up to the cap. Returns what was added."""
        with self._lock:
            added = []
            for candidate in candidates:
                domain = candidate.strip().strip(".").lower()
                if len(self._domains) >= self.max_domains:
                    break
                if domain in self._domains or not is_probeable_domain(domain):
                    continue
                self._domains.append(domain)
                added.append(domain)
            if added:
                self.save()
            return added

    def remove(self, domains: list[str]) -> list[str]:
        with self._lock:
            removed = [d for d in domains if d in self._domains]
            if removed:
                self._domains = [d for d in self._domains if d not in removed]
                self.save()
            return removed


def prune_dead_domains(
    store: LearnedDomainStore,
    domain_results: dict,
    configured_domains: list[str],
    anchor_domains: Optional[list[str]] = None,
) -> list[str]:
    """Evict learned domains that failed while an *anchor* domain resolved:
    that pattern means the name is dead, not the resolver, so keeping it would
    hold dns_ok false forever. With the anchor also failing we cannot tell the
    two apart, so nothing is pruned -- that is the systemic outage this app
    exists to report.

    The anchor has to be a name that is not itself learned, or the guarantee
    collapses on the default config: with `domains: []` every probed name is a
    learned failure, so "some other probed domain resolved" is false by
    construction and one dead name would pin a permanent false incident. That
    is why app.py probes a control domain by default (`control_domain`; a user
    who nulls it with `domains: []` disables pruning entirely). With no anchors given we
    fall back to "some other probed domain resolved", which is still right
    whenever the user configured domains of their own.
    """
    if not domain_results:
        return []
    configured = {d.strip().strip(".").lower() for d in configured_domains}
    anchors = {d.strip().strip(".").lower() for d in (anchor_domains or [])}
    anchor_results = (
        {d: ok for d, ok in domain_results.items() if d.lower() in anchors}
        if anchors
        else domain_results
    )
    if not any(anchor_results.values()):
        return []
    dead = [
        domain
        for domain, ok in domain_results.items()
        if not ok and domain.lower() not in configured and domain in store.domains
    ]
    return store.remove(dead)


def _spawn_daemon(fn: Callable[[], None]) -> None:
    threading.Thread(target=fn, name="domain-learner-scan", daemon=True).start()


def make_domain_learner(
    log_watcher: Callable[[], list[str]],
    store: LearnedDomainStore,
    configured_domains: list[str],
    interval_seconds: float = 300.0,
    clock: Callable[[], float] = time.monotonic,
    spawn: Callable[[Callable[[], None]], None] = _spawn_daemon,
) -> Callable[[], list[str]]:
    """Returns the callable the prober asks for its domain list each tick.

    The log scan is rate-limited to interval_seconds because `log show` is a
    subprocess costing whole seconds -- running it every poll would make the
    monitor itself the heaviest thing on the machine.

    `spawn` starts the scan. The scan thread only reads the log and extracts
    names; `store` is touched only by threads calling domains(), which pick up
    finished scans. A scan's names therefore appear on the first call after it
    finishes. With a spawn that runs the scan inline, that is the call that
    started it.

    domains() may be called from more than one thread at once: the rumps tick
    and the dashboard's worker thread both run the prober. One lock covers the
    whole call, because the due check and setting `scan_running` are separate
    steps, and two callers between them would each start a scan.
    """
    last_scan_at: Optional[float] = None
    scan_running = False
    finished: queue.Queue = queue.Queue()
    lock = threading.Lock()

    def scan() -> None:
        try:
            found = extract_failed_domains(log_watcher())
        except Exception:  # noqa: BLE001 - a failed scan must still report back
            # Without a report scan_running never clears, and learning stops for
            # the rest of the session without any sign.
            found = []
        finished.put(found)

    def collect_finished() -> None:
        nonlocal scan_running
        while True:
            try:
                found = finished.get_nowait()
            except queue.Empty:
                return
            scan_running = False
            store.add(found)

    def domains() -> list[str]:
        nonlocal last_scan_at, scan_running
        with lock:
            collect_finished()
            now = clock()
            due = last_scan_at is None or (now - last_scan_at) >= interval_seconds
            if due and not scan_running:
                last_scan_at = now
                scan_running = True
                try:
                    spawn(scan)
                except RuntimeError:
                    # Thread.start raises RuntimeError when no thread can be
                    # made. Learning is opportunistic, so try again at the next
                    # interval.
                    scan_running = False
            collect_finished()
            configured = [d.strip().strip(".").lower() for d in configured_domains]
            merged = list(configured)
            for domain in store.domains:
                if domain not in merged:
                    merged.append(domain)
            return merged

    return domains
