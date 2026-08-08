"""Grow the monitored-domain list automatically from evidence already on the
machine: any domain the unified log shows *failing* DNS resolution is, by
definition, a domain this user actually tried to reach and could not. That is
a better source than browser history (which would mean reading another app's
data) and it needs no user action.

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

Learned domains stay on disk locally. They are never sent anywhere: the
outbound paths (LLM escalation, Slack/email) carry booleans and summaries,
and anything the user marks sensitive is redacted on the way out.
"""

import json
import os
import re
import time
from typing import Callable, Optional

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
    "query for",
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

_HOSTNAME_RE = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63})\.?\b",
    re.IGNORECASE,
)

_REJECTED_SUFFIXES = (".arpa", ".in-addr.arpa", ".ip6.arpa")

# Unified-log scaffolding lives in brackets: "[com.apple.mdns:resolver]", "[Q65460]",
# "[com.apple.WiFiManager:]". Those are subsystem labels and query IDs, never a queried
# hostname -- but "com.apple.mdns" has the exact shape of a domain, and was being
# learned as one, probed, pruned, then learned again on the next scan. Strip bracketed
# spans before looking for hostnames.
_BRACKETED_RE = re.compile(r"\[[^\]]*\]")

# Reverse-DNS bundle identifiers survive the bracket strip when they appear in free
# text (com.apple.foo, org.mozilla.bar) and are not resolvable names. A real hostname
# does not start with a TLD label.
_REVERSE_DNS_FIRST_LABELS = ("com", "org", "net", "io", "co", "edu", "gov", "uk", "us")


def is_probeable_domain(candidate: str) -> bool:
    domain = candidate.strip().strip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
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
    """

    def __init__(self, path: str, max_domains: int = 20):
        self.path = os.path.expanduser(path)
        self.max_domains = max_domains
        self._domains: list[str] = []
        self.load()

    def load(self) -> list[str]:
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
        try:
            directory = os.path.dirname(self.path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(self.path, "w") as f:
                json.dump(self._domains, f, indent=2)
        except OSError:
            # A cache we cannot persist is still usable in memory. makedirs has
            # to be inside the try: exist_ok=True only forgives an existing
            # *directory*, and a read-only volume or a path component that is a
            # file would otherwise raise all the way into the UI thread.
            pass

    @property
    def domains(self) -> list[str]:
        return list(self._domains)

    def add(self, candidates: list[str]) -> list[str]:
        """Add valid, unseen domains up to the cap. Returns what was added."""
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
    is why app.py always probes a control domain. With no anchors given we
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


def make_domain_learner(
    log_watcher: Callable[[], list[str]],
    store: LearnedDomainStore,
    configured_domains: list[str],
    interval_seconds: float = 300.0,
    clock: Callable[[], float] = time.monotonic,
) -> Callable[[], list[str]]:
    """Returns the callable the prober asks for its domain list each tick.

    The log scan is rate-limited to interval_seconds because `log show` is a
    subprocess costing whole seconds -- running it every poll would make the
    monitor itself the heaviest thing on the machine.
    """
    last_scan: dict[str, Optional[float]] = {"at": None}

    def domains() -> list[str]:
        now = clock()
        if last_scan["at"] is None or (now - last_scan["at"]) >= interval_seconds:
            last_scan["at"] = now
            store.add(extract_failed_domains(log_watcher()))
        configured = [d.strip().strip(".").lower() for d in configured_domains]
        merged = list(configured)
        for domain in store.domains:
            if domain not in merged:
                merged.append(domain)
        return merged

    return domains
