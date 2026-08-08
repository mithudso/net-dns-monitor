import json
import os
import pathlib

from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    extract_failed_domains,
    is_probeable_domain,
    make_domain_learner,
    prune_dead_domains,
)


def test_extract_picks_up_a_domain_from_a_resolution_failure_line():
    lines = ["mDNSResponder: query for status.example.com timed out after 5000ms"]
    assert extract_failed_domains(lines) == ["status.example.com"]


def test_extract_ignores_lines_that_are_not_resolution_failures():
    lines = ["mDNSResponder: registered service for printer.example.com"]
    assert extract_failed_domains(lines) == []


def test_extract_handles_nxdomain_and_getaddrinfo_phrasings():
    lines = [
        "dns: NXDOMAIN for api.internal.example.org",
        "getaddrinfo failed: no such host cdn.example.net",
    ]
    assert extract_failed_domains(lines) == ["api.internal.example.org", "cdn.example.net"]


def test_extract_dedupes_and_preserves_first_seen_order():
    lines = [
        "query for b.example.com timed out",
        "query for a.example.com timed out",
        "query for b.example.com timed out",
    ]
    assert extract_failed_domains(lines) == ["b.example.com", "a.example.com"]


def test_extract_rejects_ip_literals_and_reverse_zones():
    lines = [
        "could not resolve 192.168.1.1",
        "query for 1.1.168.192.in-addr.arpa timed out",
    ]
    assert extract_failed_domains(lines) == []


def test_is_probeable_domain_rejects_bare_labels_and_overlong_names():
    assert is_probeable_domain("localhost") is False
    assert is_probeable_domain("example.com") is True
    assert is_probeable_domain("a." * 200 + "com") is False


def test_store_starts_empty_when_the_file_is_missing(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    assert store.domains == []


def test_store_treats_a_corrupt_file_as_empty_rather_than_crashing(tmp_path):
    path = tmp_path / "learned.json"
    path.write_text("{not json")
    assert LearnedDomainStore(str(path)).domains == []


def test_store_add_persists_and_round_trips(tmp_path):
    path = str(tmp_path / "learned.json")
    store = LearnedDomainStore(path)
    assert store.add(["a.example.com", "a.example.com", "bad"]) == ["a.example.com"]
    assert json.loads(pathlib.Path(path).read_text()) == ["a.example.com"]
    assert LearnedDomainStore(path).domains == ["a.example.com"]


def test_store_enforces_the_cap(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"), max_domains=2)
    store.add(["a.example.com", "b.example.com", "c.example.com"])
    assert store.domains == ["a.example.com", "b.example.com"]


def test_store_remove_deletes_and_persists(tmp_path):
    path = str(tmp_path / "learned.json")
    store = LearnedDomainStore(path)
    store.add(["a.example.com", "b.example.com"])
    assert store.remove(["a.example.com", "never-added.example.com"]) == ["a.example.com"]
    assert LearnedDomainStore(path).domains == ["b.example.com"]


def test_store_creates_its_parent_directory(tmp_path):
    path = str(tmp_path / "nested" / "dir" / "learned.json")
    LearnedDomainStore(path).add(["a.example.com"])
    assert os.path.isfile(path)


def test_prune_evicts_a_learned_domain_that_failed_while_others_resolved(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    store.add(["dead.example.com", "live.example.com"])
    pruned = prune_dead_domains(
        store,
        {"dead.example.com": False, "live.example.com": True},
        configured_domains=[],
    )
    assert pruned == ["dead.example.com"]
    assert store.domains == ["live.example.com"]


def test_prune_keeps_everything_during_a_systemic_outage(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    store.add(["a.example.com", "b.example.com"])
    pruned = prune_dead_domains(
        store,
        {"a.example.com": False, "b.example.com": False},
        configured_domains=[],
    )
    assert pruned == []
    assert store.domains == ["a.example.com", "b.example.com"]


def test_prune_never_evicts_a_user_configured_domain(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    store.add(["learned.example.com"])
    pruned = prune_dead_domains(
        store,
        {"configured.example.com": False, "learned.example.com": True},
        configured_domains=["configured.example.com"],
    )
    assert pruned == []


def test_prune_uses_the_anchor_not_the_learned_set(tmp_path):
    """The default config has no configured domains, so every probed name is a
    learned failure and "some other domain resolved" is false by construction.
    Without an anchor a dead name would pin a permanent false DNS incident.
    """
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    store.add(["dead.example.com"])
    pruned = prune_dead_domains(
        store,
        {"dead.example.com": False, "example.com": True},
        configured_domains=["example.com"],
        anchor_domains=["example.com"],
    )
    assert pruned == ["dead.example.com"]
    assert store.domains == []


def test_prune_keeps_learned_domains_when_the_anchor_itself_fails(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    store.add(["a.example.net"])
    pruned = prune_dead_domains(
        store,
        {"a.example.net": False, "example.com": False},
        configured_domains=["example.com"],
        anchor_domains=["example.com"],
    )
    assert pruned == []
    assert store.domains == ["a.example.net"]


def test_store_load_normalizes_and_dedupes_a_hand_edited_file(tmp_path):
    path = tmp_path / "learned.json"
    path.write_text(json.dumps(["Example.COM.", "example.com", 17, "bad"]))
    store = LearnedDomainStore(str(path))
    assert store.domains == ["example.com"]


def test_store_save_survives_an_unwritable_path(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory")
    store = LearnedDomainStore(str(blocker / "learned.json"))
    store.add(["a.example.com"])  # must not raise despite makedirs failing
    assert store.domains == ["a.example.com"]


def test_extract_ignores_the_log_subsystem_label():
    """Found against the real macOS log: "[com.apple.mdns:resolver]" has the exact
    shape of a hostname, so the learner probed "com.apple.mdns" on every scan,
    pruned it, and learned it again on the next one.
    """
    line = (
        "2026-08-05 20:33:10.054 Df mDNSResponder[441:66b4fc] "
        "[com.apple.mdns:resolver] [Q65460] query for real.example.com timed out"
    )
    assert extract_failed_domains([line]) == ["real.example.com"]


def test_is_probeable_domain_rejects_reverse_dns_bundle_identifiers():
    assert is_probeable_domain("com.apple.mdns") is False
    assert is_probeable_domain("org.mozilla.firefox") is False
    assert is_probeable_domain("apple.com") is True


def test_extract_ignores_a_completed_lookup_that_merely_mentions_a_timeout():
    lines = ["DNS query for cache.example.com completed, timeout was 5000ms"]
    assert extract_failed_domains(lines) == []


def test_learner_merges_configured_domains_with_learned_ones(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    domains = make_domain_learner(
        log_watcher=lambda: ["query for learned.example.com timed out"],
        store=store,
        configured_domains=["configured.example.com"],
        clock=lambda: 0.0,
    )
    assert domains() == ["configured.example.com", "learned.example.com"]


def test_learner_rate_limits_the_log_scan(tmp_path):
    scans = []
    now = {"t": 0.0}

    def log_watcher():
        scans.append(now["t"])
        return []

    domains = make_domain_learner(
        log_watcher=log_watcher,
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=[],
        interval_seconds=300.0,
        clock=lambda: now["t"],
    )
    domains()
    now["t"] = 100.0
    domains()
    assert len(scans) == 1
    now["t"] = 400.0
    domains()
    assert len(scans) == 2


def test_learner_does_not_duplicate_a_domain_that_is_both_configured_and_learned(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    domains = make_domain_learner(
        log_watcher=lambda: ["query for shared.example.com timed out"],
        store=store,
        configured_domains=["shared.example.com"],
        clock=lambda: 0.0,
    )
    assert domains() == ["shared.example.com"]
