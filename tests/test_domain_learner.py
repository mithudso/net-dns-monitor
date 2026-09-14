import json
import os
import pathlib
import subprocess
import sys
import threading
import time

from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    extract_failed_domains,
    is_probeable_domain,
    make_domain_learner,
    prune_dead_domains,
)
from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX, make_log_watcher


def run_inline(fn):
    """A spawn hook that runs the scan on the calling thread, so a test sees the
    scan's result on the same call that started it.
    """
    fn()


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


def test_extract_never_learns_from_the_log_watchers_no_evidence_line():
    def timing_out(args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args, timeout=10)

    sentinel = make_log_watcher(run_fn=timing_out)()
    assert extract_failed_domains(sentinel) == []
    # The rule is the prefix, not a lucky absence of a dotted name: this line has a
    # failure marker and a probeable hostname, and is still not log evidence.
    forged = f"{NO_EVIDENCE_PREFIX} no log evidence: query for dead.example.com timed out"
    assert extract_failed_domains([forged]) == []


def test_store_save_leaves_the_previous_file_intact_when_the_write_fails(tmp_path, monkeypatch):
    """save() used to truncate the file and then write it, so a failure part-way
    left a truncated file that load() reads as empty -- every learned domain lost.
    os.replace is patched because it is the commit point of the atomic write and
    the store has no writer seam of its own.
    """
    path = tmp_path / "learned.json"
    store = LearnedDomainStore(str(path))
    store.add(["a.example.com"])

    def failing_replace(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", failing_replace)
    assert store.add(["b.example.com"]) == ["b.example.com"]  # must not raise
    monkeypatch.undo()

    assert store.domains == ["a.example.com", "b.example.com"]
    assert LearnedDomainStore(str(path)).domains == ["a.example.com"]
    assert list(tmp_path.glob("*.tmp")) == []  # the failed write cleaned up after itself


def test_learner_merges_configured_domains_with_learned_ones(tmp_path):
    store = LearnedDomainStore(str(tmp_path / "learned.json"))
    domains = make_domain_learner(
        log_watcher=lambda: ["query for learned.example.com timed out"],
        store=store,
        configured_domains=["configured.example.com"],
        clock=lambda: 0.0,
        spawn=run_inline,
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
        spawn=run_inline,
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
        spawn=run_inline,
    )
    assert domains() == ["shared.example.com"]


def test_a_slow_log_scan_does_not_hold_up_the_domain_list(tmp_path):
    """domains() runs inside the rumps timer via the prober. `log show` took 2.25s
    measured and may take its full 10s timeout, and the menu bar is frozen for as
    long as the tick runs. This uses the default spawn, a real thread.
    """
    release = threading.Event()

    def blocked_log_watcher():
        release.wait(timeout=5)
        return ["query for learned.example.com timed out"]

    domains = make_domain_learner(
        log_watcher=blocked_log_watcher,
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=["configured.example.com"],
        clock=lambda: 0.0,
    )
    started = time.monotonic()
    assert domains() == ["configured.example.com"]
    assert time.monotonic() - started < 2

    release.set()
    deadline = time.monotonic() + 5
    result = domains()
    while "learned.example.com" not in result and time.monotonic() < deadline:
        time.sleep(0.01)
        result = domains()
    assert result == ["configured.example.com", "learned.example.com"]


def test_a_due_scan_does_not_start_while_the_previous_one_is_still_running(tmp_path):
    spawned = []
    now = {"t": 0.0}
    domains = make_domain_learner(
        log_watcher=lambda: ["query for learned.example.com timed out"],
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=[],
        interval_seconds=300.0,
        clock=lambda: now["t"],
        spawn=spawned.append,  # records the scan without running it
    )
    assert domains() == []
    now["t"] = 400.0
    assert domains() == []
    assert len(spawned) == 1

    spawned[0]()  # the first scan finishes
    assert domains() == ["learned.example.com"]
    # It was due, and nothing was running any more, so the next scan started.
    assert len(spawned) == 2


def test_a_scan_that_raises_does_not_stop_later_scans(tmp_path):
    """The scan runs on a worker thread. An exception there would end the thread
    without reporting back, the learner would wait for it forever, and learning
    would stop for the rest of the session.
    """
    calls = []
    now = {"t": 0.0}

    def flaky_log_watcher():
        calls.append(now["t"])
        if len(calls) == 1:
            raise RuntimeError("unforeseen")
        return ["query for learned.example.com timed out"]

    domains = make_domain_learner(
        log_watcher=flaky_log_watcher,
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=["configured.example.com"],
        interval_seconds=300.0,
        clock=lambda: now["t"],
        spawn=run_inline,
    )
    assert domains() == ["configured.example.com"]
    now["t"] = 400.0
    assert domains() == ["configured.example.com", "learned.example.com"]
    assert calls == [0.0, 400.0]


def test_a_thread_that_cannot_start_does_not_stop_later_scans(tmp_path):
    attempts = []
    now = {"t": 0.0}

    def spawn(fn):
        attempts.append(now["t"])
        if len(attempts) == 1:
            raise RuntimeError("can't start new thread")
        fn()

    domains = make_domain_learner(
        log_watcher=lambda: ["query for learned.example.com timed out"],
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=[],
        interval_seconds=300.0,
        clock=lambda: now["t"],
        spawn=spawn,
    )
    assert domains() == []
    now["t"] = 400.0
    assert domains() == ["learned.example.com"]


# --- thread safety ------------------------------------------------------------
#
# domains() is called from the rumps tick (through the prober) and from the
# dashboard's worker thread (the "full diagnosis" action runs the same prober),
# and both paths prune through store.remove.


class InMemoryStore(LearnedDomainStore):
    """Every real save is file I/O, which releases the GIL and serialises the
    threads around it, hiding the race this is meant to expose. Measured: with
    real saves the unlocked store passed; with this it broke every run.
    """

    def save(self) -> None:
        pass


def test_the_store_stays_consistent_under_concurrent_add_and_remove(tmp_path):
    """Unsynchronised, add() checked membership and the cap and then appended, so
    two threads could insert the same name twice or push past max_domains.
    """
    store = InMemoryStore(str(tmp_path / "learned.json"), max_domains=5)
    names = [f"host{i}.example.com" for i in range(8)]
    violations = []
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)

    def churn(offset):
        for i in range(2000):
            store.add([names[(i + offset) % len(names)]])
            if i % 3 == 0:
                store.remove([names[(i + offset + 1) % len(names)]])
            current = store.domains
            if len(current) != len(set(current)) or len(current) > 5:
                violations.append(current)

    try:
        workers = [threading.Thread(target=churn, args=(n,)) for n in (0, 0, 3, 5)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=60)
    finally:
        sys.setswitchinterval(previous)

    assert violations == []


def test_a_second_caller_waits_for_the_first_so_only_one_scan_starts(tmp_path):
    """Both callers could read "no scan running, scan due" before either set
    scan_running, and both started a `log show` of whole seconds for the same
    window. That gap is a few bytecodes with no seam inside it, so this checks
    what closes it: while one call is inside domains(), another cannot be.
    """
    spawned = []
    first_inside = threading.Event()
    release_first = threading.Event()
    second_done = threading.Event()
    calls = []

    def clock():
        calls.append(threading.current_thread().name)
        if len(calls) == 1:
            first_inside.set()
            release_first.wait(timeout=5)
        return 0.0

    domains = make_domain_learner(
        log_watcher=lambda: [],
        store=LearnedDomainStore(str(tmp_path / "learned.json")),
        configured_domains=["configured.example.com"],
        interval_seconds=300.0,
        clock=clock,
        spawn=spawned.append,  # records the scan without running it
    )
    results = []

    def second():
        results.append(domains())
        second_done.set()

    first = threading.Thread(target=lambda: results.append(domains()), name="first")
    first.start()
    assert first_inside.wait(timeout=5)
    other = threading.Thread(target=second, name="second")
    other.start()
    try:
        assert not second_done.wait(timeout=0.2), "a second caller ran inside the first"
    finally:
        release_first.set()
        first.join(timeout=5)
        other.join(timeout=5)

    assert results == [["configured.example.com"], ["configured.example.com"]]
    assert len(spawned) == 1
