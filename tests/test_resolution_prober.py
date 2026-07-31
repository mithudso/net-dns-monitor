import time

from netdnsmonitor.resolution_prober import resolve_domains_parallel


def test_returns_one_finding_per_domain_in_input_order():
    resolve_fn = lambda domain, timeout: (True, None)
    findings = resolve_domains_parallel(
        ["a.example", "b.example", "c.example"], resolve_fn=resolve_fn
    )
    assert [f["domain"] for f in findings] == ["a.example", "b.example", "c.example"]


def test_marks_resolved_true_on_success():
    resolve_fn = lambda domain, timeout: (True, None)
    findings = resolve_domains_parallel(["good.example"], resolve_fn=resolve_fn)
    assert findings[0]["resolved"] is True
    assert findings[0]["error"] is None


def test_marks_resolved_false_with_error_on_failure():
    resolve_fn = lambda domain, timeout: (False, "getaddrinfo failed")
    findings = resolve_domains_parallel(["bad.example"], resolve_fn=resolve_fn)
    assert findings[0]["resolved"] is False
    assert findings[0]["error"] == "getaddrinfo failed"


def test_records_elapsed_seconds_as_a_number():
    resolve_fn = lambda domain, timeout: (True, None)
    findings = resolve_domains_parallel(["a.example"], resolve_fn=resolve_fn)
    assert isinstance(findings[0]["elapsed_seconds"], float)
    assert findings[0]["elapsed_seconds"] >= 0


def test_runs_domains_in_parallel_not_serially():
    def slow_resolve(domain, timeout):
        time.sleep(0.2)
        return (True, None)

    domains = ["a.example", "b.example", "c.example", "d.example"]
    started = time.monotonic()
    resolve_domains_parallel(domains, resolve_fn=slow_resolve, max_workers=len(domains))
    elapsed = time.monotonic() - started
    assert elapsed < 0.2 * len(domains)


def test_returns_empty_list_for_empty_domain_list():
    assert resolve_domains_parallel([], resolve_fn=lambda d, t: (True, None)) == []


def test_one_domain_raising_does_not_break_others():
    def resolve_fn(domain, timeout):
        if domain == "boom.example":
            raise OSError("network unreachable")
        return (True, None)

    findings = resolve_domains_parallel(
        ["boom.example", "fine.example"], resolve_fn=resolve_fn
    )
    by_domain = {f["domain"]: f for f in findings}
    assert by_domain["boom.example"]["resolved"] is False
    assert "network unreachable" in by_domain["boom.example"]["error"]
    assert by_domain["fine.example"]["resolved"] is True


def test_completed_findings_are_marked_completed():
    findings = resolve_domains_parallel(
        ["a.example"], resolve_fn=lambda d, t: (True, None)
    )
    assert findings[0]["outcome"] == "completed"


def test_batch_deadline_returns_without_waiting_for_hung_lookups():
    """getaddrinfo cannot be bounded per lookup, so the deadline is the only
    real ceiling on a cycle. It must return early, not block for the full hang.
    """
    def hangs(domain, timeout):
        time.sleep(30)
        return (True, None)

    started = time.monotonic()
    findings = resolve_domains_parallel(
        ["hung.example"], resolve_fn=hangs, deadline_seconds=0.3
    )
    elapsed = time.monotonic() - started

    assert elapsed < 5, f"deadline did not bound the batch (took {elapsed:.1f}s)"
    assert findings[0]["outcome"] == "abandoned"
    assert findings[0]["resolved"] is False


def test_deadline_still_returns_one_finding_per_domain_in_order():
    def slow_for_one(domain, timeout):
        if domain == "hung.example":
            time.sleep(30)
        return (True, None)

    findings = resolve_domains_parallel(
        ["fast.example", "hung.example", "other.example"],
        resolve_fn=slow_for_one,
        max_workers=3,
        deadline_seconds=0.3,
    )

    assert [f["domain"] for f in findings] == [
        "fast.example",
        "hung.example",
        "other.example",
    ]
    by_domain = {f["domain"]: f for f in findings}
    assert by_domain["fast.example"]["outcome"] == "completed"
    assert by_domain["hung.example"]["outcome"] == "abandoned"


def test_fast_batch_under_its_deadline_is_unaffected():
    findings = resolve_domains_parallel(
        ["a.example", "b.example"],
        resolve_fn=lambda d, t: (True, None),
        deadline_seconds=30,
    )
    assert all(f["outcome"] == "completed" for f in findings)
    assert all(f["resolved"] is True for f in findings)
