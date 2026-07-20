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
