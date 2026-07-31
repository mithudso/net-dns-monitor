"""select_stalled_domains decides what the resolution monitor retries, so the
cases pinned here are the ones that separate "stalled" from "failed" -- a fast
failure must be excluded and a slow success must be included.
"""

import json

from netdnsmonitor.stall_log import select_stalled_domains


def _write_log(tmp_path, records):
    path = tmp_path / "resolution-log.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return str(path)


def _record(domain, elapsed, resolved=False, checked_at="2026-07-01T00:00:00+00:00", **extra):
    record = {
        "domain": domain,
        "resolved": resolved,
        "error": None if resolved else "[Errno 8] nodename nor servname provided, or not known",
        "elapsed_seconds": elapsed,
        "checked_at": checked_at,
    }
    record.update(extra)
    return record


def test_fast_failure_excluded_but_slow_success_included(tmp_path):
    """The whole point of the elapsed-time reading. An instant NXDOMAIN is a
    definitive answer, not a stall; a lookup that took 30s and *succeeded* is
    exactly what we want to keep watching.
    """
    path = _write_log(
        tmp_path,
        [
            _record("com.apple.mDNSResponder", 0.07, resolved=False),
            _record("seed.siri.apple.com", 30.11, resolved=True),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == ["seed.siri.apple.com"]


def test_slow_failure_is_also_a_stall(tmp_path):
    path = _write_log(tmp_path, [_record("Bedroom.local", 35.0, resolved=False)])

    assert select_stalled_domains(path, stall_seconds=1.0) == ["Bedroom.local"]


def test_domain_that_stalled_once_stays_selected_after_a_fast_run(tmp_path):
    """"Ever stalled" is the requirement -- one clean fast run afterwards must
    not drop a domain off the list.
    """
    path = _write_log(
        tmp_path,
        [
            _record("flaky.example.com", 12.0, checked_at="2026-07-01T00:00:00+00:00"),
            _record("flaky.example.com", 0.02, resolved=True, checked_at="2026-07-02T00:00:00+00:00"),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == ["flaky.example.com"]


def test_abandoned_records_are_not_stall_evidence(tmp_path):
    """Abandoned means the batch ran out of time, which can be caused by other
    slow domains. Counting it would let the list grow itself without bound.
    """
    path = _write_log(
        tmp_path,
        [
            _record(
                "queued.example.com",
                240.0,
                error="batch deadline exceeded before this lookup finished",
                outcome="abandoned",
            )
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == []


def test_abandonment_does_not_count_as_a_check(tmp_path):
    """The ordering guarantee depends on this. One `checked_at` is stamped per
    batch, so if an abandonment counted as a check, every domain a cycle
    touched would tie on timestamp, `sorted` would fall through to the name
    tiebreak, and the deadline-truncated tail would be abandoned again every
    cycle forever.

    The names are chosen so alphabetical order *opposes* timestamp order: the
    abandoned domain sorts last by name but first by timestamp. If the
    bookkeeping ever counted an abandonment as a check, both would tie at
    07-02 and the name tiebreak would flip this assertion.
    """
    path = _write_log(
        tmp_path,
        [
            _record("zulu.example.com", 30.0, checked_at="2026-07-01T00:00:00+00:00"),
            _record("alpha.example.com", 30.0, checked_at="2026-07-01T00:00:00+00:00"),
            # One later cycle: both were queued, only alpha finished.
            _record(
                "zulu.example.com",
                240.0,
                error="batch deadline exceeded before this lookup finished",
                outcome="abandoned",
                checked_at="2026-07-02T00:00:00+00:00",
            ),
            _record(
                "alpha.example.com",
                30.0,
                outcome="completed",
                checked_at="2026-07-02T00:00:00+00:00",
            ),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == [
        "zulu.example.com",
        "alpha.example.com",
    ]


def test_a_fast_completion_still_advances_the_check_timestamp(tmp_path):
    """The other half of the bookkeeping rule: every *completed* lookup counts
    as a check, whether or not it stalled this time. Restricting the timestamp
    update to stalling records would leave a fast-completing domain pinned to
    its ancient timestamp, permanently hogging the front of the queue -- so
    `flaky` (last completed 07-03) must sort *behind* `steady` (07-02).
    """
    path = _write_log(
        tmp_path,
        [
            _record("flaky.example.com", 12.0, checked_at="2026-07-01T00:00:00+00:00"),
            _record("steady.example.com", 12.0, checked_at="2026-07-02T00:00:00+00:00"),
            # A fast, non-stalling run: still a check.
            _record(
                "flaky.example.com",
                0.02,
                resolved=True,
                checked_at="2026-07-03T00:00:00+00:00",
            ),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == [
        "steady.example.com",
        "flaky.example.com",
    ]


def test_stalled_domain_with_no_usable_checked_at_sorts_first(tmp_path):
    """A record with no usable `checked_at` is treated as never checked. The
    absent-timestamp default has to stay a default -- indexing `last_checked`
    directly would raise on any log line lacking the field.
    """
    path = _write_log(
        tmp_path,
        [
            {"domain": "no-timestamp.example.com", "resolved": False, "elapsed_seconds": 9.0},
            _record("stamped.example.com", 9.0, checked_at="2026-07-01T00:00:00+00:00"),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == [
        "no-timestamp.example.com",
        "stamped.example.com",
    ]


def test_a_corrupt_byte_mid_file_does_not_drop_the_records_after_it(tmp_path):
    """Goes through the *default* opener on purpose -- this is the test for
    `_open_lenient`. The log is append-only and chronological, so a strict
    decode would end the read at the bad byte and silently drop every newer
    record, including any domain whose only stall sits near the tail.
    """
    path = tmp_path / "resolution-log.jsonl"
    path.write_bytes(
        json.dumps(_record("early.example.com", 9.0, checked_at="2026-07-01T00:00:00+00:00")).encode()
        + b"\n"
        # Invalid UTF-8 in the JSON *syntax*, so replacement leaves a line that
        # cannot parse and is skipped like any torn line.
        + b'{"domain": "corrupt.example.com", \xff"elapsed_seconds": 9.0}\n'
        + json.dumps(_record("late.example.com", 9.0, checked_at="2026-07-02T00:00:00+00:00")).encode()
        + b"\n"
    )

    assert select_stalled_domains(str(path), stall_seconds=1.0) == [
        "early.example.com",
        "late.example.com",
    ]


def test_a_domain_mangled_by_decode_replacement_never_enters_the_stall_set(tmp_path):
    """Corruption inside the quoted domain value leaves *valid* JSON with a
    U+FFFD in the name. The stall set is closed and never shrinks, so admitting
    a garbage name would keep it under permanent re-probe.
    """
    path = tmp_path / "resolution-log.jsonl"
    path.write_bytes(
        b'{"domain": "ex\xffample.com", "resolved": false, '
        b'"elapsed_seconds": 9.0, "checked_at": "2026-07-01T00:00:00+00:00"}\n'
        + json.dumps(_record("clean.example.com", 9.0)).encode()
        + b"\n"
    )

    assert select_stalled_domains(str(path), stall_seconds=1.0) == ["clean.example.com"]


def test_read_failure_part_way_through_keeps_the_records_already_parsed():
    """A missing log means "no history" and returns []. A read that dies
    part-way through a 16k-line file is not the same thing -- reporting []
    there would silently disable the monitor. The records parsed before the
    failure are kept; the ones after it are unavoidably lost, which is why
    `_open_lenient` keeps ordinary corruption from reaching this path at all.
    """

    class _FailsAfterFirstLine:
        """Also the closest available proxy for the streaming requirement: the
        first line is only observable if the caller consumes lines lazily.
        """

        def __init__(self, lines):
            self._lines = lines

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def __iter__(self):
            yield self._lines[0]
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    lines = [
        json.dumps(_record("early.example.com", 9.0)) + "\n",
        json.dumps(_record("late.example.com", 9.0)) + "\n",
    ]

    assert select_stalled_domains(
        "irrelevant.jsonl",
        stall_seconds=1.0,
        opener=lambda _path: _FailsAfterFirstLine(lines),
    ) == ["early.example.com"]


def test_threshold_is_inclusive_and_respected(tmp_path):
    path = _write_log(
        tmp_path,
        [
            _record("exactly.example.com", 5.0),
            _record("under.example.com", 4.999),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=5.0) == ["exactly.example.com"]


def test_ordered_least_recently_checked_first(tmp_path):
    """A deadline-bounded cycle cannot always finish a growing list, so the
    tail must not starve.
    """
    path = _write_log(
        tmp_path,
        [
            _record("newest.example.com", 9.0, checked_at="2026-07-03T00:00:00+00:00"),
            _record("oldest.example.com", 9.0, checked_at="2026-07-01T00:00:00+00:00"),
            _record("middle.example.com", 9.0, checked_at="2026-07-02T00:00:00+00:00"),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == [
        "oldest.example.com",
        "middle.example.com",
        "newest.example.com",
    ]


def test_latest_checked_at_per_domain_drives_ordering(tmp_path):
    path = _write_log(
        tmp_path,
        [
            _record("a.example.com", 9.0, checked_at="2026-07-01T00:00:00+00:00"),
            _record("a.example.com", 9.0, checked_at="2026-07-09T00:00:00+00:00"),
            _record("b.example.com", 9.0, checked_at="2026-07-05T00:00:00+00:00"),
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == [
        "b.example.com",
        "a.example.com",
    ]


def test_missing_log_returns_empty_rather_than_raising(tmp_path):
    assert select_stalled_domains(str(tmp_path / "nope.jsonl")) == []


def test_torn_and_blank_lines_are_skipped(tmp_path):
    path = tmp_path / "resolution-log.jsonl"
    path.write_text(
        json.dumps(_record("good.example.com", 9.0))
        + "\n\n"
        + '{"domain": "torn.example.com", "elapsed_sec\n'
        + "[1, 2, 3]\n"
        + json.dumps(_record("also-good.example.com", 9.0))
        + "\n"
    )

    assert select_stalled_domains(str(path), stall_seconds=1.0) == [
        "also-good.example.com",
        "good.example.com",
    ]


def test_records_without_usable_fields_are_ignored(tmp_path):
    path = _write_log(
        tmp_path,
        [
            {"resolved": False, "elapsed_seconds": 9.0},
            {"domain": "", "elapsed_seconds": 9.0},
            {"domain": "no-elapsed.example.com", "resolved": False},
            {"domain": "bad-elapsed.example.com", "elapsed_seconds": "9.0"},
        ],
    )

    assert select_stalled_domains(path, stall_seconds=1.0) == []
