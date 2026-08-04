"""The fixtures here are real lines captured from this machine's unified log, not
invented ones. Two of them are the reason the module looks the way it does: the
`identityservicesd` line is the signal (a socket that could not reach the
network), and the `com.crowdstrike.falcon.Agent` line is the noise it was buried
under -- it repeated hundreds of times in a 15-minute window.
"""

import subprocess
from types import SimpleNamespace

from netdnsmonitor.system_log import (
    DEFAULT_NOISE_PATTERNS,
    LogBuffer,
    build_predicate,
    coalesce,
    format_entries,
    format_entry,
    is_error,
    is_noise,
    log_show_command,
    make_log_reader,
    matches,
    parse_lines,
    summarize,
)

HEADER = "Timestamp               Ty Process[PID:TID]"

UNREACHABLE = (
    "2026-08-04 12:48:56.386 E  identityservicesd[762:ac80d] "
    "[com.apple.network:connection] nw_socket_handle_socket_event [C134.1.1:3] "
    "Socket SO_ERROR [51: Network is unreachable]"
)

CROWDSTRIKE_NOISE = (
    "2026-08-04 12:48:45.379 E  com.crowdstrike.falcon.Agent[580:a8fb7] "
    "[com.apple.network:] nw_endpoint_get_address called with null endpoint, "
    "backtrace limit exceeded"
)

MDNS_DEFAULT = (
    "2026-08-04 12:48:48.537 Df mDNSResponder[441:ac0cd] [com.apple.mdns:dnssd_server] "
    "[R20823] getaddrinfo start -- hostname: <mask.hash: 'bUgVj5G8ik0EQt8fUVm4Fg=='>"
)

MULTILINE = [
    "2026-08-04 12:48:48.430 Df sharingd[772:ac997] [com.apple.sharing:TetheringAgent] "
    "Devices changed: yes {",
    '    "DD4024BA-E996" : <SFRemoteHotspotDevice: name: iPad, network type: 5G>,',
    "}",
]


def entry(**overrides) -> dict:
    base = {
        "timestamp": "2026-08-04 12:00:00.000",
        "time": "12:00:00",
        "severity": "error",
        "process": "someprocess",
        "subsystem": "com.apple.network",
        "message": "something went wrong",
        "raw": "raw line",
    }
    base.update(overrides)
    return base


# --- the predicate and the command -----------------------------------------


def test_errors_only_predicate_filters_on_message_type_not_on_text():
    """The filter has to run inside `log`'s own archive scan. Measured: the same
    subsystems unfiltered returned 192,901 lines over 30 minutes; filtered to
    error and fault, 919 over 15 minutes. A text filter in Python would have to
    receive all 192,901 first.
    """
    predicate = build_predicate(errors_only=True)
    assert "messageType == 16" in predicate
    assert "messageType == 17" in predicate


def test_all_levels_predicate_keeps_the_scope_but_drops_the_level_filter():
    predicate = build_predicate(errors_only=False)
    assert "messageType" not in predicate
    assert "mDNSResponder" in predicate
    assert 'subsystem BEGINSWITH "com.apple.network"' in predicate


def test_the_command_names_log_by_absolute_path_and_honours_the_window():
    """Absolute path for the same reason ping.py and app.py use one: the PATH a
    launchd agent inherits is not the one a shell has.
    """
    command = log_show_command("7m", errors_only=True)
    assert command[0] == "/usr/bin/log"
    assert command[1] == "show"
    assert "--last" in command
    assert command[command.index("--last") + 1] == "7m"
    assert "compact" in command


# --- parsing ---------------------------------------------------------------


def test_a_real_error_line_parses_into_its_parts():
    (parsed,) = parse_lines([UNREACHABLE])
    assert parsed["time"] == "12:48:56"
    assert parsed["timestamp"] == "2026-08-04 12:48:56.386"
    assert parsed["severity"] == "error"
    assert parsed["process"] == "identityservicesd"
    assert parsed["subsystem"] == "com.apple.network:connection"
    assert "Network is unreachable" in parsed["message"]


def test_a_dotted_process_name_is_not_mistaken_for_part_of_the_message():
    """`com.crowdstrike.falcon.Agent` is a real process name with dots in it, so
    the process pattern cannot stop at the first dot.
    """
    (parsed,) = parse_lines([CROWDSTRIKE_NOISE])
    assert parsed["process"] == "com.crowdstrike.falcon.Agent"


def test_the_log_header_row_does_not_become_an_entry():
    """`log show` prints a column header. Without this it lands in the pane as an
    entry with no timestamp, at whatever position the sort puts it.
    """
    parsed = parse_lines([HEADER, UNREACHABLE])
    assert len(parsed) == 1


def test_a_multi_line_message_stays_one_entry():
    """The regression this guards: splitting output on newlines and treating each
    line as an entry produced roughly 14,000 header-less fragments in a 5-minute
    sample, because framework messages embed dictionaries.
    """
    parsed = parse_lines(MULTILINE)
    assert len(parsed) == 1
    assert "SFRemoteHotspotDevice" in parsed[0]["message"]
    assert parsed[0]["process"] == "sharingd"


def test_a_line_with_no_subsystem_bracket_still_parses():
    parsed = parse_lines(
        ["2026-08-04 12:48:50.030 Df cupsd[460:1554] (libsystem_info.dylib) Too many groups"]
    )
    assert parsed[0]["process"] == "cupsd"
    assert parsed[0]["subsystem"] == ""
    assert "Too many groups" in parsed[0]["message"]


def test_severity_comes_from_the_type_column():
    assert is_error(parse_lines([UNREACHABLE])[0])
    assert not is_error(parse_lines([MDNS_DEFAULT])[0])
    assert parse_lines([MDNS_DEFAULT])[0]["severity"] == "default"


# --- noise -----------------------------------------------------------------


def test_the_shipped_noise_list_drops_the_line_it_was_written_for():
    assert is_noise(parse_lines([CROWDSTRIKE_NOISE])[0], DEFAULT_NOISE_PATTERNS)
    assert not is_noise(parse_lines([UNREACHABLE])[0], DEFAULT_NOISE_PATTERNS)


def test_an_empty_noise_list_suppresses_nothing():
    """A config that sets `log_view_noise_patterns: []` must show everything, not
    fall back to the defaults.
    """
    assert not is_noise(parse_lines([CROWDSTRIKE_NOISE])[0], ())


# --- search ----------------------------------------------------------------


def test_an_empty_search_matches_everything():
    assert matches(entry(), "")
    assert matches(entry(), "   ")


def test_search_is_case_insensitive_and_covers_the_process_name():
    assert matches(entry(process="mDNSResponder"), "mdnsresponder")
    assert matches(entry(message="Network is unreachable"), "UNREACHABLE")


def test_every_term_must_match():
    subject = entry(process="identityservicesd", message="Socket SO_ERROR unreachable")
    assert matches(subject, "socket unreachable")
    assert not matches(subject, "socket refused")


def test_a_leading_minus_excludes():
    """The one operator worth having: the pane's whole problem is one repeated
    message, and `-crowdstrike` is how someone gets rid of it without editing a
    config file.
    """
    subject = entry(process="com.crowdstrike.falcon.Agent", message="null endpoint")
    assert matches(subject, "endpoint")
    assert not matches(subject, "endpoint -crowdstrike")


def test_a_bracketed_connection_id_can_be_pasted_into_the_search():
    """Substring, not regex, so `[C134.1.1:3]` is a search rather than an error."""
    assert matches(parse_lines([UNREACHABLE])[0], "[C134.1.1:3]")


# --- coalescing ------------------------------------------------------------


def test_identical_messages_collapse_into_one_counted_row():
    rows = coalesce([entry(time="12:00:01"), entry(time="12:00:02"), entry(time="12:00:03")])
    assert len(rows) == 1
    assert rows[0]["count"] == 3


def test_a_collapsed_row_carries_the_most_recent_time():
    """Otherwise a burst that started an hour ago is timestamped an hour ago while
    it is still happening.
    """
    rows = coalesce([entry(time="12:00:01"), entry(time="12:30:00")])
    assert rows[0]["time"] == "12:30:00"


def test_the_same_message_from_different_processes_stays_separate():
    rows = coalesce([entry(process="a"), entry(process="b")])
    assert len(rows) == 2


def test_rows_are_ordered_newest_first():
    rows = coalesce([entry(message="old"), entry(message="new")])
    assert [row["message"] for row in rows] == ["new", "old"]


def test_a_repeat_count_is_visible_in_the_formatted_line():
    (row,) = coalesce([entry(), entry()])
    assert "(x2)" in format_entry(row)
    assert "(x" not in format_entry(entry())


def test_errors_are_flagged_in_the_formatted_line():
    assert "!" in format_entry(entry(severity="error"))
    assert "!" not in format_entry(entry(severity="default", message="quiet"))


def test_formatting_nothing_produces_nothing_rather_than_a_blank_line():
    assert format_entries([]) == ""


# --- the buffer ------------------------------------------------------------


def test_an_overlapping_poll_does_not_store_the_same_entry_twice():
    """The poll window (1 minute) is deliberately longer than the poll interval
    (30 seconds) so nothing is missed in between, which means everything arrives
    about twice.
    """
    buffer = LogBuffer(max_entries=100)
    parsed = parse_lines([UNREACHABLE])
    assert len(buffer.add(parsed)) == 1
    assert buffer.add(parse_lines([UNREACHABLE])) == []
    assert len(buffer.entries()) == 1


def test_add_returns_only_what_was_new_so_the_caller_can_announce_it():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE]))
    added = buffer.add(parse_lines([UNREACHABLE, CROWDSTRIKE_NOISE]))
    assert len(added) == 1
    assert added[0]["process"] == "com.crowdstrike.falcon.Agent"


def test_the_buffer_is_bounded_and_forgets_the_oldest_first():
    buffer = LogBuffer(max_entries=3)
    buffer.add([entry(timestamp=f"t{index}", message=f"m{index}") for index in range(5)])
    assert len(buffer.entries()) == 3
    assert [item["message"] for item in buffer.entries()] == ["m2", "m3", "m4"]


def test_an_evicted_entry_can_be_stored_again():
    """The de-duplication key set has to be trimmed alongside the entries, or a
    message that recurs after eviction is silently dropped forever.
    """
    buffer = LogBuffer(max_entries=1)
    first = entry(timestamp="t0", message="m0")
    buffer.add([first])
    buffer.add([entry(timestamp="t1", message="m1")])
    assert len(buffer.add([first])) == 1


def test_the_buffer_counts_errors_separately_from_entries():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE, MDNS_DEFAULT]))
    assert len(buffer.entries()) == 2
    assert buffer.error_count() == 1


def test_clearing_empties_both_the_entries_and_the_seen_keys():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE]))
    buffer.clear()
    assert buffer.entries() == []
    assert len(buffer.add(parse_lines([UNREACHABLE]))) == 1


# --- the view --------------------------------------------------------------


def test_the_view_suppresses_noise_and_keeps_the_signal():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE, CROWDSTRIKE_NOISE]))
    view = buffer.view(noise_patterns=DEFAULT_NOISE_PATTERNS)
    assert "Network is unreachable" in view["text"]
    assert "crowdstrike" not in view["text"].lower()
    assert view["total"] == 1


def test_the_view_can_show_only_errors_without_another_log_query():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE, MDNS_DEFAULT]))
    assert buffer.view(errors_only=False, noise_patterns=())["total"] == 2
    assert buffer.view(errors_only=True, noise_patterns=())["total"] == 1


def test_the_view_reports_how_many_matched_the_search():
    buffer = LogBuffer()
    buffer.add(parse_lines([UNREACHABLE, MDNS_DEFAULT]))
    view = buffer.view(query="unreachable", noise_patterns=())
    assert view["total"] == 2
    assert view["shown"] == 1
    assert "getaddrinfo" not in view["text"]


def test_the_view_limit_caps_the_rendered_rows():
    buffer = LogBuffer()
    buffer.add([entry(timestamp=f"t{i}", message=f"m{i}") for i in range(10)])
    view = buffer.view(limit=3, noise_patterns=())
    assert view["text"].strip().count("\n") == 2
    assert view["shown"] == 10


def test_the_view_limit_keeps_the_newest_rows_and_coalesces_before_truncating():
    """A newline count alone cannot see which rows survived -- `rows[-limit:]`
    passes the test above unchanged. Newest-first-then-truncate is the whole point
    of coalesce's ordering ("a burst of one message does not push everything else
    off the pane"), so it gets pinned directly, together with the ordering of the
    two operations: collapse duplicates first, then cut.
    """
    buffer = LogBuffer()
    buffer.add(
        [entry(timestamp=f"t{i}", message="repeated") for i in range(4)]
        + [entry(timestamp=f"u{i}", message=f"m{i}") for i in range(3)]
    )
    view = buffer.view(limit=2, noise_patterns=())

    assert view["text"].strip().count("\n") == 1
    assert "m2" in view["text"] and "m1" in view["text"]
    assert "m0" not in view["text"] and "repeated" not in view["text"]
    # Counts describe everything captured, not just what was drawn.
    assert view["shown"] == 7
    # Four copies became one row before the limit applied, not four of the seven.
    assert [row["message"] for row in view["rows"]] == ["m2", "m1", "m0", "repeated"]
    assert view["rows"][-1]["count"] == 4


# --- the status line -------------------------------------------------------


def test_nothing_captured_and_nothing_matched_read_differently():
    """An empty pane otherwise means both "your search excluded everything" and
    "the network log is silent", and only one of those is interesting.
    """
    empty = summarize(total=0, shown=0, errors=0, query="", error=None)
    no_match = summarize(total=40, shown=0, errors=3, query="wifi", error=None)
    assert "no network log" in empty.lower()
    assert "no match" in no_match.lower()
    assert empty != no_match


def test_a_read_failure_replaces_the_counts_rather_than_hiding_behind_them():
    assert summarize(total=0, shown=0, errors=0, query="", error="boom") == "boom"


# --- the reader ------------------------------------------------------------


def test_a_successful_read_returns_parsed_entries_and_no_error():
    def run_fn(*_args, **_kwargs):
        return SimpleNamespace(returncode=0, stdout=HEADER + "\n" + UNREACHABLE + "\n", stderr="")

    result = make_log_reader(run_fn=run_fn)("1m")
    assert result["error"] is None
    assert len(result["entries"]) == 1


def test_a_timeout_is_reported_as_text_not_as_an_empty_log():
    """This is the failure this module is most likely to hit -- `log show` over a
    60-minute window measured 16.9s on this machine. An empty pane would read as
    a quiet network.
    """

    def run_fn(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="log", timeout=45)

    result = make_log_reader(run_fn=run_fn)("60m")
    assert result["entries"] == []
    assert "longer than" in result["error"]
    assert "60m" in result["error"]


def test_a_nonzero_exit_is_reported_with_the_first_line_of_stderr():
    def run_fn(*_args, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="bad predicate\nmore detail\n")

    result = make_log_reader(run_fn=run_fn)("1m")
    assert "bad predicate" in result["error"]


def test_an_oserror_is_reported_rather_than_raised_into_the_caller():
    """The caller is a worker thread whose exception nobody sees."""

    def run_fn(*_args, **_kwargs):
        raise OSError("no such file")

    result = make_log_reader(run_fn=run_fn)("1m")
    assert result["entries"] == []
    assert "no such file" in result["error"]


def test_the_reader_passes_the_window_and_level_through_to_the_command():
    seen = {}

    def run_fn(command, **_kwargs):
        seen["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    make_log_reader(run_fn=run_fn)("3m", errors_only=False)
    assert seen["command"][seen["command"].index("--last") + 1] == "3m"
    assert "messageType" not in " ".join(seen["command"])
