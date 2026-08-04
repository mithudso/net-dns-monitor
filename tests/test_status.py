from netdnsmonitor.status import (
    PING_DOWN_TEXT,
    STATS_UNKNOWN,
    build_title,
    format_rate,
    format_stats,
    status_state,
)


def test_status_state_incident_takes_priority():
    assert status_state("incident", consecutive_failures=0) == "incident"
    assert status_state("incident", consecutive_failures=5) == "incident"


def test_status_state_flaky_on_nonzero_failures_below_threshold():
    assert status_state("healthy", consecutive_failures=1) == "flaky"


def test_status_state_healthy_when_no_failures():
    assert status_state("healthy", consecutive_failures=0) == "healthy"


def test_healthy_state_shows_healthy_regardless_of_past_classification():
    assert "healthy" in build_title("healthy", None).lower()
    assert "healthy" in build_title("healthy", "dns").lower()


def test_healthy_state_never_mentions_issue():
    assert "issue" not in build_title("healthy", "dns").lower()


def test_incident_state_includes_last_classification():
    title = build_title("incident", "dns")
    assert "dns" in title.lower()
    assert "issue" in title.lower()


def test_incident_state_with_no_classification_yet_says_unknown():
    title = build_title("incident", None)
    assert "unknown" in title.lower()


def test_zero_consecutive_failures_still_shows_healthy():
    assert "healthy" in build_title("healthy", None, consecutive_failures=0).lower()


def test_nonzero_consecutive_failures_below_threshold_shows_flaky():
    title = build_title("healthy", None, consecutive_failures=1)
    assert "flaky" in title.lower()
    assert "healthy" not in title.lower()
    assert "issue" not in title.lower()


def test_incident_takes_priority_over_consecutive_failures():
    title = build_title("incident", "dns", consecutive_failures=5)
    assert "issue" in title.lower()
    assert "flaky" not in title.lower()


def test_resolution_failures_appended_when_present():
    title = build_title("healthy", None, resolution_failed=3, resolution_total=50)
    assert "3/50" in title


def test_no_resolution_suffix_when_nothing_failed():
    title = build_title("healthy", None, resolution_failed=0, resolution_total=50)
    assert "50" not in title


def test_no_resolution_suffix_when_no_data_yet():
    title = build_title("healthy", None)
    assert "resolution fails" not in title


# Literals on purpose: asserting `ICONS["healthy"] in title` would read the
# same dict the code reads, so it holds even when the mapping is inverted.
GREEN, YELLOW, RED = "\U0001f7e2", "\U0001f7e1", "\U0001f534"


def test_title_glyph_colour_matches_the_state_it_reports():
    """The coloured circle is the signal; the word beside it is secondary --
    and no test in the repo asserted ICONS at all. Swapping the healthy and
    incident entries ships a red dot on a healthy network with the whole suite
    green. test_dock_icon.py already pins this same property for the Dock by
    sampling pixels, so the project treats it as worth testing.
    """
    healthy = build_title("healthy", None)
    assert GREEN in healthy
    assert RED not in healthy and YELLOW not in healthy

    incident = build_title("incident", "dns")
    assert RED in incident
    assert GREEN not in incident

    flaky = build_title("healthy", None, consecutive_failures=1)
    assert YELLOW in flaky
    assert GREEN not in flaky and RED not in flaky

    assert len({GREEN, YELLOW, RED}) == 3


def test_unknown_flap_state_is_treated_as_healthy_not_as_an_incident():
    """flap_state is a bare string, not an enum, so any renamed or future
    state lands here. Falling through to healthy is the deliberate fail-open
    choice, matching dock_icon's default, and nothing pinned it: replacing
    `== "incident"` with `!= "healthy"` passes the rest of this file.
    """
    assert status_state("degraded", consecutive_failures=0) == "healthy"
    assert status_state("", consecutive_failures=0) == "healthy"
    assert status_state("degraded", consecutive_failures=1) == "flaky"
    assert "issue" not in build_title("degraded", "dns").lower()


# --- the stats segment that replaced the signal-bars glyph -----------------


def test_no_signal_bars_glyph_remains_anywhere_in_the_title():
    """The request was to show network stats *instead of* a wifi signal icon.
    A leftover 📶 would sit right where the stats now go, so this is the pin
    that the replacement actually happened rather than the stats being appended
    alongside it.
    """
    for title in (
        build_title("healthy", None),
        build_title("healthy", None, consecutive_failures=1),
        build_title("incident", "dns"),
        build_title("healthy", None, stats="61ms", ping_down=True),
    ):
        assert "\U0001f4f6" not in title


def test_title_leads_with_the_stats_segment():
    assert build_title("healthy", None, stats="61ms 1.2M↓0.3M↑").startswith("61ms 1.2M↓0.3M↑")


def test_title_before_the_first_ping_shows_a_digit_free_placeholder():
    """It must not read as a measurement, and it must carry no digits -- see
    STATS_UNKNOWN's comment for why digits here would break the
    resolution-suffix assertions.
    """
    title = build_title("healthy", None)
    assert title.startswith(STATS_UNKNOWN)
    assert not any(char.isdigit() for char in STATS_UNKNOWN)


def test_a_failing_ping_turns_the_dot_red_even_while_the_gate_is_healthy():
    """The gate debounces a 30s TCP poll; the heartbeat is 5s. If ping_down
    didn't drive the indicator, the menu bar would keep showing green for up to
    a minute after the network dropped.
    """
    title = build_title("healthy", None, stats=PING_DOWN_TEXT, ping_down=True)
    assert RED in title
    assert GREEN not in title and YELLOW not in title


def test_a_failing_ping_reports_itself_as_a_ping_issue():
    assert "ping issue" in build_title("healthy", None, ping_down=True)


def test_a_failing_ping_does_not_borrow_a_stale_classification():
    """last_classification can still hold "dns" from an incident hours ago.
    Labelling a ping failure with it would send the user looking at the wrong
    subsystem.
    """
    title = build_title("healthy", "dns", ping_down=True)
    assert "ping issue" in title
    assert "dns" not in title


def test_a_real_incident_keeps_its_own_classification_when_ping_also_fails():
    """When the gate has actually declared a DNS incident, that is the more
    specific and more useful label of the two.
    """
    assert "dns issue" in build_title("incident", "dns", ping_down=True)


def test_ping_down_outranks_the_flaky_heuristic():
    title = build_title("healthy", None, consecutive_failures=1, ping_down=True)
    assert "issue" in title
    assert "flaky" not in title


def test_status_state_reports_incident_when_pings_are_unanswered():
    assert status_state("healthy", consecutive_failures=0, ping_down=True) == "incident"


def test_status_state_stays_healthy_when_pings_are_answered():
    assert status_state("healthy", consecutive_failures=0, ping_down=False) == "healthy"


def test_resolution_suffix_still_appends_after_the_stats_segment():
    title = build_title("healthy", None, resolution_failed=3, resolution_total=50, stats="61ms")
    assert title.startswith("61ms")
    assert "3/50" in title


# --- format_stats ----------------------------------------------------------


def test_stats_show_round_trip_time_in_whole_milliseconds():
    assert format_stats(rtt_ms=61.366) == "61ms"


def test_stats_show_no_reply_when_pings_are_unanswered():
    assert format_stats(rtt_ms=None, ping_down=True) == PING_DOWN_TEXT


def test_ping_down_suppresses_a_stale_reading():
    """Rendering the last good rtt and throughput next to a dead network reads
    as a working connection.
    """
    stats = format_stats(rtt_ms=61.0, down_bps=1e6, up_bps=1e6, ping_down=True)
    assert stats == PING_DOWN_TEXT


def test_stats_include_throughput_in_both_directions():
    stats = format_stats(rtt_ms=61.0, down_bps=1_200_000, up_bps=300_000)
    assert "1.2M↓" in stats
    assert "300K↑" in stats


def test_zero_loss_is_omitted_to_save_menu_bar_width():
    assert "%" not in format_stats(rtt_ms=61.0, loss_pct=0.0)


def test_nonzero_loss_is_shown():
    assert "8%" in format_stats(rtt_ms=61.0, loss_pct=8.3)


def test_stats_with_nothing_measured_yet_fall_back_to_the_placeholder():
    assert format_stats() == STATS_UNKNOWN


def test_measured_idle_throughput_is_shown_as_zero_not_omitted():
    """(None, None) means "not measured" and (0, 0) means "measured, idle";
    collapsing the two would make a stalled meter look like an idle network.
    """
    stats = format_stats(rtt_ms=61.0, down_bps=0.0, up_bps=0.0)
    assert "0↓0↑" in stats


def test_unmeasured_throughput_is_omitted_entirely():
    assert format_stats(rtt_ms=61.0) == "61ms"


# --- format_rate -----------------------------------------------------------


def test_rate_scales_to_kilo_mega_and_giga():
    assert format_rate(300_000) == "300K"
    assert format_rate(1_200_000) == "1.2M"
    assert format_rate(2_500_000_000) == "2.5G"


def test_sub_kilobit_rate_renders_as_zero_rather_than_a_long_number():
    assert format_rate(500) == "0"
    assert format_rate(0) == "0"


def test_unmeasured_rate_is_empty():
    assert format_rate(None) == ""
