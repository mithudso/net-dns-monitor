"""The collapsed always-on-top panel.

`mini_text` is pure and gets ordinary assertions. The panel itself is built for
real rather than mocked, the same choice test_dashboard.py and test_dock_icon.py
make: NSPanel construction works headlessly, and the four settings this window
depends on are exactly the ones that fail silently in a bundle -- a panel that
looks right in a screenshot and then buries itself the moment you click away.
`show()` is never called; that would flash a panel across the screen every run.

This file did not exist until 2026-08-08. Nothing in tests/ imported
mini_window at all, so every property below was unpinned.
"""

from netdnsmonitor.mini_window import (
    FRAME_AUTOSAVE_NAME,
    HEIGHT,
    WIDTH,
    MiniWindow,
    mini_text,
)

# Literals on purpose, for the reason test_status.py records about the title
# glyphs: asserting `DOT["healthy"] in text` reads the same dict the code reads,
# so it holds even when the mapping is inverted.
GREEN, YELLOW, RED = "\U0001f7e2", "\U0001f7e1", "\U0001f534"


# --- mini_text ---------------------------------------------------------------


def test_incident_spells_out_down_rather_than_showing_a_number():
    """The docstring's own claim: "DOWN" beats a dash someone has to interpret
    while walking past. With no reason given -- the caller predates `reason` --
    the panel keeps its old wording, and a round-trip time during an incident
    would be a stale reading presented as current.
    """
    text = mini_text("incident", rtt_ms=61.4, ping_down=True)
    assert "DOWN" in text
    assert "61" not in text


def test_a_dns_incident_names_dns_rather_than_claiming_the_network_is_down():
    """Pings answering and names failing is the one incident where "DOWN" sends
    someone to check the cable instead of the resolver.
    """
    text = mini_text("incident", rtt_ms=30, reason="dns")
    assert "DNS" in text
    assert "DOWN" not in text
    assert "30" not in text
    assert RED in text


def test_ping_and_network_incidents_still_read_down():
    for reason in (None, "ping", "network"):
        assert mini_text("incident", rtt_ms=30, reason=reason) == f"{RED}  DOWN"


def test_an_unclassified_incident_is_not_presented_as_down():
    """Unclassified means a load-bearing probe never ran. Showing "DOWN" would
    turn that unknown into a failed reading.
    """
    text = mini_text("incident", reason="unclassified")
    assert "DOWN" not in text
    assert "UNCLASSIFIED" in text


def test_a_reason_changes_nothing_outside_an_incident():
    """The app passes the last classification on every refresh, and it can
    outlive the incident that set it.
    """
    assert mini_text("healthy", rtt_ms=61.4, reason="dns") == f"{GREEN}  61ms"
    assert mini_text("flaky", rtt_ms=61.4, reason="dns") == f"{YELLOW}  61ms"


def test_a_dns_only_incident_keeps_the_live_round_trip():
    """DNS broken, pings answered: the network is not down, and saying so sends
    someone after the wrong fault. The red dot carries the incident; the
    number carries the evidence that the link itself is alive.
    """
    text = mini_text("incident", rtt_ms=61.4, ping_down=False)
    assert RED in text
    assert "61ms" in text
    assert "DOWN" not in text


def test_healthy_shows_the_round_trip_time_in_whole_milliseconds():
    assert mini_text("healthy", rtt_ms=61.366) == f"{GREEN}  61ms"


def test_no_reading_yet_shows_a_placeholder_not_a_zero():
    """Covers the first seconds after launch. "0ms" would read as a measurement
    that was never taken -- the same reason status.STATS_UNKNOWN is digit-free.
    """
    text = mini_text("healthy", rtt_ms=None)
    assert "--" in text
    assert not any(char.isdigit() for char in text)


def test_loss_is_shown_only_when_it_is_nonzero():
    """168px of width is the scarce resource here, and "0%" on a healthy
    network spends it saying nothing.
    """
    assert "%" not in mini_text("healthy", rtt_ms=61.4, loss_pct=0)
    assert "12%" in mini_text("healthy", rtt_ms=61.4, loss_pct=12.4)


def test_the_dot_colour_matches_the_state_it_reports():
    """Swapping the healthy and incident entries in DOT ships a red dot on a
    healthy network, and nothing else in the suite would notice.
    """
    healthy = mini_text("healthy", rtt_ms=10)
    assert GREEN in healthy and RED not in healthy and YELLOW not in healthy

    flaky = mini_text("flaky", rtt_ms=10)
    assert YELLOW in flaky and GREEN not in flaky and RED not in flaky

    incident = mini_text("incident")
    assert RED in incident and GREEN not in incident

    assert len({GREEN, YELLOW, RED}) == 3


def test_an_unknown_state_falls_back_to_healthy_rather_than_raising():
    """`state` is a bare string, not an enum, so any renamed or future state
    lands here. Falling through is the deliberate fail-open choice, matching
    status.status_state and dock_icon's default.
    """
    text = mini_text("degraded", rtt_ms=61.4)
    assert GREEN in text
    assert "61ms" in text


# --- the panel ---------------------------------------------------------------


def test_the_panel_floats_above_ordinary_windows():
    """Without this it is buried by the next window you click, which defeats
    the one thing a glanceable panel is for.
    """
    import AppKit

    window = MiniWindow()
    assert window.window.level() == AppKit.NSFloatingWindowLevel


def test_the_panel_does_not_hide_when_the_app_deactivates():
    """The setting the module docstring calls out as the one people miss.
    NSPanel hides on deactivation by default -- precisely when you want to
    glance at it.
    """
    window = MiniWindow()
    assert window.window.hidesOnDeactivate() is False


def test_the_panel_remembers_where_it_was_left():
    """Free position memory via user defaults, and no config key. A missing
    autosave name recentres the panel on every launch.
    """
    window = MiniWindow()
    assert str(window.window.frameAutosaveName()) == FRAME_AUTOSAVE_NAME


def test_the_panel_is_draggable_by_its_background():
    """It is borderless, so there is no title bar to drag it by."""
    window = MiniWindow()
    assert window.window.isMovableByWindowBackground() is True


def test_the_longest_incident_label_fits_the_panel():
    """The panel is 168px and the label does not wrap, so a reason spelled out
    too long is clipped into something unreadable at a glance.
    """
    window = MiniWindow()
    window.set_text(mini_text("incident", reason="unclassified"))
    assert window.label.attributedStringValue().size().width <= WIDTH


def test_the_panel_opens_at_the_declared_size():
    window = MiniWindow()
    frame = window.window.frame()
    assert (frame.size.width, frame.size.height) == (WIDTH, HEIGHT)


def test_the_panel_is_not_released_when_closed():
    """Retain policy, the same property test_dashboard.py pins: a panel released
    on close leaves the next open touching freed memory.

    Named for what it asserts rather than for the symptom. Actually closing and
    reopening would be the stronger test, but `close()` on a panel that was
    never ordered front is not the path the bug takes, and asserting the flag is
    honest about what is being checked. `mini_window` sets all five of these
    explicitly, so none of these tests is pinning an AppKit default.
    """
    window = MiniWindow()
    assert window.window.isReleasedWhenClosed() is False
