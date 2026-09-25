"""A real window: current network statistics, the settings in force, and
buttons that run each troubleshooting step by hand.

Until now the only UI was the status-item title and a two-item dropdown. That
left no way to see anything beyond a one-line summary, and no way to *do*
anything on purpose -- the ladder only ran when the anti-flap gate decided to
run it.

The content is split from the window on purpose, the same way status.py is split
from app.py: `dashboard_sections` and `render_dashboard_text` are pure and
tested without AppKit, and `DashboardWindow` only draws what they return.

Four AppKit details that each break this outright if missed:

1. **The window must be retained by Python.** An NSWindow with no strong
   reference is collected out from under AppKit, which looks exactly like "no
   window appears". `App` keeps `self._dashboard`, and this class keeps its own
   references to every subview it needs to update.
2. **`setReleasedWhenClosed_(False)`.** Otherwise closing the window
   deallocates it and the next open touches freed memory.
3. **`makeKeyAndOrderFront_` alone is not enough.** For a non-active
   application the window opens *behind* whatever is frontmost, which would
   reproduce the very complaint this exists to fix, so `show` also calls
   `activateIgnoringOtherApps_(True)`.
4. **Nothing here may be constructed in `App.__init__`.** Eleven tests build
   NetDnsMonitorApp directly and would each pop a window; the window is created
   lazily on first open, the same rule the ping worker follows.

Plain AppKit only -- NSWindow, NSTextView, NSButton. Anything else would mean
adding a framework to `packages` in setup.py, and this project's bundling has
already cost several commits.
"""

import sys
import traceback
from typing import Callable, Optional

from netdnsmonitor.graphs import format_bits
from netdnsmonitor.peers import BUCKETS

WINDOW_TITLE = "Net-DNS-Monitor"

# A peer's hostname is network-supplied (up to 253 characters after
# sanitising) and the label column's width is global, so one long name would
# push every value in the window that far to the right.
PEER_LABEL_MAX = 28

# (button label, action id, kind). The kind is surfaced in the label for repairs
# because `flush_dns_cache` genuinely mutates system state and a button that
# does that should say so before it is clicked, not after.
TROUBLESHOOTING_ACTIONS = [
    ("Ping now", "ping_now", "check"),
    ("Check interface state", "check_interface_state", "check"),
    ("Check default route", "check_default_route", "check"),
    ("Check DNS servers", "check_configured_dns_servers", "check"),
    ("Check resolver overrides", "check_resolver_overrides", "check"),
    ("Resolve via public resolver", "resolve_against_public_resolver", "check"),
    ("Flush DNS cache (changes system state)", "flush_dns_cache", "repair"),
    ("Prewarm DNS (top 50 queried names)", "prewarm_dns", "check"),
    ("Run full diagnosis", "full_diagnosis", "repair"),
]

SECONDARY_ACTIONS = [
    # Left as "check" rather than "repair" even though what gets typed into it
    # may well mutate: opening a prompt changes nothing, and tagging it as a
    # repair would put the "changes system state" warning on every one of these
    # buttons' worth of attention while saying nothing true about this one. The
    # label carries what the reader actually needs -- that it is a real shell.
    ("Open console (arbitrary shell)", "open_console", "check"),
    ("Open router console", "open_router_window", "check"),
    ("Open settings", "open_settings", "check"),
    ("Collapse to floating mini window", "toggle_mini", "check"),
    ("Open last incident report", "open_last_report", "check"),
    ("Open forensic logs folder", "open_forensic_dir", "check"),
    ("Test network alert", "test_alert", "check"),
    # Tagged "repair" so the label and tooltip both warn: this one changes the
    # machine's security configuration, which is a bigger deal than flushing a
    # cache. What it installs, and what that permits, is printed into the results
    # pane before macOS asks for a password -- see privileges.py.
    ("Grant elevated permissions (changes system state)", "grant_privileges", "repair"),
    ("Revoke elevated permissions", "revoke_privileges", "repair"),
]

ALL_ACTIONS = TROUBLESHOOTING_ACTIONS + SECONDARY_ACTIONS


def _yes_no(value: Optional[bool]) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


# The results pane is appended to on most log polls whether or not the window
# is visible. Each append copies the whole pane across the bridge and re-lays it
# out on the main thread, so after weeks of LaunchAgent uptime an uncapped pane
# turns every append into a multi-megabyte stall of the run loop the tick,
# ping and UI timers share. The newest text is what anyone reads.
OUTPUT_MAX_CHARS = 200_000


def capped_output(current: str, text: str, limit: int = OUTPUT_MAX_CHARS) -> str:
    return (current + text)[-limit:]


def dashboard_sections(
    *,
    ping_stats: dict,
    flap_state: str,
    consecutive_failures: int = 0,
    config: Optional[dict] = None,
    last_classification: Optional[str] = None,
    last_report_path: Optional[str] = None,
    resolution_findings: Optional[list] = None,
    episode_open: bool = False,
    episode_started_at: Optional[str] = None,
    peers: Optional[dict] = None,
    fault_verdict: Optional[dict] = None,
    dns_domains: Optional[list] = None,
    log_entries: int = 0,
    log_errors: int = 0,
    new_log_errors: int = 0,
    log_error: Optional[str] = None,
    permissions: Optional[list] = None,
) -> list:
    """The window's contents as (section title, [(label, value)]) pairs."""
    config = config or {}
    findings = resolution_findings or []

    rtt = ping_stats.get("rtt_ms")
    loss = ping_stats.get("loss_pct")
    down_bps = ping_stats.get("down_bps")
    up_bps = ping_stats.get("up_bps")

    network = [
        ("Ping target", str(config.get("ping_host", "unknown"))),
        ("Round trip", "no reply" if ping_stats.get("down") else _rtt_text(rtt)),
        ("Packet loss", "not measured yet" if loss is None else f"{loss:.0f}%"),
        ("Download", _rate_text(down_bps)),
        ("Upload", _rate_text(up_bps)),
    ]

    monitor = [
        ("Status", _status_text(flap_state, consecutive_failures, ping_stats)),
        ("Consecutive probe failures", str(consecutive_failures)),
        ("Last incident classified as", last_classification or "no incident yet"),
        ("Last incident report", last_report_path or "none written yet"),
        (
            "Resolution check",
            _resolution_text(findings),
        ),
        (
            "Forensic episode",
            f"open since {episode_started_at}" if episode_open else "none open",
        ),
        (
            "System log",
            _log_text(log_entries, log_errors, new_log_errors, log_error),
        ),
    ]

    settings = [
        ("Ping every", f"{config.get('ping_interval_seconds', '?')}s"),
        ("Alert after", f"{config.get('ping_failure_threshold', '?')} failed ping(s)"),
        (
            "Re-alert while down",
            _repeat_text(config.get("ping_alert_repeat_seconds")),
        ),
        ("Incident probe every", f"{config.get('poll_interval_seconds', '?')}s"),
        (
            "Incident after / clears after",
            f"{config.get('failure_threshold', '?')} fails / "
            f"{config.get('success_threshold', '?')} successes",
        ),
        ("Resolution batch every", f"{config.get('resolution_interval_seconds', '?')}s"),
        # dns_domains is what the prober actually resolves (domains plus the
        # control domain); config["domains"] alone said "none configured"
        # while api.anthropic.com was checked on every tick.
        (
            "Domains checked for DNS",
            ", ".join(dns_domains if dns_domains is not None else config.get("domains") or [])
            or "none configured",
        ),
    ]

    sections = [
        ("Network right now", network),
        ("Monitor", monitor),
        ("Settings in force", settings),
    ]
    if permissions:
        # After "Settings in force", because that is what it is: a standing
        # decision about what this app may do, not a live measurement.
        sections.append(("Permissions", permissions))
    if peers is not None:
        sections.insert(2, ("Other monitors on this network", _peer_rows(peers)))
    if fault_verdict:
        # First, not last: when something is broken, where it is broken is the
        # only thing anyone opens this window for.
        sections.insert(0, ("Where the problem is", _verdict_rows(fault_verdict)))
    return sections


def _verdict_rows(verdict: dict) -> list:
    """The localization result, with the evidence behind it.

    The reasoning is shown, not just the conclusion. A bare "this machine" is an
    assertion; the sentence explaining which comparison produced it is something
    the reader can disagree with -- which matters, because acting on it means
    rebooting or reconfiguring something.
    """
    evidence = verdict.get("evidence") or {}
    rows = [
        ("Cause", verdict.get("summary", "unknown")),
        ("Confidence", str(verdict.get("confidence", "unknown"))),
        ("Why", verdict.get("reason", "")),
        (
            "Peers consulted",
            f"{evidence.get('peers_answered', 0)} answered of "
            f"{evidence.get('peers_known', 0)} known",
        ),
    ]
    for label, field in (
        ("Peer can reach internet", "peer_external_reachable"),
        ("Peer can resolve DNS", "peer_dns_ok"),
    ):
        if evidence.get(field) is not None:
            rows.append((label, _yes_no(evidence[field])))
    return rows


def _peer_rows(peers: dict) -> list:
    """One row per known peer, grouped by how recently it was heard from.

    Deliberately lists every bucket rather than only the live ones: "this machine
    was here yesterday and isn't answering now" is the interesting fact, and it
    is invisible if absent peers are hidden.
    """
    rows = []
    for bucket in BUCKETS:
        entries = peers.get(bucket) or []
        if not entries:
            continue
        rows.append((f"[{bucket}]", f"{len(entries)} host(s)"))
        for peer in entries:
            missed = peer.get("missed_healthchecks") or 0
            detail = f"{peer.get('address', '?')} -- {peer.get('status') or 'unknown'}"
            if missed:
                detail += f", {missed} missed heartbeat(s)"
            name = str(peer.get("host") or peer.get("id", "?"))[:PEER_LABEL_MAX]
            rows.append((f"  {name}", detail))
    if not rows:
        return [("Peers", "none discovered yet")]
    return rows


def _rtt_text(rtt: Optional[float]) -> str:
    return "not measured yet" if rtt is None else f"{rtt:.0f} ms"


def _rate_text(bps: Optional[float]) -> str:
    if bps is None:
        return "not measured yet"
    return f"{format_bits(bps)}bps"


def _repeat_text(seconds: Optional[float]) -> str:
    # An absent key is not a zero: the sibling rows say '?' for a missing
    # setting, and "one alert per outage" is a claim about configured behaviour.
    if seconds is None:
        return "?"
    if not seconds:
        return "no (one alert per outage)"
    return f"every {seconds}s"


def _status_text(flap_state: str, consecutive_failures: int, ping_stats: dict) -> str:
    if ping_stats.get("down"):
        return "DOWN -- pings unanswered"
    if flap_state == "incident":
        return "incident declared"
    if consecutive_failures:
        return "flaky -- a probe is failing"
    # ping_stats starts as NO_PING_YET, whose `down` is False, so without this
    # the window reads "healthy" before the first reply -- and for as long as
    # the ping worker keeps failing to produce one.
    if ping_stats.get("rtt_ms") is None and ping_stats.get("loss_pct") is None:
        return "not probed yet"
    return "healthy"


def _log_text(entries: int, errors: int, new_errors: int, error: Optional[str]) -> str:
    """The system log's state, summarised for the left column.

    Duplicated here rather than only above the pane on purpose: this row is what
    someone sees in a screenshot of the stats, and "the log viewer is broken" and
    "the network log is quiet" have to be distinguishable there too.
    """
    if error:
        return error
    if not entries:
        return "nothing captured yet"
    text = f"{entries} entries, {errors} error/fault"
    if new_errors:
        text += f"; {new_errors} reported since launch"
    return text


def _resolution_text(findings: list) -> str:
    if not findings:
        return "no batch has run yet"
    failed = sum(1 for f in findings if not f.get("resolved"))
    return f"{failed} of {len(findings)} domains failing"


def render_dashboard_text(sections: list) -> str:
    """Flatten sections into the monospaced block the window displays.

    Labels are padded to a common width across the whole document rather than
    per section, so the values line up in one column down the window instead of
    stepping in and out.
    """
    width = max(
        (len(label) for _, rows in sections for label, _ in rows),
        default=0,
    )
    lines = []
    for title, rows in sections:
        lines.append(title.upper())
        for label, value in rows:
            lines.append(f"  {label.ljust(width)}   {value}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


# --- the window ------------------------------------------------------------

# Two columns. The left one is the original window unchanged -- stats, graphs,
# button grid, results pane -- and every frame in it is still laid out against
# LEFT_WIDTH, which is what WINDOW_WIDTH used to be. The right one is the system
# log pane.
#
# Widening rather than lengthening was forced by the hardware. The window was
# already 950 tall and the display it opens on is 1080 logical pixels high, so
# there was nowhere to stack a log pane underneath -- adding one below the results
# pane would have pushed the window off the bottom of the screen. Log lines are
# also long: `nw_socket_handle_socket_event [C134.1.1:3] Socket SO_ERROR
# [51: Network is unreachable]` is a *short* one. Width is what the pane needed
# anyway.
LEFT_WIDTH = 640
LOG_WIDTH = 620
# Tall enough that the three graphs fit between the stats pane and the buttons
# without the buttons landing on top of the results pane. The stats pane scrolls,
# which is why it gives up the room rather than the window growing further --
# test_buttons_do_not_overlap_the_output_pane is what keeps this arithmetic
# honest, and it caught exactly this when the graphs were added.
WINDOW_HEIGHT = 950
MARGIN = 16
WINDOW_WIDTH = LEFT_WIDTH + LOG_WIDTH + MARGIN
# 200 until the two permission buttons were added. Sixteen actions in two columns
# is eight rows, one more than fourteen was, and the extra 34px pushed the grid
# 10px over the results pane -- caught by
# test_buttons_do_not_overlap_the_output_pane, which is the third time that test
# has earned its place. The stats pane is what gives up the room because it is the
# only one of the four that scrolls; the graphs and the buttons cannot.
#
# 168 -> 150 when the console button made it seventeen actions and so nine rows,
# which put the grid 12px over the results pane -- the fourth time. 18px rather
# than the bare 12 the test demands, so the grid clears the pane by one BUTTON_GAP
# instead of landing exactly on it.
STATS_HEIGHT = 150
OUTPUT_HEIGHT = 150
BUTTON_HEIGHT = 28
BUTTON_GAP = 6
GRAPH_HEIGHT = 92
GRAPH_GAP = 6

# --- the log column --------------------------------------------------------
# The left column's content stops at LEFT_WIDTH - MARGIN, so the log column
# starts at LEFT_WIDTH and the window's own right margin closes it out.
LOG_X = LEFT_WIDTH
LOG_ROW_HEIGHT = 24
LOG_ROW_GAP = 6
LOG_STATUS_HEIGHT = 18
LOG_SEARCH_LABEL_WIDTH = 54

# Buttons under the search field. Not part of ALL_ACTIONS: those are the
# troubleshooting grid, they are counted and asserted over by the tests, and a
# log control is not a troubleshooting step. They dispatch through the same
# callback with their own ids, which `App.handle_dashboard_action` has to answer
# explicitly -- an unhandled id falls through to the ladder-step branch and
# reports "Unknown step", which is the bug this file already documents once.
LOG_ACTIONS = [
    ("Refresh now", "log_refresh"),
    ("Errors only", "log_toggle_level"),
    ("Clear search", "log_clear_search"),
    ("Empty buffer", "log_clear_buffer"),
]
# Latency, download, upload -- three graphs rather than one with three axes,
# because a 61ms line and a 1.2Mbps line share no sensible scale.
GRAPH_KINDS = (
    ("Ping latency", "rtt_ms", "latency", "ms"),
    ("Download", "down_bps", "download", ""),
    ("Upload", "up_bps", "upload", ""),
)


class DashboardWindow:
    """Retains an NSWindow and the views inside it that get updated."""

    def __init__(self, on_action: Callable[[str], None]):
        import AppKit

        self.on_action = on_action
        self._target = _make_button_target(self._handle)

        rect = AppKit.NSMakeRect(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT)
        style = (
            AppKit.NSWindowStyleMaskTitled
            | AppKit.NSWindowStyleMaskClosable
            | AppKit.NSWindowStyleMaskMiniaturizable
            | AppKit.NSWindowStyleMaskResizable
        )
        self.window = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            rect, style, AppKit.NSBackingStoreBuffered, False
        )
        self.window.setTitle_(WINDOW_TITLE)
        # Closing must hide the window, not deallocate it -- the next open would
        # otherwise touch freed memory.
        self.window.setReleasedWhenClosed_(False)
        self.window.center()

        content = self.window.contentView()

        self.stats_view = _text_view(
            AppKit,
            AppKit.NSMakeRect(
                MARGIN,
                WINDOW_HEIGHT - MARGIN - STATS_HEIGHT,
                LEFT_WIDTH - 2 * MARGIN,
                STATS_HEIGHT,
            ),
        )
        content.addSubview_(self.stats_view.enclosingScrollView() or self.stats_view)

        self.graph_views = {}
        self._add_graphs(AppKit, content)

        self.buttons = []
        self._add_buttons(AppKit, content)

        self.output_view = _text_view(
            AppKit,
            AppKit.NSMakeRect(MARGIN, MARGIN, LEFT_WIDTH - 2 * MARGIN, OUTPUT_HEIGHT),
        )
        content.addSubview_(self.output_view.enclosingScrollView() or self.output_view)
        self.output_view.setString_("Results of anything you run from here appear in this pane.\n")

        self.log_control_buttons = {}
        self._add_log_column(AppKit, content)

    def _add_graphs(self, AppKit, content):
        """One image view per series, stacked under the stats pane.

        NSImageView holding a rendered NSImage rather than a custom NSView: an
        ObjC class may only be registered once per process, and an offscreen
        NSImage is pixel-testable headlessly. See graphs.py.
        """
        top = WINDOW_HEIGHT - MARGIN - STATS_HEIGHT - GRAPH_GAP
        for index, (_title, field, _kind, _unit) in enumerate(GRAPH_KINDS):
            y = top - (index + 1) * (GRAPH_HEIGHT + GRAPH_GAP)
            view = AppKit.NSImageView.alloc().initWithFrame_(
                AppKit.NSMakeRect(MARGIN, y, LEFT_WIDTH - 2 * MARGIN, GRAPH_HEIGHT)
            )
            view.setImageScaling_(AppKit.NSImageScaleNone)
            content.addSubview_(view)
            self.graph_views[field] = view

    def _graphs_bottom(self) -> float:
        top = WINDOW_HEIGHT - MARGIN - STATS_HEIGHT - GRAPH_GAP
        return top - len(GRAPH_KINDS) * (GRAPH_HEIGHT + GRAPH_GAP)

    def set_graphs(self, series_by_field: dict):
        """Re-render each graph from the history."""
        from netdnsmonitor.graphs import format_bits, render_series_graph

        for title, field, kind, unit in GRAPH_KINDS:
            view = self.graph_views.get(field)
            if view is None:
                continue
            values = series_by_field.get(field) or []
            view.setImage_(
                render_series_graph(
                    values,
                    title=title,
                    kind=kind,
                    unit=unit,
                    # LEFT_WIDTH, not WINDOW_WIDTH: the graphs live in the left
                    # column, and rendering them at the full two-column width
                    # would draw a 1276px image into a 608px view.
                    size=(LEFT_WIDTH - 2 * MARGIN, GRAPH_HEIGHT),
                    format_value=None if field == "rtt_ms" else format_bits,
                )
            )

    def _add_buttons(self, AppKit, content):
        """Two columns, laid out downward from just under the graphs."""
        column_width = (LEFT_WIDTH - 2 * MARGIN - BUTTON_GAP) / 2
        top = self._graphs_bottom() - GRAPH_GAP
        for index, (label, action_id, kind) in enumerate(ALL_ACTIONS):
            row, column = divmod(index, 2)
            x = MARGIN + column * (column_width + BUTTON_GAP)
            y = top - (row + 1) * (BUTTON_HEIGHT + BUTTON_GAP)
            button = AppKit.NSButton.alloc().initWithFrame_(
                AppKit.NSMakeRect(x, y, column_width, BUTTON_HEIGHT)
            )
            button.setTitle_(label)
            button.setBezelStyle_(AppKit.NSBezelStyleRounded)
            button.setTarget_(self._target)
            button.setAction_("invoke:")
            # The action id travels on the button itself, so the single shared
            # target can dispatch without a closure per button.
            button.setIdentifier_(action_id)
            if kind == "repair":
                button.setToolTip_("Changes system state.")
            content.addSubview_(button)
            self.buttons.append(button)

    def _add_log_column(self, AppKit, content):
        """Search field, control buttons, status line, then the pane itself.

        Laid out top-down from the window's top margin; the pane takes whatever is
        left down to the bottom margin, so it is the part that gives up room to
        the controls rather than the other way round. Each row's y is derived from
        the one above it, so inserting a control cannot silently overlap the pane
        the way the left column's fixed offsets once did.
        """
        search_y = WINDOW_HEIGHT - MARGIN - LOG_ROW_HEIGHT
        content.addSubview_(
            _label(
                AppKit,
                AppKit.NSMakeRect(LOG_X, search_y + 3, LOG_SEARCH_LABEL_WIDTH, 18),
                "Search",
                10.5,
            )
        )
        self.log_search_field = AppKit.NSTextField.alloc().initWithFrame_(
            AppKit.NSMakeRect(
                LOG_X + LOG_SEARCH_LABEL_WIDTH,
                search_y,
                LOG_WIDTH - LOG_SEARCH_LABEL_WIDTH,
                21,
            )
        )
        self.log_search_field.setFont_(
            AppKit.NSFont.monospacedSystemFontOfSize_weight_(10.5, AppKit.NSFontWeightRegular)
        )
        self.log_search_field.setPlaceholderString_(
            "terms are ANDed; -term excludes, e.g. dns -crowdstrike"
        )
        # The same shared ObjC target every button uses. Defining a new target
        # class here would raise "_ButtonTarget is overriding existing
        # Objective-C class" the second time this window is built -- see the note
        # above _button_target_class. Return in the field fires this action; the
        # pane also re-filters as you type, off the app's 1s refresh, so this is
        # for people who expect Return to do something.
        self.log_search_field.setTarget_(self._target)
        self.log_search_field.setAction_("invoke:")
        self.log_search_field.setIdentifier_("log_search")
        content.addSubview_(self.log_search_field)

        controls_y = search_y - LOG_ROW_GAP - LOG_ROW_HEIGHT
        control_width = (LOG_WIDTH - (len(LOG_ACTIONS) - 1) * LOG_ROW_GAP) / len(LOG_ACTIONS)
        for index, (title, action_id) in enumerate(LOG_ACTIONS):
            button = AppKit.NSButton.alloc().initWithFrame_(
                AppKit.NSMakeRect(
                    LOG_X + index * (control_width + LOG_ROW_GAP),
                    controls_y,
                    control_width,
                    LOG_ROW_HEIGHT,
                )
            )
            button.setTitle_(title)
            button.setBezelStyle_(AppKit.NSBezelStyleRounded)
            button.setTarget_(self._target)
            button.setAction_("invoke:")
            button.setIdentifier_(action_id)
            content.addSubview_(button)
            # Kept by id rather than appended to self.buttons: that list is the
            # troubleshooting grid, and the tests count it against ALL_ACTIONS.
            self.log_control_buttons[action_id] = button

        status_y = controls_y - LOG_ROW_GAP - LOG_STATUS_HEIGHT
        self.log_status_label = _label(
            AppKit,
            AppKit.NSMakeRect(LOG_X, status_y, LOG_WIDTH, LOG_STATUS_HEIGHT),
            "Reading the system log...",
            9.5,
        )
        content.addSubview_(self.log_status_label)

        pane_top = status_y - LOG_ROW_GAP
        self.log_view = _text_view(
            AppKit,
            AppKit.NSMakeRect(LOG_X, MARGIN, LOG_WIDTH, pane_top - MARGIN),
        )
        content.addSubview_(self.log_view.enclosingScrollView() or self.log_view)

    def _handle(self, sender):
        identifier = sender.identifier()
        if not identifier:
            return
        try:
            self.on_action(str(identifier))
        except Exception as exc:  # noqa: BLE001 - never raise into AppKit
            # Escaping here unwinds through PyObjC into AppKit and the click looks
            # like it did nothing at all. Class name only, for the reason in
            # _report_action_failure.
            _report_action_failure(str(identifier), exc)
            self.append_output(f"{identifier} raised {type(exc).__name__}; see the app log.\n")

    # --- what App calls ----------------------------------------------------

    def show(self, activate: bool = True):
        """Order the window front. `activate` decides whether to steal focus.

        True for anything the user just asked for -- a Dock click or a menu item
        -- because without `activateIgnoringOtherApps_` the window opens *behind*
        the frontmost app, which is indistinguishable from it not opening.

        False for the automatic open at launch. This runs from a launchd agent at
        login, and yanking focus away from whatever someone is doing, every
        login, would be a new annoyance in place of the old one.
        """
        import AppKit

        if activate:
            self.window.makeKeyAndOrderFront_(None)
            AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        else:
            self.window.orderFront_(None)

    def is_visible(self) -> bool:
        return bool(self.window.isVisible())

    def set_stats(self, text: str):
        self.stats_view.setString_(text)

    def append_output(self, text: str):
        current = self.output_view.string() or ""
        self.output_view.setString_(capped_output(current, text))
        self.output_view.scrollRangeToVisible_((len(self.output_view.string() or ""), 0))

    # --- the log column ----------------------------------------------------

    def search_query(self) -> str:
        """Whatever is typed in the search box, read fresh.

        The field is the single source of truth for the filter rather than a
        mirrored copy on the app: a copy has to be kept in step with every
        keystroke, and the failure mode is a pane that filters on something other
        than what the box says.
        """
        return str(self.log_search_field.stringValue() or "")

    def set_search_query(self, text: str):
        self.log_search_field.setStringValue_(text)

    def set_log(self, text: str):
        """Replace the pane's contents.

        The caller must only call this when the text actually changed --
        `setString_` resets the scroll position, so at the 1-second refresh this
        would drag the view back to the top every second while someone is reading
        it. `App._refresh_log_pane` holds the comparison, the same way
        `_refresh_dashboard` does for the stats pane.
        """
        self.log_view.setString_(text)

    def set_log_status(self, text: str):
        self.log_status_label.setStringValue_(text)

    def set_log_level_title(self, title: str):
        """The level button's label states the *current* filter, not the action.

        A button reading "Errors only" is ambiguous about whether that is what you
        get now or what you would get if you clicked, and getting that backwards
        means someone concludes the network log is empty when they are looking at a
        filtered view of it.
        """
        button = self.log_control_buttons.get("log_toggle_level")
        if button is not None:
            button.setTitle_(title)


def _report_action_failure(action_id: str, exc: BaseException) -> None:
    """Log where a click handler failed without logging what it said.

    Not `traceback.print_exc()`: the message of a network or auth failure can
    carry a credential -- urllib's error text embeds the full request URL, and
    the Slack webhook URL is one. The frames say where it broke; the class name
    says what kind of failure it was.
    """
    print(f"{action_id} raised {type(exc).__name__}", file=sys.stderr)
    traceback.print_tb(exc.__traceback__, file=sys.stderr)


def _label(AppKit, frame, text: str, point_size: float):
    """Static text. An NSTextField with the editing switched off, because AppKit
    has no separate label class.

    Lives here rather than in settings_window.py, which is where it started: both
    windows need it, and this is the module settings_window already reaches into
    for `_make_button_target`.
    """
    field = AppKit.NSTextField.alloc().initWithFrame_(frame)
    field.setStringValue_(text)
    field.setEditable_(False)
    field.setSelectable_(False)
    field.setBordered_(False)
    field.setDrawsBackground_(False)
    field.setFont_(
        AppKit.NSFont.monospacedSystemFontOfSize_weight_(point_size, AppKit.NSFontWeightRegular)
    )
    return field


def _text_view(AppKit, frame):
    """A non-editable monospaced text view inside a scroll view."""
    scroll = AppKit.NSScrollView.alloc().initWithFrame_(frame)
    scroll.setHasVerticalScroller_(True)
    scroll.setAutohidesScrollers_(True)
    scroll.setBorderType_(AppKit.NSBezelBorder)

    view = AppKit.NSTextView.alloc().initWithFrame_(
        AppKit.NSMakeRect(0, 0, frame.size.width, frame.size.height)
    )
    view.setEditable_(False)
    view.setRichText_(False)
    view.setFont_(AppKit.NSFont.monospacedSystemFontOfSize_weight_(11, AppKit.NSFontWeightRegular))
    view.setAutoresizingMask_(AppKit.NSViewWidthSizable)
    scroll.setDocumentView_(view)
    return view


# Objective-C classes are registered globally by name in the runtime, so the
# class body may execute exactly once per process. Defining it inside
# _make_button_target raised `_ButtonTarget is overriding existing Objective-C
# class` on the second DashboardWindow -- and the second window is the reopen
# path, i.e. normal use. Built on first need rather than at import so merely
# importing this module registers nothing.
_BUTTON_TARGET_CLASS = None


def _button_target_class():
    global _BUTTON_TARGET_CLASS
    if _BUTTON_TARGET_CLASS is None:
        import AppKit
        import objc

        class _ButtonTarget(AppKit.NSObject):
            def initWithHandler_(self, callback):
                this = objc.super(_ButtonTarget, self).init()
                if this is None:
                    return None
                this._callback = callback
                return this

            def invoke_(self, sender):
                self._callback(sender)

        _BUTTON_TARGET_CLASS = _ButtonTarget
    return _BUTTON_TARGET_CLASS


def _make_button_target(handler):
    """An ObjC object to receive button clicks.

    NSButton's target has to be an Objective-C object, so this is the smallest
    possible bridge.
    """
    return _button_target_class().alloc().initWithHandler_(handler)


APP_MENU_ITEMS = [
    ("Open Dashboard", "open_dashboard", "d"),
    # The mini window is borderless and has no close control, so collapsing must
    # never be a one-way trip -- the toggle is reachable from here, from the
    # status-item dropdown, and from the dashboard.
    ("Toggle Mini Window", "toggle_mini", "m"),
    ("Settings…", "open_settings", ","),
]

# (title, selector, key equivalent), with None for a separator. A text field does
# not handle Cmd-V itself: AppKit matches the keystroke against the main menu's
# key equivalents and sends that item's action. With no Edit menu nothing matched,
# so paste did nothing anywhere -- including the store build's masked credentials
# dialog, the only place a key can be entered in that build. An uppercase key
# equivalent implies Shift, which makes Redo Cmd-Shift-Z.
EDIT_MENU_ITEMS = [
    ("Undo", "undo:", "z"),
    ("Redo", "redo:", "Z"),
    None,
    ("Cut", "cut:", "x"),
    ("Copy", "copy:", "c"),
    ("Paste", "paste:", "v"),
    ("Select All", "selectAll:", "a"),
]


def install_main_menu(on_action: Callable[[str], None]):
    """Give the app a real application menu, and return the target to retain.

    rumps never populates one. With `LSUIElement: False` this app is a normal
    Dock app, so activating it puts "Net-DNS-Monitor" in the menu bar at the
    top-*left* -- and clicking it did nothing at all, because the menu genuinely
    had no items. That is a separate surface from the status item on the right,
    and someone reaching for the app name is doing the obvious thing.

    Quit is included because a macOS application menu without one is wrong, but
    note it behaves the way the status item's Quit does: launchd's KeepAlive
    brings the app straight back. `net-dns-monitor-service stop` is the real off
    switch, for the reasons recorded in that script.
    """
    import AppKit

    def dispatch(sender):
        action_id = str(sender.identifier() or "")
        try:
            on_action(action_id)
        except Exception as exc:  # noqa: BLE001 - never raise into AppKit
            # No window to report into from a menu item; the log is all there is.
            _report_action_failure(action_id, exc)

    target = _make_button_target(dispatch)

    app_menu = AppKit.NSMenu.alloc().init()
    for title, action_id, key in APP_MENU_ITEMS:
        item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, "invoke:", key)
        item.setTarget_(target)
        item.setIdentifier_(action_id)
        app_menu.addItem_(item)
    app_menu.addItem_(AppKit.NSMenuItem.separatorItem())
    app_menu.addItem_(
        AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(
            f"Quit {WINDOW_TITLE}", "terminate:", "q"
        )
    )

    # The first item of the main menu is the application menu; its own title is
    # ignored by AppKit, which uses the bundle name instead.
    app_item = AppKit.NSMenuItem.alloc().init()
    app_item.setSubmenu_(app_menu)
    main_menu = AppKit.NSMenu.alloc().init()
    main_menu.addItem_(app_item)

    # No target on these, unlike the items above. A nil target sends the action
    # to the first responder -- the focused field -- which is the object that can
    # paste. Targeting the dispatch object would route paste: to it instead.
    edit_menu = AppKit.NSMenu.alloc().initWithTitle_("Edit")
    for entry in EDIT_MENU_ITEMS:
        if entry is None:
            edit_menu.addItem_(AppKit.NSMenuItem.separatorItem())
            continue
        title, selector, key = entry
        edit_menu.addItem_(
            AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(title, selector, key)
        )
    edit_item = AppKit.NSMenuItem.alloc().init()
    edit_item.setSubmenu_(edit_menu)
    main_menu.addItem_(edit_item)

    AppKit.NSApplication.sharedApplication().setMainMenu_(main_menu)
    return target
