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

from typing import Callable, Optional

from netdnsmonitor.status import format_rate

WINDOW_TITLE = "Net-DNS-Monitor"

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
    ("Open settings", "open_settings", "check"),
    ("Collapse to floating mini window", "toggle_mini", "check"),
    ("Open last incident report", "open_last_report", "check"),
    ("Open forensic logs folder", "open_forensic_dir", "check"),
    ("Test network alert", "test_alert", "check"),
]

ALL_ACTIONS = TROUBLESHOOTING_ACTIONS + SECONDARY_ACTIONS


def _yes_no(value: Optional[bool]) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"


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
        ("Domains checked for DNS", ", ".join(config.get("domains") or []) or "none configured"),
    ]

    sections = [
        ("Network right now", network),
        ("Monitor", monitor),
        ("Settings in force", settings),
    ]
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
            f"{evidence.get('peers_asked', 0)} known",
        ),
    ]
    if evidence.get("peer_external_reachable") is not None:
        rows.append(
            ("Peer can reach internet", "yes" if evidence["peer_external_reachable"] else "no")
        )
    if evidence.get("peer_dns_ok") is not None:
        rows.append(("Peer can resolve DNS", "yes" if evidence["peer_dns_ok"] else "no"))
    return rows


def _peer_rows(peers: dict) -> list:
    """One row per known peer, grouped by how recently it was heard from.

    Deliberately lists every bucket rather than only the live ones: "this machine
    was here yesterday and isn't answering now" is the interesting fact, and it
    is invisible if absent peers are hidden.
    """
    rows = []
    for bucket in ("current", "recent", "other"):
        entries = peers.get(bucket) or []
        if not entries:
            continue
        rows.append((f"[{bucket}]", f"{len(entries)} host(s)"))
        for peer in entries:
            missed = peer.get("missed_healthchecks") or 0
            detail = f"{peer.get('address', '?')} -- {peer.get('status') or 'unknown'}"
            if missed:
                detail += f", {missed} missed heartbeat(s)"
            rows.append((f"  {peer.get('host') or peer.get('id', '?')}", detail))
    if not rows:
        return [("Peers", "none discovered yet")]
    return rows


def _rtt_text(rtt: Optional[float]) -> str:
    return "not measured yet" if rtt is None else f"{rtt:.0f} ms"


def _rate_text(bps: Optional[float]) -> str:
    if bps is None:
        return "not measured yet"
    return f"{format_rate(bps)}bps"


def _repeat_text(seconds) -> str:
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
    return "healthy"


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

WINDOW_WIDTH = 640
# Tall enough that the three graphs fit between the stats pane and the buttons
# without the buttons landing on top of the results pane. The stats pane scrolls,
# which is why it gives up the room rather than the window growing further --
# test_buttons_do_not_overlap_the_output_pane is what keeps this arithmetic
# honest, and it caught exactly this when the graphs were added.
WINDOW_HEIGHT = 950
MARGIN = 16
STATS_HEIGHT = 200
OUTPUT_HEIGHT = 150
BUTTON_HEIGHT = 28
BUTTON_GAP = 6
GRAPH_HEIGHT = 92
GRAPH_GAP = 6
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
                WINDOW_WIDTH - 2 * MARGIN,
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
            AppKit.NSMakeRect(MARGIN, MARGIN, WINDOW_WIDTH - 2 * MARGIN, OUTPUT_HEIGHT),
        )
        content.addSubview_(self.output_view.enclosingScrollView() or self.output_view)
        self.output_view.setString_("Results of anything you run from here appear in this pane.\n")

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
                AppKit.NSMakeRect(MARGIN, y, WINDOW_WIDTH - 2 * MARGIN, GRAPH_HEIGHT)
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
                    size=(WINDOW_WIDTH - 2 * MARGIN, GRAPH_HEIGHT),
                    format_value=None if field == "rtt_ms" else format_bits,
                )
            )

    def _add_buttons(self, AppKit, content):
        """Two columns, laid out downward from just under the graphs."""
        column_width = (WINDOW_WIDTH - 2 * MARGIN - BUTTON_GAP) / 2
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

    def _handle(self, sender):
        identifier = sender.identifier()
        if identifier:
            self.on_action(str(identifier))

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
        self.output_view.setString_(current + text)
        self.output_view.scrollRangeToVisible_((len(self.output_view.string() or ""), 0))


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

    target = _make_button_target(lambda sender: on_action(str(sender.identifier() or "")))

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
    AppKit.NSApplication.sharedApplication().setMainMenu_(main_menu)
    return target
