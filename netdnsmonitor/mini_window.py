"""The collapsed view: a small always-on-top panel you can glance at.

The dashboard answers "what exactly is happening". This answers only "is the
network up", from the corner of your eye, without switching apps or hunting for
the status item. That is a different job and it needs a different window.

Four AppKit settings do the actual work here, and leaving any one of them out
breaks the one thing it is for:

  NSFloatingWindowLevel        stays above ordinary windows, so it does not get
                               buried the moment you click anything else.
  setHidesOnDeactivate_(False) NSPanel hides itself when the app deactivates by
                               default -- which is precisely when you want to
                               glance at it. This is the setting people miss.
  movableByWindowBackground    there is no title bar to drag, so the background
                               has to be the drag handle.
  setFrameAutosaveName_        macOS persists the frame in user defaults, so it
                               reopens where it was left rather than recentring
                               every launch. Free position memory, no config key.

Borderless, so there is no close button: the toggle lives in the status-item
dropdown, the application menu, and the dashboard. Collapsing must never be a
one-way trip.

`NSPanel` rather than `NSWindow` with `NSNonactivatingPanelMask`: clicking to drag
it does not steal focus from what you were doing.
"""

from typing import Optional

WIDTH = 168
HEIGHT = 44
FRAME_AUTOSAVE_NAME = "NetDnsMonitorMiniWindow"

DOT = {"healthy": "\U0001f7e2", "flaky": "\U0001f7e1", "incident": "\U0001f534"}


# "ping" and "network" mean nothing is getting through, so "DOWN" is true. None
# is here only so a caller that passes no reason keeps the old wording. Anything
# else is named: "DOWN" for a DNS incident with pings answering sends someone to
# the cable instead of the resolver, and for "unclassified" it turns a probe that
# never ran into a failed one.
DOWN_REASONS = (None, "ping", "network")


def mini_text(
    state: str,
    rtt_ms: Optional[float] = None,
    loss_pct: Optional[float] = None,
    reason: Optional[str] = None,
) -> str:
    """The one line the panel shows. Pure, so the wording is testable.

    Deliberately not the menu bar's title: at this size there is room for the
    state and one number, and "DOWN" spelled out beats a dash someone has to
    interpret while walking past.

    `reason` is read only during an incident: "ping" for unanswered pings,
    otherwise the incident's classification. None keeps the old "DOWN".
    """
    dot = DOT.get(state, DOT["healthy"])
    if state == "incident":
        if reason in DOWN_REASONS:
            return f"{dot}  DOWN"
        return f"{dot}  {str(reason).upper()}"
    if rtt_ms is None:
        return f"{dot}  --"
    text = f"{dot}  {rtt_ms:.0f}ms"
    if loss_pct:
        text += f"  {loss_pct:.0f}%"
    return text


class MiniWindow:
    """Retains the panel. See dashboard.DashboardWindow for why that matters."""

    def __init__(self):
        import AppKit

        rect = AppKit.NSMakeRect(0, 0, WIDTH, HEIGHT)
        style = AppKit.NSWindowStyleMaskBorderless | AppKit.NSWindowStyleMaskNonactivatingPanel
        self.window = AppKit.NSPanel.alloc().initWithContentRect_styleMask_backing_defer_(
            rect, style, AppKit.NSBackingStoreBuffered, False
        )
        self.window.setLevel_(AppKit.NSFloatingWindowLevel)
        # Without this the panel disappears exactly when it is wanted: NSPanel
        # hides on app deactivation by default.
        self.window.setHidesOnDeactivate_(False)
        self.window.setReleasedWhenClosed_(False)
        self.window.setMovableByWindowBackground_(True)
        self.window.setOpaque_(False)
        self.window.setBackgroundColor_(AppKit.NSColor.clearColor())
        # Visible over any wallpaper, and it follows the system appearance.
        self.window.setAlphaValue_(0.92)
        self.window.setFrameAutosaveName_(FRAME_AUTOSAVE_NAME)

        content = self.window.contentView()
        content.setWantsLayer_(True)
        effect = AppKit.NSVisualEffectView.alloc().initWithFrame_(rect)
        effect.setMaterial_(AppKit.NSVisualEffectMaterialHUDWindow)
        effect.setBlendingMode_(AppKit.NSVisualEffectBlendingModeBehindWindow)
        effect.setState_(AppKit.NSVisualEffectStateActive)
        effect.setAutoresizingMask_(AppKit.NSViewWidthSizable | AppKit.NSViewHeightSizable)
        content.addSubview_(effect)
        self.effect = effect

        self.label = AppKit.NSTextField.alloc().initWithFrame_(AppKit.NSMakeRect(0, 8, WIDTH, 26))
        self.label.setEditable_(False)
        self.label.setSelectable_(False)
        self.label.setBordered_(False)
        self.label.setDrawsBackground_(False)
        self.label.setAlignment_(AppKit.NSTextAlignmentCenter)
        self.label.setFont_(
            AppKit.NSFont.monospacedDigitSystemFontOfSize_weight_(15, AppKit.NSFontWeightSemibold)
        )
        self.label.setStringValue_(mini_text("healthy"))
        effect.addSubview_(self.label)

    # --- what App calls ----------------------------------------------------

    def show(self):
        # orderFrontRegardless, not makeKeyAndOrderFront_: this must appear
        # without taking focus, which is the whole point of a glanceable panel.
        self.window.orderFrontRegardless()

    def hide(self):
        self.window.orderOut_(None)

    def is_visible(self) -> bool:
        return bool(self.window.isVisible())

    def set_text(self, text: str):
        self.label.setStringValue_(text)
