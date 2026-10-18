"""The look of every window: Liquid Glass where the system has it, and tooltips.

AppKit helpers only. The rules about *what* a control says live in
`ui_catalog.py`, which the offline suite reads without a GUI; this module is the
half that touches views. It never decides content.

**Liquid Glass.** macOS 26 added `NSGlassEffectView` and the `glass` bezel style.
They are looked up at run time (`getattr`), never imported by name, so the same
code runs on a Mac or a PyObjC without them: the window then gets a vibrancy
background (`NSVisualEffectView`) and buttons keep the rounded bezel. Nothing here
may raise because a style is missing -- a cosmetic upgrade must not cost a window.

**Tooltips are required, not optional.** `tip` refuses an empty string, and
`iter_views` / `controls_without_tip` exist so a test can walk a built window and
fail on any control that has none.
"""

import contextlib
from collections.abc import Iterator

# NSVisualEffectMaterialUnderWindowBackground / BehindWindow / Active. Spelled as
# numbers so a PyObjC without the constant names still works.
_MATERIAL_UNDER_WINDOW = 21
_BLEND_BEHIND_WINDOW = 0
_STATE_ACTIVE = 1
_BEZEL_GLASS = 16
# NSViewWidthSizable | NSViewHeightSizable
_RESIZE_BOTH = 2 | 16

PANE_CORNER_RADIUS = 10.0


def glass_available(AppKit) -> bool:
    """True when this system has Liquid Glass views and the glass bezel."""
    return hasattr(AppKit, "NSGlassEffectView") and hasattr(AppKit, "NSBezelStyleGlass")


def tip(view, text: str):
    """Set a tooltip, refusing an empty one. Returns the view for chaining."""
    if not text or not text.strip():
        raise ValueError("a tooltip may not be empty")
    view.setToolTip_(text)
    return view


def apply_window_glass(AppKit, window) -> str:
    """Give `window` a glass (or vibrancy) background behind its existing content.

    Returns "glass", "vibrancy" or "plain" so a test can say which path ran. The
    window's current content view becomes the glass view's content, so call this
    after the controls are added or before -- both work. The titlebar is left to the system.
    """
    content = window.contentView()
    frame = content.frame()
    try:
        if glass_available(AppKit):
            glass = AppKit.NSGlassEffectView.alloc().initWithFrame_(frame)
            window.setContentView_(glass)
            glass.setContentView_(content)
            content.setFrame_(glass.bounds())
            content.setAutoresizingMask_(_RESIZE_BOTH)
            kind = "glass"
        else:
            effect = AppKit.NSVisualEffectView.alloc().initWithFrame_(frame)
            effect.setMaterial_(_MATERIAL_UNDER_WINDOW)
            effect.setBlendingMode_(_BLEND_BEHIND_WINDOW)
            effect.setState_(_STATE_ACTIVE)
            window.setContentView_(effect)
            effect.addSubview_(content)
            content.setFrame_(effect.bounds())
            content.setAutoresizingMask_(_RESIZE_BOTH)
            kind = "vibrancy"
    except Exception:  # noqa: BLE001 - a missing style must not cost the window
        return "plain"
    with contextlib.suppress(Exception):
        window.setOpaque_(False)
        window.setBackgroundColor_(AppKit.NSColor.clearColor())
    return kind


def style_button(AppKit, button, prominent: bool = False):
    """Glass bezel when the system has one; otherwise the rounded bezel."""
    if glass_available(AppKit):
        button.setBezelStyle_(_BEZEL_GLASS)
        if prominent:
            with contextlib.suppress(Exception):
                button.setBezelColor_(AppKit.NSColor.controlAccentColor())
    else:
        button.setBezelStyle_(AppKit.NSBezelStyleRounded)
    return button


def make_pulldown(AppKit, frame, title: str, tooltip: str, entries, target):
    """A pull-down menu button: `title` shown, `entries` listed beneath it.

    `entries` is `(menu title, action id, tooltip)` triples. Each menu item sends
    `invoke:` to `target` with its action id as the item's identifier, so the same
    single ObjC target that serves plain buttons serves these (a second target
    class cannot be registered -- see dashboard._button_target_class).
    """
    popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(frame, True)
    popup.addItemWithTitle_(title)  # the first item of a pull-down is its label
    items = {}
    for label, action_id, entry_tip in entries:
        item = AppKit.NSMenuItem.alloc().initWithTitle_action_keyEquivalent_(label, "invoke:", "")
        item.setTarget_(target)
        item.setIdentifier_(action_id)
        tip(item, entry_tip)
        popup.menu().addItem_(item)
        items[action_id] = item
    style_button(AppKit, popup)
    tip(popup, tooltip)
    return popup, items


def style_pane(AppKit, scroll, text_view=None):
    """Rounded, borderless, lightly translucent text pane that reads on glass."""
    scroll.setBorderType_(AppKit.NSNoBorder)
    scroll.setDrawsBackground_(False)
    with contextlib.suppress(Exception):
        scroll.setWantsLayer_(True)
        scroll.layer().setCornerRadius_(PANE_CORNER_RADIUS)
        scroll.layer().setMasksToBounds_(True)
    if text_view is not None:
        with contextlib.suppress(Exception):
            text_view.setDrawsBackground_(True)
            text_view.setBackgroundColor_(
                AppKit.NSColor.textBackgroundColor().colorWithAlphaComponent_(0.45)
            )
    return scroll


def window_content(window):
    """The view the window's own controls were added to.

    `apply_window_glass` puts a glass (or vibrancy) view in front of the original
    content view; this returns the original, so a test measuring a layout is not
    measuring the wrapper's full-window frame.
    """
    outer = window.contentView()
    inner = getattr(outer, "contentView", None)
    if callable(inner):
        found = inner()
        if found is not None:
            return found
    subviews = list(outer.subviews() or [])
    return subviews[0] if len(subviews) == 1 else outer


def iter_views(root) -> Iterator:
    """Every view under `root`, depth first, including `root`."""
    yield root
    for child in list(root.subviews() or []):
        yield from iter_views(child)


def _is_input(AppKit, view) -> bool:
    """A control a person operates: button, pop-up, or an editable field."""
    if isinstance(view, AppKit.NSButton):  # includes NSPopUpButton
        return True
    if isinstance(view, AppKit.NSTextField):
        return bool(view.isEditable())
    if isinstance(view, (AppKit.NSSegmentedControl, AppKit.NSSlider)):
        return True
    # The window's shared field editor is inserted under whichever field has focus;
    # it is not a control of its own, and the field already carries the tip.
    return (
        isinstance(view, AppKit.NSTextView) and bool(view.isEditable()) and not view.isFieldEditor()
    )


def controls_without_tip(AppKit, root) -> list[str]:
    """Descriptions of every operable control under `root` that has no tooltip.

    Menu items inside pop-ups are checked as well. Static labels are exempt on
    their own, but the field they label carries the tip.
    """
    missing = []
    for view in iter_views(root):
        target = view
        # The text view of a scroll view is what holds the tooltip a person sees.
        if isinstance(view, AppKit.NSScrollView) and view.documentView() is not None:
            continue
        if _is_input(AppKit, target) and not (target.toolTip() or "").strip():
            missing.append(
                f"{type(target).__name__} id={target.identifier()!s} title={_title(target)!s}"
            )
        if isinstance(view, AppKit.NSPopUpButton):
            for item in view.itemArray():
                if not (item.toolTip() or "").strip() and item is not view.itemArray()[0]:
                    missing.append(f"menu item {item.identifier()!s} {item.title()!s}")
    return missing


def _title(view) -> str:
    try:
        return str(view.title())
    except Exception:  # noqa: BLE001 - not every control has a title
        return ""
