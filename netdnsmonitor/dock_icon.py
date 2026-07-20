"""Render the Dock tile as a colored network icon instead of the generic
Python rocket. Without a real .app bundle (this ships as a plain script),
rumps/NSApplication has no Info.plist or custom icon to draw from, so
macOS falls back to the bare python3 interpreter's default Dock icon.

Uses a real vector SF Symbol (no bundled image asset needed, works on any
Mac with the symbol available) tinted per the same three-state status
`status.status_state` computes, so the Dock icon carries the same visual
indicator as the menu bar title rather than a second, independently-drifting
copy of the healthy/flaky/incident decision.

Tinting recipe: draw the template (black-and-transparent) symbol image,
then fill the same rect with the status color using the
`sourceAtop` compositing operation, which paints color only over pixels
the symbol already touched -- the standard macOS technique for tinting a
template image without needing per-color asset variants.
"""

STATUS_COLOR_NAMES = {
    "healthy": "systemGreenColor",
    "flaky": "systemYellowColor",
    "incident": "systemRedColor",
}


def build_status_icon(status: str, symbol_name: str = "wifi", size: int = 256):
    import AppKit
    from Foundation import NSMakeRect

    color_name = STATUS_COLOR_NAMES.get(status, "systemGreenColor")
    color = getattr(AppKit.NSColor, color_name)()

    base = AppKit.NSImage.imageWithSystemSymbolName_accessibilityDescription_(symbol_name, None)
    if base is None:
        raise ValueError(f"no SF Symbol named {symbol_name!r} on this macOS version")
    config = AppKit.NSImageSymbolConfiguration.configurationWithPointSize_weight_scale_(
        size * 0.6, AppKit.NSFontWeightRegular, AppKit.NSImageSymbolScaleLarge
    )
    base = base.imageWithSymbolConfiguration_(config)
    base.setTemplate_(True)

    image = AppKit.NSImage.alloc().initWithSize_((size, size))
    image.lockFocus()
    rect = NSMakeRect(0, 0, size, size)
    base.drawInRect_fromRect_operation_fraction_(
        rect, AppKit.NSZeroRect, AppKit.NSCompositingOperationSourceOver, 1.0
    )
    color.set()
    AppKit.NSRectFillUsingOperation(rect, AppKit.NSCompositingOperationSourceAtop)
    image.unlockFocus()
    return image


def set_dock_icon(status: str) -> None:
    """Cosmetic only -- a failure here must never take the monitor down."""
    try:
        import AppKit

        AppKit.NSApplication.sharedApplication().setApplicationIconImage_(
            build_status_icon(status)
        )
    except Exception:  # noqa: BLE001 - cosmetic, never fatal
        pass
