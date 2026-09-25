"""Draw the Dock tile as the current network reading, coloured by status.

This used to render the `wifi` SF Symbol tinted green/yellow/red. The symbol
was decorative -- it looked identical whether the round trip was 12ms or 900ms
-- so the tile now carries the number itself: round-trip time in milliseconds
on a healthy network, and a cross when pings are going unanswered. Same three
status colours as before, and still computed by `status.status_state`, so the
tile and the menu bar title cannot disagree about the state.

Text rather than an image asset for the same reason the SF Symbol was chosen
over one: nothing has to be bundled, and it scales to whatever tile size the
Dock asks for. Monospaced digits specifically, so the glyph widths don't jitter
as the number changes.

Drawing notes, both of which are easy to get subtly wrong:

- An NSImage under `lockFocus` is an *unflipped* context: the origin is at the
  bottom-left and `drawAtPoint_` positions the text's lower-left corner. The
  two lines are therefore laid out from the bottom up, and the whole block is
  centred by measuring it first.
- The font is shrunk to fit when the text is wide ("1204ms" is a plausible
  reading on a bad hotel network), because NSAttributedString will happily draw
  straight off the edge of the image otherwise.
"""

from typing import Callable, Optional

STATUS_COLOR_NAMES = {
    "healthy": "systemGreenColor",
    "flaky": "systemYellowColor",
    "incident": "systemRedColor",
}

# Shown before the first ping comes back, and when it doesn't come back at all.
NO_DATA_TEXT = "--"
PING_DOWN_TEXT = "✕"  # ✕

NUMBER_POINT_FRACTION = 0.42
UNIT_POINT_FRACTION = 0.17
# Leave a little air at the edges of the tile rather than filling it corner to
# corner; the Dock draws no padding of its own.
USABLE_WIDTH_FRACTION = 0.9


def dock_text(rtt_ms: Optional[float] = None, ping_down: bool = False) -> tuple[str, str]:
    """The (number, unit) pair to draw for the current reading.

    Separate from the drawing so the decision is testable without AppKit.
    """
    if ping_down:
        return PING_DOWN_TEXT, ""
    if rtt_ms is None:
        return NO_DATA_TEXT, ""
    return f"{rtt_ms:.0f}", "ms"


def _attributed(text: str, point_size: float, color):
    import AppKit

    font = AppKit.NSFont.monospacedDigitSystemFontOfSize_weight_(
        point_size, AppKit.NSFontWeightBold
    )
    return AppKit.NSAttributedString.alloc().initWithString_attributes_(
        text, {AppKit.NSFontAttributeName: font, AppKit.NSForegroundColorAttributeName: color}
    )


def build_status_icon(
    status: str,
    text: str = NO_DATA_TEXT,
    unit: str = "",
    size: int = 256,
):
    import AppKit

    color_name = STATUS_COLOR_NAMES.get(status, "systemGreenColor")
    color = getattr(AppKit.NSColor, color_name)()

    number = _attributed(text, size * NUMBER_POINT_FRACTION, color)
    # Shrink to fit rather than overflowing the tile. One pass is enough:
    # rendered width scales linearly with point size.
    usable = size * USABLE_WIDTH_FRACTION
    width = number.size().width
    if width > usable and width > 0:
        number = _attributed(text, size * NUMBER_POINT_FRACTION * usable / width, color)

    unit_line = _attributed(unit, size * UNIT_POINT_FRACTION, color) if unit else None

    number_size = number.size()
    unit_size = unit_line.size() if unit_line is not None else None
    block_height = number_size.height + (unit_size.height if unit_size else 0)
    bottom = (size - block_height) / 2

    image = AppKit.NSImage.alloc().initWithSize_((size, size))
    image.lockFocus()
    try:
        # Unflipped context: lay the block out from the bottom up.
        if unit_line is not None:
            unit_line.drawAtPoint_(((size - unit_size.width) / 2, bottom))
        number.drawAtPoint_(
            ((size - number_size.width) / 2, bottom + (unit_size.height if unit_size else 0))
        )
    finally:
        # An exception between lockFocus and unlockFocus leaves the focus stack
        # unbalanced for the whole process, which corrupts every later draw --
        # including the menu bar's.
        image.unlockFocus()
    return image


# Last tile actually pushed to the Dock. Measured: setApplicationIconImage_ costs
# ~2 seconds per call in this process, and it runs on the main thread -- so
# repeating it with identical content blocked the run loop for nothing. It also
# made the test suite take 244s instead of 7s, since every constructed app paid it.
_applied: Optional[tuple] = None


def _push_to_dock(image) -> None:
    import AppKit

    AppKit.NSApplication.sharedApplication().setApplicationIconImage_(image)


def set_dock_icon(
    status: str,
    rtt_ms: Optional[float] = None,
    ping_down: bool = False,
    apply: Optional[Callable] = None,
) -> None:
    """Cosmetic only -- a failure here must never take the monitor down.

    Skips the call entirely when the tile would be identical to the one already
    showing. See `_applied`: the underlying AppKit call is expensive and
    synchronous, so "the number has not changed" is worth checking. `apply` is
    the seam for that check: it receives the built image, and defaults to the
    real Dock call.
    """
    global _applied
    try:
        text, unit = dock_text(rtt_ms=rtt_ms, ping_down=ping_down)
        wanted = (status, text, unit)
        if wanted == _applied:
            return
        push = apply or _push_to_dock
        push(build_status_icon(status, text=text, unit=unit))
        # Recorded only after the push succeeds, so a failed push is retried on
        # the next tick rather than remembered as showing.
        _applied = wanted
    except Exception:  # noqa: BLE001 - cosmetic, never fatal
        pass


def _reset_for_tests() -> None:
    global _applied
    _applied = None
