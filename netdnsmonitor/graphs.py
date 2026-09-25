"""Draw the history as line graphs.

Rendered into an `NSImage` and handed to an `NSImageView`, rather than
subclassing `NSView` and overriding `drawRect_`. Two reasons, both of which have
already cost this project time: an ObjC class may only be registered once per
process (see `dashboard._button_target_class`), and offscreen `NSImage` drawing
works headlessly, so `test_graphs.py` can sample pixels the way
`test_dock_icon.py` already does. A custom view would be untestable without a
window on screen.

**Gaps are drawn as gaps.** `None` in a series means "not measured" -- a failed
ping, or throughput before the second sample. The line is broken there instead of
being interpolated across it, because a straight line drawn through an outage
hides the one thing the graph exists to show. Each gap also gets a faint vertical
marker so a short outage is visible even where the break is a single pixel wide.

**Two graphs, not one with two axes.** A 61ms latency line and a 1.2Mbps
throughput line share no sensible scale; on one pair of axes either the latency is
a flat line at the bottom or the throughput is off the top.
"""

import math
from typing import Optional

MARGIN_LEFT = 44  # room for the y-axis labels
MARGIN_RIGHT = 6
MARGIN_TOP = 16  # room for the title
MARGIN_BOTTOM = 12

GRID_LINES = 3
DOT_RADIUS = 1.5  # an isolated sample, drawn about as wide as the 1.5pt line

COLOR_NAMES = {
    "latency": "systemBlueColor",
    "download": "systemGreenColor",
    "upload": "systemPurpleColor",
}


def _measured(value) -> bool:
    # `is not None` alone lets NaN and inf through: max() of a series holding a
    # NaN is NaN, every point then projects to the top edge and the axis reads
    # "nan". A non-finite sample is not a measurement.
    return value is not None and math.isfinite(value)


def latest_label(values: list, formatter=None, unit: str = "") -> str:
    """The headline number for a series, or "--" when the newest sample is a gap.

    Reads the *last* slot, not the last measured value: during an outage the
    latest measured value is the one from before it broke, and "60ms" on a
    graph whose right edge is a gap claims the network is fine right now.
    """
    latest = values[-1] if values else None
    if not _measured(latest):
        return "--"
    return f"{(formatter or _plain)(latest)}{unit}"


def scale(values: list, height: float) -> tuple:
    """Return (lo, hi, project) for a series, where project(value) -> y offset.

    The floor is pinned at zero rather than at the minimum: latency that wobbles
    between 60 and 64ms would otherwise fill the whole graph and read as wild
    instability. A graph of network measurements is only honest with zero on it.
    """
    real = [v for v in values if _measured(v)]
    hi = max(real) if real else 1.0
    if hi <= 0:
        hi = 1.0
    # A little headroom so the peak is not drawn exactly on the top edge.
    hi *= 1.1

    def project(value: float) -> float:
        return max(0.0, min(1.0, value / hi)) * height

    return 0.0, hi, project


def render_series_graph(
    values: list,
    title: str = "",
    kind: str = "latency",
    unit: str = "",
    size: tuple = (560, 100),
    format_value=None,
):
    """One line graph as an NSImage. Never raises on odd input.

    `values` is oldest-first and may contain None. `format_value` renders the axis
    labels; it defaults to a plain integer, which suits milliseconds.
    """
    import AppKit
    from Foundation import NSMakeRect

    width, height = int(size[0]), int(size[1])
    formatter = format_value or _plain

    image = AppKit.NSImage.alloc().initWithSize_((width, height))
    image.lockFocus()
    try:
        plot_width = max(1, width - MARGIN_LEFT - MARGIN_RIGHT)
        plot_height = max(1, height - MARGIN_TOP - MARGIN_BOTTOM)
        origin_x, origin_y = MARGIN_LEFT, MARGIN_BOTTOM

        _draw_text(AppKit, title, 8.5, MARGIN_LEFT, height - MARGIN_TOP + 2, "secondaryLabelColor")

        real = [v for v in values if _measured(v)]
        if not real:
            # A placeholder rather than an empty box: "no data yet" and "flat at
            # zero" are different states and must not look identical.
            _draw_text(
                AppKit,
                "collecting…",
                9.0,
                origin_x + plot_width / 2 - 24,
                origin_y + plot_height / 2 - 5,
                "tertiaryLabelColor",
            )
            return image

        _, hi, project = scale(values, plot_height)

        # Grid and y-axis labels.
        grid = AppKit.NSColor.separatorColor()
        grid.setStroke()
        for index in range(GRID_LINES + 1):
            fraction = index / GRID_LINES
            y = origin_y + fraction * plot_height
            line = AppKit.NSBezierPath.bezierPath()
            line.setLineWidth_(0.5)
            line.moveToPoint_((origin_x, y))
            line.lineToPoint_((origin_x + plot_width, y))
            line.stroke()
            _draw_text(
                AppKit,
                f"{formatter(hi * fraction)}{unit}",
                8.0,
                2,
                y - 5,
                "tertiaryLabelColor",
            )

        step = plot_width / max(1, len(values) - 1) if len(values) > 1 else plot_width

        # Gap markers first, so the line draws over them.
        gap_color = AppKit.NSColor.systemRedColor().colorWithAlphaComponent_(0.18)
        gap_color.setFill()
        for index, value in enumerate(values):
            if not _measured(value):
                x = origin_x + index * step
                AppKit.NSRectFillUsingOperation(
                    NSMakeRect(x - step / 2, origin_y, max(1.0, step), plot_height),
                    AppKit.NSCompositingOperationSourceOver,
                )

        color = getattr(AppKit.NSColor, COLOR_NAMES.get(kind, "systemBlueColor"))()
        color.setStroke()
        path = AppKit.NSBezierPath.bezierPath()
        path.setLineWidth_(1.5)
        pen_down = False
        for index, value in enumerate(values):
            if not _measured(value):
                # Lift the pen. The next real point starts a new subpath, which is
                # what makes the gap a gap rather than a line across it.
                pen_down = False
                continue
            point = (origin_x + index * step, origin_y + project(value))
            if pen_down:
                path.lineToPoint_(point)
            else:
                path.moveToPoint_(point)
                pen_down = True
        path.stroke()

        # A measured sample with a gap on both sides is a subpath of one
        # moveToPoint, and stroking that draws nothing -- so alternating 50% loss
        # rendered exactly like a total outage. Those points get a dot instead.
        color.setFill()
        for index, value in enumerate(values):
            if value is None:
                continue
            before = values[index - 1] if index > 0 else None
            after = values[index + 1] if index + 1 < len(values) else None
            if before is None and after is None:
                x, y = origin_x + index * step, origin_y + project(value)
                AppKit.NSBezierPath.bezierPathWithOvalInRect_(
                    NSMakeRect(x - DOT_RADIUS, y - DOT_RADIUS, 2 * DOT_RADIUS, 2 * DOT_RADIUS)
                ).fill()

        # The latest value, spelled out -- reading a number off a line is guesswork.
        _draw_text(
            AppKit,
            latest_label(values, formatter, unit),
            9.0,
            origin_x + plot_width - 52,
            height - MARGIN_TOP + 2,
            "labelColor",
        )
    finally:
        # An exception between lockFocus and unlockFocus unbalances the focus
        # stack for the whole process and corrupts every later draw, including
        # the menu bar's.
        image.unlockFocus()
    return image


def _plain(value: float) -> str:
    return f"{value:.0f}"


def _draw_text(AppKit, text: str, point_size: float, x: float, y: float, color_name: str):
    if not text:
        return
    color = getattr(AppKit.NSColor, color_name, AppKit.NSColor.labelColor)()
    font = AppKit.NSFont.monospacedSystemFontOfSize_weight_(point_size, AppKit.NSFontWeightRegular)
    AppKit.NSAttributedString.alloc().initWithString_attributes_(
        text,
        {AppKit.NSFontAttributeName: font, AppKit.NSForegroundColorAttributeName: color},
    ).drawAtPoint_((x, y))


def format_bits(value: Optional[float]) -> str:
    """Throughput for the graph axes and the dashboard's stats pane.

    Not plain `format_rate`: that rounds anything under 1K to "0" so the menu bar
    stays short, which here labels a real trickle as nothing moving at all. There
    is room for "587" on an axis.
    """
    from netdnsmonitor.status import format_rate

    if value is not None and 0 < value < 1e3:
        return f"{value:.0f}"
    return format_rate(value)
