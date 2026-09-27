#!/usr/bin/env python3
"""Place window renders on 2880x1800 backgrounds for App Store Connect.

Usage: .venv/bin/python scripts/appstore/compose_screenshots.py IN_DIR OUT_DIR

Every PNG in IN_DIR becomes OUT_DIR/<name>.png: exactly 2880x1800, no alpha
channel (App Store Connect refuses one), the window scaled down to fit inside a
margin (never up) and centred, with a drop shadow, on the icon's teal-to-navy
gradient. A source that cannot be read is reported and skipped; the exit
status is 1 if any was. AppKit only, so it runs on the project venv.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # sibling helpers, when run as a script
from appkit_draw import brand_gradient, drawing, new_canvas, write_png  # noqa: E402

# The canvas is a 1440x900-point display at 2x, the store's largest 16:10 size.
WIDTH, HEIGHT = 2880, 1800
CANVAS_SCALE = 2
# Store product pages show screenshots as small thumbnails first; a wide margin
# keeps the window's own drop shadow inside the frame and reads as one object.
MARGIN = 140
# Larger and darker than the icon's shadow: at thumbnail size a subtle one
# vanishes and the dark window dissolves into the dark bottom of the gradient.
SHADOW_OFFSET, SHADOW_BLUR, SHADOW_ALPHA = (0, -18), 40, 0.55


def fit(points_wide: float, points_high: float) -> tuple[float, float, float, float]:
    """The centred pixel rect (x, y, width, height) for a window of that size in points.

    Sized in points, not pixels: the same window captured on a 1x display
    holds half the pixels it does on a Retina one, and fitting by pixel count
    framed the two runs differently. At 2x every point is two canvas pixels, so
    a window is drawn at its Retina size, and scaled down only when that does
    not fit inside the margin. It is never drawn larger than that.
    """
    if points_wide <= 0 or points_high <= 0:
        raise ValueError(f"empty image: {points_wide:g}x{points_high:g} points")
    wide, high = points_wide * CANVAS_SCALE, points_high * CANVAS_SCALE
    scale = min((WIDTH - 2 * MARGIN) / wide, (HEIGHT - 2 * MARGIN) / high, 1.0)
    width, height = wide * scale, high * scale
    return (WIDTH - width) / 2, (HEIGHT - height) / 2, width, height


def compose(src: Path, dst: Path) -> None:
    import AppKit

    window = AppKit.NSBitmapImageRep.imageRepWithContentsOfFile_(str(src))
    if window is None:
        raise ValueError(f"not an image: {src}")
    # size() is the image's point size from the PNG's resolution metadata,
    # which shoot_screenshots.py's renders carry (2552 px wide reads as 1276
    # pt). A PNG without it reads as 72 dpi, one point per pixel, the 1x case.
    points = window.size()
    x, y, width, height = fit(points.width, points.height)

    canvas = new_canvas(WIDTH, HEIGHT)
    with drawing(canvas) as context:
        brand_gradient().drawInRect_angle_(AppKit.NSMakeRect(0, 0, WIDTH, HEIGHT), 90)
        shadow = AppKit.NSShadow.alloc().init()
        shadow.setShadowOffset_(SHADOW_OFFSET)
        shadow.setShadowBlurRadius_(SHADOW_BLUR)
        shadow.setShadowColor_(
            AppKit.NSColor.colorWithSRGBRed_green_blue_alpha_(0.0, 0.0, 0.0, SHADOW_ALPHA)
        )
        shadow.set()
        context.setImageInterpolation_(AppKit.NSImageInterpolationHigh)
        window.drawInRect_fromRect_operation_fraction_respectFlipped_hints_(
            AppKit.NSMakeRect(x, y, width, height),
            AppKit.NSZeroRect,
            AppKit.NSCompositingOperationSourceOver,
            1.0,
            False,
            None,
        )
    # The gradient covered every pixel, so dropping the channel loses nothing,
    # and the PNG comes out without alpha as the store requires.
    canvas.setAlpha_(False)
    write_png(canvas, dst)
    print(f"{dst.name}: {WIDTH}x{HEIGHT} from {src.name} at {width / window.pixelsWide():.2f}x")


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__)
        return 2
    src_dir, out_dir = Path(argv[1]), Path(argv[2])
    sources = sorted(src_dir.glob("*.png"))
    if not sources:
        print(f"no PNG files in {src_dir}", file=sys.stderr)
        return 1
    out_dir.mkdir(parents=True, exist_ok=True)
    failed = []
    for src in sources:
        try:
            compose(src, out_dir / src.name)
        except (ValueError, OSError) as exc:
            failed.append(src.name)
            print(f"{src.name}: skipped: {exc}", file=sys.stderr)
    print(f"composed {len(sources) - len(failed)} of {len(sources)} into {out_dir}")
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
