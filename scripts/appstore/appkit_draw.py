"""AppKit drawing helpers shared by the App Store scripts.

`make_icon.py`, `compose_screenshots.py` and `shoot_screenshots.py` each draw
into an offscreen bitmap and write a PNG. The bitmap set-up, the save and
restore of the graphics context and the PNG write live here once, as do the two
brand colours, so the screenshot background cannot drift from the icon when one
of them changes.

AppKit is imported inside each function: the module is also imported by the
test suite on machines where loading AppKit is not free, and `--help` paths of
the scripts should not pay for it either.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

# The icon's gradient, as sRGB components: navy at the bottom, teal at the top.
BRAND_NAVY = (0.02, 0.11, 0.27)
BRAND_TEAL = (0.00, 0.52, 0.60)


def new_canvas(width: int, height: int):
    """An RGBA bitmap AppKit can draw into.

    RGBA, never 24-bit RGB: AppKit refuses a graphics context over a rep that
    has no alpha channel ("Inconsistent set of values to create
    NSBitmapImageRep", then a crash). A caller that needs a PNG without an
    alpha channel calls `rep.setAlpha_(False)` after drawing instead.
    """
    import AppKit

    return AppKit.NSBitmapImageRep.alloc().initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel_(
        None, width, height, 8, 4, True, False, AppKit.NSDeviceRGBColorSpace, 0, 0
    )


@contextmanager
def drawing(rep) -> Iterator[object]:
    """Make `rep` the current graphics context for the block, then restore it."""
    import AppKit

    context = AppKit.NSGraphicsContext.graphicsContextWithBitmapImageRep_(rep)
    if context is None:
        raise RuntimeError("AppKit gave no graphics context for this bitmap")
    AppKit.NSGraphicsContext.saveGraphicsState()
    AppKit.NSGraphicsContext.setCurrentContext_(context)
    try:
        yield context
    finally:
        AppKit.NSGraphicsContext.restoreGraphicsState()


def brand_gradient():
    """The icon's gradient; angle 90 in `drawIn…angle:` puts the navy at the bottom."""
    import AppKit

    rgb = AppKit.NSColor.colorWithSRGBRed_green_blue_alpha_
    return AppKit.NSGradient.alloc().initWithStartingColor_endingColor_(
        rgb(*BRAND_NAVY, 1.0), rgb(*BRAND_TEAL, 1.0)
    )


def write_png(rep, path: Path) -> None:
    import AppKit

    data = rep.representationUsingType_properties_(AppKit.NSBitmapImageFileTypePNG, {})
    if data is None or not data.writeToFile_atomically_(str(path), True):
        raise OSError(f"could not write {path}")
