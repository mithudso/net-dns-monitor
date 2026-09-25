#!/usr/bin/env python3
"""Render the app icon as an .icns file.

Usage: python scripts/appstore/make_icon.py OUTPUT.icns

The repo has no icon asset, and a bundle built outside Xcode needs an ICNS that
contains both 512x512 and 512x512@2x or App Store Connect rejects the upload.
This draws one with AppKit so the build has no binary asset to keep in sync.

It is a placeholder that meets the technical requirements, not a designed
icon: a rounded square on Apple's macOS icon grid (an 824pt body on a 1024pt
canvas) with a globe and a pulse line. Replace it with a designed icon before
the first public release.

It deliberately does not use SF Symbols. Apple's SF Symbols licence does not
allow them in app icons.
"""

import math
import subprocess
import sys
import tempfile
from pathlib import Path

ICONSET_SIZES = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]


def render_png(pixels: int, path: Path) -> None:
    import AppKit

    rep = AppKit.NSBitmapImageRep.alloc().initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel_(
        None, pixels, pixels, 8, 4, True, False, AppKit.NSDeviceRGBColorSpace, 0, 0
    )
    context = AppKit.NSGraphicsContext.graphicsContextWithBitmapImageRep_(rep)
    AppKit.NSGraphicsContext.saveGraphicsState()
    AppKit.NSGraphicsContext.setCurrentContext_(context)
    try:
        scale = pixels / 1024.0
        transform = AppKit.NSAffineTransform.transform()
        transform.scaleBy_(scale)
        transform.concat()
        draw_icon()
    finally:
        AppKit.NSGraphicsContext.restoreGraphicsState()
    data = rep.representationUsingType_properties_(AppKit.NSBitmapImageFileTypePNG, {})
    data.writeToFile_atomically_(str(path), True)


def draw_icon() -> None:
    import AppKit

    rgb = AppKit.NSColor.colorWithSRGBRed_green_blue_alpha_
    body = AppKit.NSMakeRect(100, 100, 824, 824)
    shape = AppKit.NSBezierPath.bezierPathWithRoundedRect_xRadius_yRadius_(body, 185, 185)
    gradient = AppKit.NSGradient.alloc().initWithStartingColor_endingColor_(
        rgb(0.05, 0.36, 0.55, 1.0), rgb(0.02, 0.62, 0.58, 1.0)
    )
    gradient.drawInBezierPath_angle_(shape, 90)

    white = rgb(1.0, 1.0, 1.0, 0.95)
    white.setStroke()
    center_x, center_y, radius = 512.0, 540.0, 250.0
    globe = AppKit.NSBezierPath.bezierPathWithOvalInRect_(
        AppKit.NSMakeRect(center_x - radius, center_y - radius, 2 * radius, 2 * radius)
    )
    globe.setLineWidth_(34)
    globe.stroke()

    meridian = AppKit.NSBezierPath.bezierPathWithOvalInRect_(
        AppKit.NSMakeRect(center_x - radius * 0.45, center_y - radius, radius * 0.9, 2 * radius)
    )
    meridian.setLineWidth_(24)
    meridian.stroke()

    for offset in (-radius * 0.45, 0.0, radius * 0.45):
        half = math.sqrt(max(radius**2 - offset**2, 0.0))
        line = AppKit.NSBezierPath.bezierPath()
        line.moveToPoint_((center_x - half, center_y + offset))
        line.lineToPoint_((center_x + half, center_y + offset))
        line.setLineWidth_(24)
        line.stroke()

    rgb(0.55, 1.0, 0.62, 1.0).setStroke()
    pulse = AppKit.NSBezierPath.bezierPath()
    points = [(200, 215), (400, 215), (455, 300), (520, 150), (575, 260), (620, 215), (824, 215)]
    pulse.moveToPoint_(points[0])
    for point in points[1:]:
        pulse.lineToPoint_(point)
    pulse.setLineWidth_(30)
    pulse.setLineJoinStyle_(AppKit.NSLineJoinStyleRound)
    pulse.setLineCapStyle_(AppKit.NSLineCapStyleRound)
    pulse.stroke()


def main(argv: list) -> int:
    if len(argv) != 2 or not argv[1].endswith(".icns"):
        print(__doc__)
        return 2
    output = Path(argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "AppIcon.iconset"
        iconset.mkdir()
        for name, pixels in ICONSET_SIZES:
            render_png(pixels, iconset / name)
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(output)], check=True)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
