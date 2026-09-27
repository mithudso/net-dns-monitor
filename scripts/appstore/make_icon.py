#!/usr/bin/env python3
"""Render the app icon as an .icns file.

Usage: python scripts/appstore/make_icon.py OUTPUT.icns
       python scripts/appstore/make_icon.py PREVIEW.png    # one 1024px render

The repo has no icon asset, and a bundle built outside Xcode needs an ICNS that
contains both 512x512 and 512x512@2x or App Store Connect rejects the upload.
This draws one with AppKit so the build has no binary asset to keep in sync,
and so the design is reviewable as code.

The icon: a rounded square on Apple's macOS icon grid (an 824pt body on a
1024pt canvas, 185pt corners, the template's drop shadow), teal fading to navy,
a wireframe globe, and a heartbeat trace running edge to edge as the globe's
equator. The pulse is the app: it watches whether the world is reachable.

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

    # The drop shadow Apple's macOS icon template carries. Cast from a solid
    # fill so it has one opaque source; the gradient is painted over it.
    AppKit.NSGraphicsContext.saveGraphicsState()
    shadow = AppKit.NSShadow.alloc().init()
    shadow.setShadowOffset_((0, -12))
    shadow.setShadowBlurRadius_(26)
    shadow.setShadowColor_(rgb(0.0, 0.0, 0.0, 0.32))
    shadow.set()
    rgb(0.02, 0.11, 0.27, 1.0).setFill()
    shape.fill()
    AppKit.NSGraphicsContext.restoreGraphicsState()

    # Teal at the top, deep navy at the bottom. Angle 90 runs the starting
    # colour from the bottom edge upwards, so the starting colour is the navy.
    gradient = AppKit.NSGradient.alloc().initWithStartingColor_endingColor_(
        rgb(0.02, 0.11, 0.27, 1.0), rgb(0.00, 0.52, 0.60, 1.0)
    )
    gradient.drawInBezierPath_angle_(shape, 90)
    # Light from above: a sheen centred near the top edge, gone by the middle.
    sheen = AppKit.NSGradient.alloc().initWithStartingColor_endingColor_(
        rgb(1.0, 1.0, 1.0, 0.16), rgb(1.0, 1.0, 1.0, 0.0)
    )
    sheen.drawInBezierPath_relativeCenterPosition_(shape, (0.0, 0.75))

    # Everything from here is clipped to the body: the pulse runs edge to edge.
    AppKit.NSGraphicsContext.saveGraphicsState()
    shape.addClip()

    rgb(1.0, 1.0, 1.0, 0.96).setStroke()
    center_x, center_y, radius = 512.0, 520.0, 262.0
    globe = AppKit.NSBezierPath.bezierPathWithOvalInRect_(
        AppKit.NSMakeRect(center_x - radius, center_y - radius, 2 * radius, 2 * radius)
    )
    globe.setLineWidth_(34)
    globe.stroke()

    meridian = AppKit.NSBezierPath.bezierPathWithOvalInRect_(
        AppKit.NSMakeRect(center_x - radius * 0.44, center_y - radius, radius * 0.88, 2 * radius)
    )
    meridian.setLineWidth_(22)
    meridian.stroke()

    # Two latitudes; the equator's place is taken by the pulse below.
    rgb(1.0, 1.0, 1.0, 0.80).setStroke()
    for offset in (-radius * 0.5, radius * 0.5):
        half = math.sqrt(max(radius**2 - offset**2, 0.0))
        line = AppKit.NSBezierPath.bezierPath()
        line.moveToPoint_((center_x - half, center_y + offset))
        line.lineToPoint_((center_x + half, center_y + offset))
        line.setLineWidth_(20)
        line.setLineCapStyle_(AppKit.NSLineCapStyleRound)
        line.stroke()

    # The heartbeat: baseline at the equator, one QRS spike through the centre
    # of the globe. A wide translucent stroke underneath gives it a glow.
    points = [
        (100, center_y),
        (392, center_y),
        (440, center_y),
        (476, center_y + 150),
        (514, center_y - 128),
        (548, center_y + 46),
        (576, center_y),
        (924, center_y),
    ]
    pulse = AppKit.NSBezierPath.bezierPath()
    pulse.moveToPoint_(points[0])
    for point in points[1:]:
        pulse.lineToPoint_(point)
    pulse.setLineJoinStyle_(AppKit.NSLineJoinStyleRound)
    pulse.setLineCapStyle_(AppKit.NSLineCapStyleRound)
    rgb(0.55, 1.0, 0.60, 0.28).setStroke()
    pulse.setLineWidth_(72)
    pulse.stroke()
    rgb(0.60, 1.0, 0.58, 1.0).setStroke()
    pulse.setLineWidth_(30)
    pulse.stroke()

    AppKit.NSGraphicsContext.restoreGraphicsState()


def main(argv: list) -> int:
    if len(argv) != 2 or not argv[1].endswith((".icns", ".png")):
        print(__doc__)
        return 2
    output = Path(argv[1])
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix == ".png":
        render_png(1024, output)
        print(output)
        return 0
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
