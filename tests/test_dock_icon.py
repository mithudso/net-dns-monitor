"""These exercise real AppKit drawing (no injected fakes) rather than
skip it the way app.py's rumps event loop is skipped -- unlike a real
run loop, NSImage/NSBitmapImageRep offscreen rendering works headlessly
and its output (size, transparency, tinted color) is deterministically
checkable, so there is no reason to leave it untested.
"""

import pytest

from netdnsmonitor.dock_icon import build_status_icon


def _corner_and_center_colors(image):
    tiff = image.TIFFRepresentation()
    import AppKit

    rep = AppKit.NSBitmapImageRep.imageRepWithData_(tiff)
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    corner = rep.colorAtX_y_(1, 1)
    center = rep.colorAtX_y_(w // 2, h // 2)
    return corner, center


def test_returns_image_of_requested_size():
    image = build_status_icon("healthy", size=64)
    assert tuple(image.size()) == (64, 64)


def test_corners_are_fully_transparent():
    image = build_status_icon("healthy", size=64)
    corner, _ = _corner_and_center_colors(image)
    assert corner.alphaComponent() == pytest.approx(0.0, abs=1e-6)


def test_healthy_status_tints_green():
    _, center = _corner_and_center_colors(build_status_icon("healthy", size=64))
    assert center.alphaComponent() > 0.9
    assert center.greenComponent() > center.redComponent()
    assert center.greenComponent() > center.blueComponent()


def test_incident_status_tints_red():
    _, center = _corner_and_center_colors(build_status_icon("incident", size=64))
    assert center.redComponent() > center.greenComponent()
    assert center.redComponent() > center.blueComponent()


def test_flaky_status_tints_yellow():
    _, center = _corner_and_center_colors(build_status_icon("flaky", size=64))
    assert center.redComponent() > center.blueComponent()
    assert center.greenComponent() > center.blueComponent()


def test_unknown_status_falls_back_to_healthy_green():
    _, center = _corner_and_center_colors(build_status_icon("some-unknown-state", size=64))
    assert center.greenComponent() > center.redComponent()
    assert center.greenComponent() > center.blueComponent()


def test_invalid_symbol_name_raises_a_clear_error_not_an_attributeerror():
    with pytest.raises(ValueError, match="no SF Symbol"):
        build_status_icon("healthy", symbol_name="this-is-not-a-real-symbol-name", size=64)
