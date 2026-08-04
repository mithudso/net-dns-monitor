"""These exercise real AppKit drawing (no injected fakes) rather than
skip it the way app.py's rumps event loop is skipped -- unlike a real
run loop, NSImage/NSBitmapImageRep offscreen rendering works headlessly
and its output (size, transparency, tinted color) is deterministically
checkable, so there is no reason to leave it untested.

Colour is sampled as the mean of the *opaque* pixels rather than the single
centre pixel. The tile now draws text, and the exact centre of a string like
"61ms" can easily land in the gap between two glyphs, so a centre-pixel
assertion would be testing where the kerning happened to fall.
"""

import pytest

from netdnsmonitor.dock_icon import NO_DATA_TEXT, PING_DOWN_TEXT, build_status_icon, dock_text


def _rep(image):
    import AppKit

    return AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())


def _pixels(image):
    rep = _rep(image)
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    # Every 2nd pixel: enough coverage to find the drawn glyphs, ~4x cheaper.
    return [rep.colorAtX_y_(x, y) for x in range(0, w, 2) for y in range(0, h, 2)]


def _mean_opaque_color(image):
    opaque = [c for c in _pixels(image) if c.alphaComponent() > 0.5]
    assert opaque, "nothing was drawn -- the tile is entirely transparent"
    n = len(opaque)
    return (
        sum(c.redComponent() for c in opaque) / n,
        sum(c.greenComponent() for c in opaque) / n,
        sum(c.blueComponent() for c in opaque) / n,
    )


def _opaque_fraction(image):
    pixels = _pixels(image)
    return sum(1 for c in pixels if c.alphaComponent() > 0.5) / len(pixels)


def test_returns_image_of_requested_size():
    image = build_status_icon("healthy", text="61", unit="ms", size=64)
    assert tuple(image.size()) == (64, 64)


def test_corners_are_fully_transparent():
    """The tile must not be an opaque square: the Dock composites it, and a
    filled background would draw a coloured block over the app's shape.
    """
    image = build_status_icon("healthy", text="61", unit="ms", size=64)
    assert _rep(image).colorAtX_y_(1, 1).alphaComponent() == pytest.approx(0.0, abs=1e-6)


def test_healthy_status_tints_green():
    red, green, blue = _mean_opaque_color(build_status_icon("healthy", text="61", size=64))
    assert green > red
    assert green > blue


def test_incident_status_tints_red():
    red, green, blue = _mean_opaque_color(build_status_icon("incident", text="61", size=64))
    assert red > green
    assert red > blue


def test_flaky_status_tints_yellow():
    red, green, blue = _mean_opaque_color(build_status_icon("flaky", text="61", size=64))
    assert red > blue
    assert green > blue


def test_unknown_status_falls_back_to_healthy_green():
    red, green, blue = _mean_opaque_color(
        build_status_icon("some-unknown-state", text="61", size=64)
    )
    assert green > red
    assert green > blue


def test_the_reading_is_actually_drawn_not_just_the_colour():
    """The whole point of the change: the tile carries the number. Colour
    assertions alone would pass on a blank image, which is why
    _mean_opaque_color asserts non-empty -- and this pins that more digits put
    more ink on the tile, i.e. the text argument is really being rendered.
    """
    narrow = _opaque_fraction(build_status_icon("healthy", text="1", size=128))
    wide = _opaque_fraction(build_status_icon("healthy", text="888", size=128))
    assert wide > narrow > 0


def test_a_wide_reading_is_shrunk_to_fit_instead_of_overflowing():
    """`1204ms` is a plausible reading on a bad hotel network. Without the
    shrink-to-fit pass NSAttributedString draws straight off the edge of the
    image and the number silently loses its leading digits.
    """
    rep = _rep(build_status_icon("healthy", text="1204", unit="ms", size=64))
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    for y in range(0, h, 2):
        assert rep.colorAtX_y_(0, y).alphaComponent() == pytest.approx(0.0, abs=1e-6)
        assert rep.colorAtX_y_(w - 1, y).alphaComponent() == pytest.approx(0.0, abs=1e-6)


def test_the_unit_line_adds_ink_below_the_number():
    with_unit = _opaque_fraction(build_status_icon("healthy", text="61", unit="ms", size=128))
    without = _opaque_fraction(build_status_icon("healthy", text="61", unit="", size=128))
    assert with_unit > without


def test_the_ping_down_cross_actually_renders():
    """The tile that exists for the exact moment the feature is for. Every other
    drawing test here uses digits, and `set_dock_icon` swallows exceptions, so a
    glyph without a usable font would leave the Dock blank throughout an outage
    with nothing logged. Measured: 130 of 4096 sampled pixels opaque, red.
    """
    image = build_status_icon("incident", text=PING_DOWN_TEXT, size=64)
    red, green, blue = _mean_opaque_color(image)
    assert red > green
    assert red > blue


def test_empty_text_still_produces_a_valid_image():
    """Defensive: an empty string must not raise out of a repaint that happens
    on every tick.
    """
    image = build_status_icon("healthy", text="", unit="", size=64)
    assert tuple(image.size()) == (64, 64)


# --- dock_text -------------------------------------------------------------


def test_dock_text_shows_the_round_trip_time_in_whole_milliseconds():
    assert dock_text(rtt_ms=61.366) == ("61", "ms")


def test_dock_text_shows_a_cross_when_pings_go_unanswered():
    assert dock_text(rtt_ms=None, ping_down=True) == (PING_DOWN_TEXT, "")


def test_ping_down_wins_over_a_stale_round_trip_time():
    """A number left over from the last successful ping, drawn while the network
    is down, reads as a working connection.
    """
    assert dock_text(rtt_ms=61.0, ping_down=True) == (PING_DOWN_TEXT, "")


def test_dock_text_before_the_first_ping_is_a_placeholder():
    assert dock_text() == (NO_DATA_TEXT, "")
