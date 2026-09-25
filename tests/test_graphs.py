"""The history graphs.

Real AppKit drawing sampled by pixel, the same approach test_dock_icon.py takes:
offscreen NSImage rendering works headlessly and its output is deterministic, so
there is no reason to mock it. Measured values are quoted in the assertions'
comments so a regression shows up as a number that moved rather than a vague
"looks different".
"""

import math

import AppKit

from netdnsmonitor.graphs import format_bits, latest_label, render_series_graph, scale

FLAT = [60.0] * 60
SPIKY = [60.0 if index % 2 else 300.0 for index in range(60)]
WITH_GAP = [60.0] * 20 + [None] * 10 + [60.0] * 30


def opaque_fraction(image, stride=3):
    rep = AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    pixels = [rep.colorAtX_y_(x, y) for x in range(0, w, stride) for y in range(0, h, stride)]
    return sum(1 for c in pixels if c.alphaComponent() > 0.5) / len(pixels)


def column_has_ink(image, x_fraction, min_alpha=0.05):
    """Any ink at all in one column.

    A much lower alpha threshold than opaque_fraction on purpose: the outage
    marker is deliberately faint (0.18 alpha) so it does not shout over the line,
    and a 0.5 threshold would report it as blank.
    """
    rep = AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    x = int(w * x_fraction)
    return any(rep.colorAtX_y_(x, y).alphaComponent() > min_alpha for y in range(0, h))


# --- scaling ---------------------------------------------------------------


def test_the_floor_is_pinned_at_zero_not_at_the_minimum():
    """Latency wobbling between 60 and 64ms would otherwise fill the graph and
    read as wild instability. A graph of network measurements is only honest with
    zero on it.
    """
    lo, hi, _ = scale([60.0, 64.0], 100)
    assert lo == 0.0
    assert hi > 64.0


def test_the_top_has_headroom_so_the_peak_is_not_on_the_edge():
    _, hi, project = scale([100.0], 100)
    assert hi > 100.0
    assert project(100.0) < 100.0


def test_an_all_none_series_does_not_divide_by_zero():
    _, hi, project = scale([None, None], 100)
    assert hi > 0
    assert project(0.0) == 0.0


def test_an_all_zero_series_does_not_divide_by_zero():
    """Genuinely possible: an idle machine reports 0 bps for both directions."""
    _, hi, project = scale([0.0, 0.0], 100)
    assert hi > 0
    assert project(0.0) == 0.0


def test_values_above_the_ceiling_are_clamped_into_the_plot():
    _, _, project = scale([10.0], 100)
    assert project(1e9) <= 100.0


def test_a_nan_sample_does_not_poison_the_scale():
    """max() of a series holding NaN is NaN: every point then projects to the
    top edge and the axis reads "nan". A non-finite sample is not a measurement.
    """
    _, hi, project = scale([float("nan"), 60.0], 100)
    assert math.isfinite(hi) and hi > 60
    assert project(60.0) < 100
    _, hi_inf, _ = scale([float("inf"), 60.0], 100)
    assert math.isfinite(hi_inf)


# --- headline ----------------------------------------------------------------


def test_the_headline_is_a_dash_when_the_newest_sample_is_a_gap():
    """ "60ms" on a graph whose right edge is an outage claims the network is
    fine right now; the last *measured* value is the one from before it broke.
    """
    fmt = lambda v: f"{v:.0f}"  # noqa: E731
    assert latest_label([60.0, None], fmt, "ms") == "--"
    assert latest_label([], fmt, "ms") == "--"
    assert latest_label([60.0, float("nan")], fmt, "ms") == "--"


def test_the_headline_is_the_newest_value_when_it_was_measured():
    assert latest_label([None, 60.0], lambda v: f"{v:.0f}", "ms") == "60ms"


def test_a_series_ending_in_a_gap_still_renders():
    render_series_graph([60.0] * 10 + [None] * 5, title="Latency", unit="ms")


def test_a_nan_sample_renders_as_a_gap_rather_than_raising():
    image = render_series_graph([60.0] * 20 + [float("nan")] * 10 + [60.0] * 30)
    assert column_has_ink(image, 0.45)


# --- rendering -------------------------------------------------------------


def test_a_graph_is_the_requested_size():
    assert tuple(render_series_graph(FLAT, size=(400, 80)).size()) == (400.0, 80.0)


def test_a_series_is_actually_drawn():
    # Measured: ~0.015 of sampled pixels for a flat 60ms line.
    assert opaque_fraction(render_series_graph(FLAT, title="Latency", unit="ms")) > 0.005


def test_a_spiky_series_puts_more_ink_on_the_graph_than_a_flat_one():
    """The property that proves the values reach the drawing, not just that
    *something* was drawn. Measured: flat ~0.015, spiky ~0.085.
    """
    flat = opaque_fraction(render_series_graph(FLAT))
    spiky = opaque_fraction(render_series_graph(SPIKY))
    assert spiky > flat * 2


def any_ink_fraction(image, stride=3, min_alpha=0.05):
    """Fraction of sampled pixels with *any* ink.

    Separate from opaque_fraction because the placeholder text is drawn in
    tertiaryLabelColor, whose alpha sits below 0.5 -- measuring it against the
    opaque threshold made this test depend on which antialiased pixels happened
    to tip over 0.5, and it passed and failed on identical code.
    """
    rep = AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
    w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
    pixels = [rep.colorAtX_y_(x, y) for x in range(0, w, stride) for y in range(0, h, stride)]
    return sum(1 for c in pixels if c.alphaComponent() > min_alpha) / len(pixels)


def test_an_empty_series_renders_a_placeholder_rather_than_raising():
    """ "No data yet" and "flat at zero" are different states and must not look
    identical -- otherwise a broken history reads as a perfectly idle network.
    """
    image = render_series_graph([], title="Latency")
    assert tuple(image.size())[0] > 0
    # Something is drawn (the title and the "collecting…" placeholder), but far
    # less than a real series with its grid, labels and line.
    assert 0 < any_ink_fraction(image) < any_ink_fraction(render_series_graph(FLAT))


def test_an_all_none_series_renders_the_placeholder_too():
    """What the first minutes after launch look like: samples exist but nothing
    resolved yet.
    """
    image = render_series_graph([None] * 30, title="Latency")
    assert any_ink_fraction(image) < any_ink_fraction(render_series_graph(FLAT))


def test_a_single_sample_does_not_divide_by_zero_on_the_x_step():
    render_series_graph([61.0], title="Latency")


def test_a_gap_is_drawn_as_a_gap_not_interpolated_across():
    """A straight line through an outage hides the one thing the graph exists to
    show. The gap also gets a faint marker, so this asserts the *marked* column
    differs from a series with no gap at all.
    """
    gapped = render_series_graph(WITH_GAP)
    ungapped = render_series_graph([60.0] * 60)
    assert opaque_fraction(gapped) != opaque_fraction(ungapped)
    # The outage region is still marked, so the column is not simply blank.
    assert column_has_ink(gapped, 0.45)
    # But only faintly: the marker is 0.18 alpha (measured max 0.28 in the
    # column). A None drawn as 0 would put the opaque line (1.0) through here,
    # and the assertion above alone would not notice.
    assert not column_has_ink(gapped, 0.45, min_alpha=0.5)


def test_the_throughput_formatter_is_used_for_the_axis():
    """A throughput axis labelled in raw bits per second would read 1200000."""
    assert format_bits(1_200_000) == "1.2M"
    render_series_graph([1.2e6] * 20, kind="download", format_value=format_bits)


def test_each_kind_gets_its_own_colour():
    """Three series on three graphs; sharing one colour would make the window
    harder to read at a glance, which is the only reason it exists.
    """

    def mean_colour(image):
        rep = AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
        w, h = int(rep.pixelsWide()), int(rep.pixelsHigh())
        opaque = [
            rep.colorAtX_y_(x, y)
            for x in range(0, w, 2)
            for y in range(0, h, 2)
            if rep.colorAtX_y_(x, y).alphaComponent() > 0.5
        ]
        n = len(opaque)
        return (
            sum(c.redComponent() for c in opaque) / n,
            sum(c.greenComponent() for c in opaque) / n,
            sum(c.blueComponent() for c in opaque) / n,
        )

    latency = mean_colour(render_series_graph(SPIKY, kind="latency"))
    download = mean_colour(render_series_graph(SPIKY, kind="download"))
    assert latency != download


def test_an_unknown_kind_falls_back_instead_of_raising():
    render_series_graph(FLAT, kind="not-a-real-kind")


def test_corners_stay_transparent_so_the_graph_composites():
    image = render_series_graph(FLAT)
    rep = AppKit.NSBitmapImageRep.imageRepWithData_(image.TIFFRepresentation())
    assert rep.colorAtX_y_(int(rep.pixelsWide()) - 2, 1).alphaComponent() < 0.6
