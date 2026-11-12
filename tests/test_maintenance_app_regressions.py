"""Synthetic regressions for the corroborated app maintenance findings."""

import sys
from types import SimpleNamespace

import pytest

from netdnsmonitor import graphs, ui_style
from netdnsmonitor.app import NetDnsMonitorApp


@pytest.fixture
def drawing(monkeypatch):
    dots, labels = [], []

    class Image:
        @classmethod
        def alloc(cls):
            return cls()

        def initWithSize_(self, size):
            return self

        def lockFocus(self):
            pass

        def unlockFocus(self):
            pass

    class Path:
        @classmethod
        def bezierPath(cls):
            return cls()

        @classmethod
        def bezierPathWithOvalInRect_(cls, rect):
            dots.append(rect)
            return cls()

        def setLineWidth_(self, width):
            pass

        def moveToPoint_(self, point):
            pass

        def lineToPoint_(self, point):
            pass

        def stroke(self):
            pass

        def fill(self):
            pass

    class Color:
        def setStroke(self):
            pass

        def setFill(self):
            pass

        def colorWithAlphaComponent_(self, alpha):
            return self

    color = Color()
    monkeypatch.setitem(
        sys.modules,
        "AppKit",
        SimpleNamespace(
            NSImage=Image,
            NSBezierPath=Path,
            NSColor=SimpleNamespace(
                separatorColor=lambda: color,
                systemRedColor=lambda: color,
                systemBlueColor=lambda: color,
            ),
            NSRectFillUsingOperation=lambda *a: None,
            NSCompositingOperationSourceOver=0,
        ),
    )
    monkeypatch.setitem(sys.modules, "Foundation", SimpleNamespace(NSMakeRect=lambda *a: a))
    monkeypatch.setattr(graphs, "_draw_text", lambda kit, text, *a: labels.append(text))
    return dots, labels


@pytest.mark.parametrize("missing", [None, float("nan"), float("inf"), float("-inf")])
def test_finite_samples_next_to_missing_measurements_are_drawn(drawing, missing):
    dots, _ = drawing
    graphs.render_series_graph([50.0, missing, 50.0])
    assert len(dots) == 2
    assert dots[0][0] < dots[1][0]


def test_axis_formatter_output_reaches_the_drawing_operation(drawing):
    _, labels = drawing
    values = []

    def formatter(value):
        values.append(value)
        return f"formatted:{value}"

    graphs.render_series_graph([50.0] * 3, format_value=formatter, unit="ms")
    expected_axis = [55.0 * i / graphs.GRID_LINES for i in range(graphs.GRID_LINES + 1)]
    assert values[: len(expected_axis)] == pytest.approx(expected_axis)
    assert all(f"formatted:{v}ms" in labels for v in values[: len(expected_axis)])


@pytest.mark.parametrize("glass", [True, False])
@pytest.mark.parametrize("failure", ["attach", "frame", "install"])
def test_styling_failure_restores_the_original_window_content(glass, failure):
    original_frame = (0, 0, 50, 50)

    class Content:
        def __init__(self):
            self.current_frame = original_frame

        def frame(self):
            return self.current_frame

        def setFrame_(self, frame):
            self.current_frame = frame
            if failure == "frame" and frame != original_frame:
                raise RuntimeError("synthetic frame failure")

        def setAutoresizingMask_(self, mask):
            pass

    class Wrapper:
        @classmethod
        def alloc(cls):
            return cls()

        def initWithFrame_(self, frame):
            return self

        def setContentView_(self, content):
            if failure == "attach":
                raise RuntimeError("synthetic attachment failure")

        addSubview_ = setContentView_

        def bounds(self):
            return (0, 0, 99, 99)

        def setMaterial_(self, value):
            pass

        setBlendingMode_ = setMaterial_
        setState_ = setMaterial_

    content = Content()

    class Window:
        current = content

        def contentView(self):
            return self.current

        def setContentView_(self, view):
            self.current = view
            if failure == "install" and view is not content:
                raise RuntimeError("synthetic post-install failure")

    kit = SimpleNamespace(NSVisualEffectView=Wrapper)
    if glass:
        kit.NSGlassEffectView = Wrapper
        kit.NSBezelStyleGlass = 16
    window = Window()
    assert ui_style.apply_window_glass(kit, window) == "plain"
    assert window.contentView() is content
    assert content.frame() == original_frame


def test_delayed_privilege_worker_keeps_the_injected_launch_providers(tmp_path, monkeypatch):
    import netdnsmonitor.app as module

    app = NetDnsMonitorApp(config_path=str(tmp_path / "absent.yaml"))
    pending = []

    class DelayedThread:
        def __init__(self, target, args=(), kwargs=None, **options):
            pending.append(lambda: target(*args, **(kwargs or {})))

        def start(self):
            pass

    with monkeypatch.context() as launch:
        launch.setattr(module.privileges, "granted_commands_now", lambda: [])
        launch.setattr(module.privileges, "dhcp_interfaces", lambda: ["synthetic0"])
        launch.setattr(module.privileges, "primary_interface", lambda: "synthetic0")
        launch.setattr(module.threading, "Thread", DelayedThread)
        app._refresh_privilege_status()

    def restored_provider():
        pytest.fail("a delayed worker resolved a provider after launch patches ended")

    monkeypatch.setattr(module.privileges, "granted_commands_now", restored_provider)
    monkeypatch.setattr(module.privileges, "dhcp_interfaces", restored_provider)
    monkeypatch.setattr(module.privileges, "primary_interface", restored_provider)
    pending[0]()
    app._drain_privilege_results()
    assert app.privileges_probed is True
    assert app.dhcp_interfaces == ["synthetic0"]
    assert app.primary_dhcp_interface == "synthetic0"
