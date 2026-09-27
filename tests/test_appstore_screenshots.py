"""The App Store screenshot helpers: the compositor's framing and output format,
and the driver's phase logic against a fake app and a fake clock.

Both scripts live under scripts/appstore (not a package), so they are loaded by
path like build_appstore.py is. No test starts the app or a run loop; the
driver's readiness checks are exercised with fakes injected as callables.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest
import yaml

from netdnsmonitor.config import DEFAULT_CONFIG, PATH_KEYS, load_config

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts" / "appstore"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


compose = _load("compose_screenshots")
shoot = _load("shoot_screenshots")
draw = _load("appkit_draw")


# --- compose_screenshots ------------------------------------------------------


def _solid_png(path: Path, width: int, height: int) -> Path:
    """A fully red PNG, `width` x `height` pixels, with no resolution metadata
    (one point per pixel, the 1x case)."""
    import AppKit

    rep = draw.new_canvas(width, height)
    with draw.drawing(rep):
        AppKit.NSColor.redColor().setFill()
        AppKit.NSBezierPath.fillRect_(AppKit.NSMakeRect(0, 0, width, height))
    draw.write_png(rep, path)
    return path


def _red_at(path: Path, x: int, y: int) -> float:
    import AppKit

    rep = AppKit.NSBitmapImageRep.imageRepWithContentsOfFile_(str(path))
    colour = rep.colorAtX_y_(x, y).colorUsingColorSpace_(AppKit.NSColorSpace.sRGBColorSpace())
    return colour.redComponent()


def test_fit_draws_a_window_at_its_retina_size_centred():
    x, y, width, height = compose.fit(100, 50)
    assert (width, height) == (200, 100)
    assert (x, y) == ((2880 - 200) / 2, (1800 - 100) / 2)


def test_fit_scales_down_to_the_margin_but_never_up():
    x, _y, width, _height = compose.fit(2000, 50)
    assert x == compose.MARGIN
    assert width == 2880 - 2 * compose.MARGIN
    _x, _y, width, height = compose.fit(10, 10)
    assert (width, height) == (20, 20)


def test_fit_refuses_an_empty_image_as_a_value_error_main_can_skip():
    """A zero dimension must fail as the ValueError main() catches per file,
    not as a ZeroDivisionError that aborts the whole batch."""
    with pytest.raises(ValueError, match="empty image"):
        compose.fit(0, 50)
    with pytest.raises(ValueError, match="empty image"):
        compose.fit(50, 0)


def test_output_is_exactly_2880x1800_with_no_alpha(tmp_path):
    import AppKit

    src = _solid_png(tmp_path / "shot.png", 200, 100)
    dst = tmp_path / "out" / "shot.png"
    dst.parent.mkdir()
    compose.compose(src, dst)
    out = AppKit.NSBitmapImageRep.imageRepWithContentsOfFile_(str(dst))
    assert (out.pixelsWide(), out.pixelsHigh()) == (2880, 1800)
    assert out.hasAlpha() is False


def test_a_1x_capture_is_framed_by_points_so_it_matches_a_retina_one(tmp_path):
    """200x100 px with no resolution metadata is 200x100 pt, drawn 400x200 px
    centred: red at the centre, background just outside the drawn box."""
    src = _solid_png(tmp_path / "shot.png", 200, 100)
    dst = tmp_path / "shot-out.png"
    compose.compose(src, dst)
    assert _red_at(dst, 1440, 900) > 0.9
    assert _red_at(dst, 1440 - 200 - 20, 900) < 0.3


def test_an_oversized_capture_stops_at_the_margin(tmp_path):
    src = _solid_png(tmp_path / "wide.png", 2000, 50)
    dst = tmp_path / "wide-out.png"
    compose.compose(src, dst)
    assert _red_at(dst, compose.MARGIN - 4, 900) < 0.3
    assert _red_at(dst, compose.MARGIN + 4, 900) > 0.9
    assert _red_at(dst, 2880 - compose.MARGIN - 4, 900) > 0.9


def test_a_file_that_is_not_an_image_is_refused_by_name(tmp_path):
    bad = tmp_path / "bad.png"
    bad.write_bytes(b"not a png")
    with pytest.raises(ValueError, match="bad.png"):
        compose.compose(bad, tmp_path / "out.png")


def test_main_composes_the_rest_and_exits_1_when_one_source_fails(tmp_path, capsys):
    src_dir, out_dir = tmp_path / "in", tmp_path / "out"
    src_dir.mkdir()
    _solid_png(src_dir / "good.png", 20, 20)
    (src_dir / "bad.png").write_bytes(b"not a png")
    assert compose.main(["compose", str(src_dir), str(out_dir)]) == 1
    assert (out_dir / "good.png").exists()
    assert not (out_dir / "bad.png").exists()
    err = capsys.readouterr().err
    assert "bad.png: skipped" in err and "failed: bad.png" in err


def test_main_refuses_an_empty_input_directory(tmp_path, capsys):
    (tmp_path / "in").mkdir()
    assert compose.main(["compose", str(tmp_path / "in"), str(tmp_path / "out")]) == 1
    assert "no PNG files" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


# --- shoot_screenshots: isolation ----------------------------------------------


def test_the_isolated_config_moves_every_file_the_app_writes_under_out(tmp_path):
    path = shoot.write_isolated_config(tmp_path)
    config = yaml.safe_load(path.read_text())
    assert PATH_KEYS, "config.py names no path-valued key at all"
    for key in PATH_KEYS:
        assert config[key].startswith(str(tmp_path / "app-data")), f"{key}: {config[key]}"
    assert config["slack_enabled"] is False
    assert config["email_enabled"] is False
    assert config["peer_discovery_enabled"] is False
    # And the app can still load it: the rewrite must not break validation.
    loaded = load_config(str(path))
    assert loaded["history_path"].startswith(str(tmp_path / "app-data"))
    # A URL path, not a file: it must come through as the app's default.
    assert loaded["failover_speedtest_path"] == DEFAULT_CONFIG["failover_speedtest_path"]


def test_the_isolated_config_covers_the_defaults_the_example_leaves_out(tmp_path):
    """config.example.yaml names only reports_dir and learned_domains_path;
    history_path and the forensic paths come from DEFAULT_CONFIG and must be
    redirected too, or a run appends to the owner's history.jsonl."""
    config = yaml.safe_load(shoot.write_isolated_config(tmp_path).read_text())
    for key in ("history_path", "forensic_log_path", "forensic_episodes_dir", "peer_record_path"):
        assert config[key].startswith(str(tmp_path / "app-data")), key


def test_a_run_refuses_the_apps_own_data_directories(tmp_path):
    shoot.refuse_owner_dir(tmp_path)
    for owner in shoot.OWNER_DIRS:
        root = Path(owner).expanduser().resolve()
        with pytest.raises(SystemExit, match="refusing"):
            shoot.refuse_owner_dir(root)
        with pytest.raises(SystemExit, match="refusing"):
            shoot.refuse_owner_dir(root / "shots")


# --- shoot_screenshots: the driver --------------------------------------------


class FakeThread:
    def __init__(self):
        self.alive = True

    def is_alive(self):
        return self.alive


class FakeWindow:
    def __init__(self):
        self.ordered_out = 0

    def orderOut_(self, _sender):
        self.ordered_out += 1


class FakeApp:
    def __init__(self, shown):
        self.shown = shown
        self.ping_stats = {"rtt_ms": None, "down": False}
        self.state_machine = types.SimpleNamespace(flap_gate=types.SimpleNamespace(state="healthy"))
        self._dashboard = types.SimpleNamespace(window="dashboard-window")
        self._action_thread = None
        self.calls = []

    def open_dashboard(self):
        self.calls.append("open_dashboard")

    def handle_dashboard_action(self, action_id):
        self.calls.append(("action", action_id))
        self._action_thread = FakeThread()

    def allow_claude_diagnosis(self):
        self.calls.append("allow_claude_diagnosis")
        self.shown["alert"] = (None, FakeWindow())


class FakeTimer:
    def __init__(self):
        self.stopped = 0

    def stop(self):
        self.stopped += 1


class Harness:
    def __init__(self, out: Path, writes_files: bool = True):
        self.shown = {}
        self.app = FakeApp(self.shown)
        self.t = 0.0
        self.captured, self.quits, self.failures = [], [], []
        self.writes_files = writes_files
        self.placed = []
        self.driver = shoot.Driver(
            self.app,
            out,
            self.shown,
            capture=self._capture,
            place=self.placed.append,
            quit=lambda: self.quits.append(True),
            now=lambda: self.t,
            fail=self.failures.append,
        )
        self.driver.timer = FakeTimer()

    def _capture(self, window, path: Path):
        self.captured.append((window, path.name))
        if self.writes_files:
            path.write_bytes(b"png")

    def tick(self, at: float | None = None):
        if at is not None:
            self.t = at
        self.driver.tick()


def test_the_driver_advances_on_the_apps_signals_not_on_a_count(tmp_path):
    h = Harness(tmp_path)
    h.tick(0)
    assert h.app.calls == [] and h.driver.phase == "warm-up"
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(1)
    assert h.app.calls == ["open_dashboard"] and h.driver.phase == "dashboard"
    assert h.placed == ["dashboard-window"], "moved to a Retina screen before the capture"
    h.tick(1 + shoot.SETTLE_SECONDS)
    assert h.captured == [("dashboard-window", "01-dashboard.png")]
    assert h.app.calls[-1] == ("action", "full_diagnosis") and h.driver.phase == "diagnosis"
    h.tick(20)
    assert h.driver.phase == "diagnosis", "a live worker holds the phase"
    h.app._action_thread.alive = False
    h.tick(21)
    assert h.driver.phase == "settle"
    h.tick(21 + shoot.SETTLE_SECONDS)
    assert h.captured[-1] == ("dashboard-window", "02-dashboard-diagnosis.png")
    assert h.app.calls[-1] == "allow_claude_diagnosis" and h.driver.phase == "dialog"
    _alert, window = h.shown["alert"]
    h.tick(21 + shoot.SETTLE_SECONDS + shoot.TICK_SECONDS)
    assert h.placed == ["dashboard-window", window], "the dialog is moved a tick before capture"
    assert len(h.captured) == 2, "not captured on the tick it was moved"
    h.tick(21 + 2 * shoot.SETTLE_SECONDS)
    assert h.captured[-1] == (window, "03-claude-permission.png")
    assert window.ordered_out == 1 and h.driver.phase == "finish"
    h.tick(30)
    assert h.quits == [True] and h.failures == [] and h.driver.timer.stopped == 1
    assert [name for _, name in h.captured] == list(shoot.CAPTURES)


def test_the_driver_opens_the_dashboard_anyway_once_the_warm_up_deadline_passes(tmp_path):
    h = Harness(tmp_path)
    h.tick(shoot.WARMUP_DEADLINE + 1)
    assert h.app.calls == ["open_dashboard"]


def test_an_unhealthy_network_stops_the_run_before_the_diagnosis(tmp_path):
    """A diagnosis on an unhealthy network runs the ladder and captures an
    incident, not the healthy state the store page shows; the run stops."""
    h = Harness(tmp_path)
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(0)
    h.app.ping_stats["down"] = True
    h.tick(shoot.SETTLE_SECONDS)
    assert ("action", "full_diagnosis") not in h.app.calls
    assert h.failures == ["phase 'dashboard' raised"] and h.driver.timer.stopped == 1
    assert h.quits == []


def test_an_open_incident_stops_the_run_too_even_with_the_ping_up(tmp_path):
    """The gate's second half: the app's own flap gate can hold an incident
    open after the ping recovers, and the ladder would run for it."""
    h = Harness(tmp_path)
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(0)
    h.app.state_machine.flap_gate.state = "incident"
    h.tick(shoot.SETTLE_SECONDS)
    assert ("action", "full_diagnosis") not in h.app.calls
    assert h.failures == ["phase 'dashboard' raised"]


def test_a_diagnosis_that_never_finishes_fails_at_its_deadline(tmp_path):
    h = Harness(tmp_path)
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(0)
    h.tick(shoot.SETTLE_SECONDS)
    assert h.driver.phase == "diagnosis"
    h.tick(shoot.SETTLE_SECONDS + shoot.DIAGNOSIS_DEADLINE + 1)
    assert h.failures == ["phase 'diagnosis' raised"]


def test_a_dialog_that_never_appears_fails_at_its_deadline(tmp_path):
    h = Harness(tmp_path)
    h.app.allow_claude_diagnosis = lambda: None  # the prompt is never shown
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(0)
    h.tick(shoot.SETTLE_SECONDS)
    h.app._action_thread.alive = False
    h.tick(3)
    h.tick(3 + shoot.SETTLE_SECONDS)
    assert h.driver.phase == "dialog"
    h.tick(3 + shoot.SETTLE_SECONDS + shoot.DIALOG_DEADLINE + 1)
    assert h.failures == ["phase 'dialog' raised"]


def test_a_run_whose_captures_are_not_on_disk_fails_instead_of_reporting_done(tmp_path):
    h = Harness(tmp_path, writes_files=False)
    h.app.ping_stats["rtt_ms"] = 12.0
    h.tick(0)
    h.tick(shoot.SETTLE_SECONDS)
    h.app._action_thread.alive = False
    h.tick(3)
    h.tick(3 + shoot.SETTLE_SECONDS)
    h.tick(3 + shoot.SETTLE_SECONDS + shoot.TICK_SECONDS)
    h.tick(3 + 2 * shoot.SETTLE_SECONDS)
    h.tick(10)
    assert h.quits == []
    assert h.failures == ["missing captures: " + ", ".join(shoot.CAPTURES)]


def test_make_confirm_shows_the_apps_question_and_answers_no(tmp_path):
    """Built for real, presented through a fake: activating an application
    and ordering a window front is what a headless CI runner cannot do."""
    shown, presented = {}, []
    confirm = shoot.make_confirm(tmp_path / "missing.icns", shown, present=presented.append)
    assert confirm("Allow Claude diagnosis?", "What is sent.", "Allow", "Don't Allow") is False
    alert, window = shown["alert"]
    assert presented == [window]
    assert alert.messageText() == "Allow Claude diagnosis?"
    assert alert.informativeText() == "What is sent."
    assert [button.title() for button in alert.buttons()] == ["Allow", "Don't Allow"]
