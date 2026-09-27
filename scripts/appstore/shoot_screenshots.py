#!/usr/bin/env python3
"""Run the app from source as the store edition and render its windows to PNG.

Usage: .venv/bin/python scripts/appstore/shoot_screenshots.py OUT_DIR

A manual check, not a test: it launches the menu bar app (rumps, so it needs a
GUI session) and quits it when the last capture is on disk, usually within
half a minute. It forces NETDNS_DISTRIBUTION=appstore and isolates the run
under OUT_DIR: a config derived from config.example.yaml with every file the
app writes (reports, history, forensic journal and episodes, peer record,
learned domains, failover state, resolution log) moved under OUT_DIR/app-data,
Slack and e-mail alerts and peer discovery off, an empty credential store, a
consent file under OUT_DIR and the drawn AppIcon.icns. Nothing of the owner's Keychain, config or
data is read or written, and OUT_DIR may not be one of the app's own data
directories.

Each phase waits for the app's own readiness signal (the first ping heartbeat,
the diagnosis worker finishing, the dialog appearing) with a deadline, rather
than a fixed number of seconds, and a watchdog thread ends the process if the
whole run overruns. "Run full diagnosis" is clicked only while the network is
healthy: on an unhealthy one the ladder would run and the capture would show
an incident, not the store page's healthy state, so the run stops and says
so. Each window is rendered
in-process from its view hierarchy, which needs no screen-recording permission
and includes the title bar but not the shadow; compose_screenshots.py adds the
shadow and the background.

Writes 01-dashboard.png, 02-dashboard-diagnosis.png and 03-claude-permission.png
at the display's scale factor (2x on Retina). Exit status 1, with the missing
names on stderr, if any of the three is not there at the end.
"""

import os
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CAPTURES = ("01-dashboard.png", "02-dashboard-diagnosis.png", "03-claude-permission.png")
# The app's own data directories; a run must never write its config or icon there.
OWNER_DIRS = ("~/Library/Application Support/net-dns-monitor", "~/.config/net-dns-monitor")
# Alerts off outright, and no LAN announcement: peer discovery would open the
# UDP socket and broadcast from the first announce tick, and isolation must
# not rest on that tick happening to fall after the run ends.
ISOLATED_FLAGS = {
    "slack_enabled": False,
    "email_enabled": False,
    "peer_discovery_enabled": False,
}
TICK_SECONDS = 1
# Phase deadlines. The ping heartbeat is 5 s apart and gives up after ~3 s; a
# full ladder is four steps of up to 5 s each plus the probes around them.
WARMUP_DEADLINE = 15
DIAGNOSIS_DEADLINE = 90
DIALOG_DEADLINE = 10
# The whole run, enforced from a thread: the driver's NSTimer fires only in the
# default run-loop mode, so a modal session opened by any future code path
# would stop it silently, and an unattended script must not hang for good.
RUN_DEADLINE = 180
# The dashboard repaints from a 1 s UI tick that also drains the worker's
# result queue, so a capture waits two ticks after the state it wants exists:
# one for the queue, one for the repaint.
SETTLE_SECONDS = 2


def refuse_owner_dir(out: Path) -> None:
    for owner in OWNER_DIRS:
        root = Path(owner).expanduser().resolve()
        if out == root or root in out.parents:
            raise SystemExit(f"refusing to write a screenshot run under the app's own {root}")


def write_isolated_config(out: Path) -> Path:
    """config.example.yaml with every file the app writes moved under `out`.

    Copying the example verbatim is not isolation: it names the owner's real
    Application Support directory for reports and learned domains, and
    load_config fills every other path with the same defaults, so the first
    version of this script appended its ping samples to the owner's
    history.jsonl (2026-09-27). Alerts are switched off outright rather than
    relying on the example's empty recipients staying empty.
    """
    import yaml

    from netdnsmonitor.config import DEFAULT_CONFIG, PATH_KEYS

    config = yaml.safe_load((REPO / "config.example.yaml").read_text()) or {}
    data_dir = out / "app-data"
    # PATH_KEYS, not every key ending in _path: failover_speedtest_path is a
    # URL path, and config.py keeps the one list of keys that name files.
    for key in PATH_KEYS:
        default = config.get(key, DEFAULT_CONFIG[key])
        config[key] = str(data_dir / Path(str(default)).name)
    config.update(ISOLATED_FLAGS)
    path = out / "config.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=True))
    return path


def move_to_retina(window) -> None:
    """Put the window on a 2x screen when it is on a 1x one.

    A window renders at its screen's backing scale, and the app opens it on
    whichever screen is main. compose_screenshots.py frames a 1x and a 2x
    render alike, but the store shows the 2x one crisp, so the run prefers a
    Retina screen when one is attached. Called a tick before the capture: the
    backing scale changes when the move lands, not on the call.
    """
    import AppKit

    if window.backingScaleFactor() >= 2:
        return
    for screen in AppKit.NSScreen.screens():
        if screen.backingScaleFactor() >= 2:
            origin = screen.visibleFrame().origin
            window.setFrameOrigin_((origin.x + 40, origin.y + 40))
            return


def capture(window, path: Path) -> None:
    """Render a window's theme frame (title bar plus content, no shadow) to PNG."""
    from appkit_draw import write_png

    view = window.contentView().superview()
    bounds = view.bounds()
    rep = view.bitmapImageRepForCachingDisplayInRect_(bounds)
    if rep is None:
        raise RuntimeError(f"AppKit gave no bitmap for the window behind {path.name}")
    view.cacheDisplayInRect_toBitmapImageRep_(bounds, rep)
    write_png(rep, path)
    print(f"captured {path.name} {rep.pixelsWide()}x{rep.pixelsHigh()}", flush=True)


def present(window) -> None:
    """Bring the app forward and order the window on screen, non-modally."""
    import AppKit

    window.center()
    AppKit.NSApp.activateIgnoringOtherApps_(True)
    window.makeKeyAndOrderFront_(None)


def make_confirm(
    icon_path: Path, shown: dict, present: Callable[[object], None] = present
) -> Callable[[str, str, str, str], bool]:
    """The app's two-button NSAlert, shown non-modally so the timer can render it.

    The real prompt (credentials_prompt.confirm) runs the alert modally, which
    would stop the driver's timer; ordering the window front instead keeps the
    run loop turning. The bundled app's alerts carry the bundle icon; from
    source NSAlert would fall back to Python's, so the drawn icon is set.
    `present` is injectable so the test suite can build the alert without
    activating an application or ordering a window on a headless runner.
    """

    def confirm(title: str, message: str, ok_label: str, cancel_label: str) -> bool:
        import AppKit

        alert = AppKit.NSAlert.alloc().init()
        alert.setMessageText_(title)
        alert.setInformativeText_(message)
        alert.addButtonWithTitle_(ok_label)
        alert.addButtonWithTitle_(cancel_label)
        icon = AppKit.NSImage.alloc().initWithContentsOfFile_(str(icon_path))
        if icon is not None:
            alert.setIcon_(icon)
        # NSAlert.layout (macOS 10.9+) sizes the window before it is shown
        # without runModal; without it the frame is the pre-layout default.
        alert.layout()
        window = alert.window()
        present(window)
        shown["alert"] = (alert, window)
        return False  # "Don't Allow" with nothing granted changes nothing

    return confirm


def hard_exit(message: str) -> None:
    """Fail the run with exit status 1 from inside the AppKit run loop.

    `rumps.quit_application` goes through NSApp.terminate, which exits 0 and
    never returns, and a SystemExit raised in a timer callback is swallowed by
    the bridge; os._exit is the one exit that carries a status out of here.
    """
    print(f"shoot_screenshots: {message}", file=sys.stderr, flush=True)
    sys.stdout.flush()
    os._exit(1)


class Driver:
    """Advances one phase per timer tick when the app's readiness signal says so.

    `capture`, `place`, `quit`, `now` and `fail` are injectable so the phase
    logic runs in the offline test suite against a fake app and a fake clock.
    """

    def __init__(
        self,
        app,
        out: Path,
        shown: dict,
        capture: Callable[[object, Path], None] = capture,
        place: Callable[[object], None] = move_to_retina,
        quit: Callable[[], None] | None = None,
        now: Callable[[], float] = time.monotonic,
        fail: Callable[[str], None] = hard_exit,
    ):
        self.app, self.out, self.shown = app, out, shown
        self.capture, self.place, self.now, self.fail = capture, place, now, fail
        self._quit = quit
        self.phase = "warm-up"
        self.phase_started = now()
        self.timer = None  # set by main(); a fake in tests

    def quit(self) -> None:
        if self._quit is not None:
            self._quit()
            return
        import rumps

        rumps.quit_application()

    def enter(self, phase: str) -> None:
        self.phase = phase
        self.phase_started = self.now()

    def since_phase(self) -> float:
        return self.now() - self.phase_started

    def tick(self, _timer=None) -> None:
        try:
            self.advance()
        except Exception:  # noqa: BLE001 - report, then always leave the GUI app
            traceback.print_exc()
            if self.timer is not None:
                self.timer.stop()
            self.fail(f"phase {self.phase!r} raised")

    def advance(self) -> None:
        app, out = self.app, self.out
        if self.phase == "warm-up":
            # The dashboard's NETWORK RIGHT NOW block is empty until the first
            # ping heartbeat has landed.
            if app.ping_stats.get("rtt_ms") is not None or self.since_phase() > WARMUP_DEADLINE:
                app.open_dashboard()
                self.place(app._dashboard.window)
                self.enter("dashboard")
        elif self.phase == "dashboard":
            if self.since_phase() >= SETTLE_SECONDS:
                self.capture(app._dashboard.window, out / CAPTURES[0])
                # On a healthy network the diagnosis has no ladder to run and
                # the capture shows that. On an unhealthy one the ladder runs
                # (its repairs answer "unavailable" in the store edition) and
                # the capture shows an incident, which is not the screenshot.
                if app.ping_stats.get("down") or app.state_machine.flap_gate.state == "incident":
                    raise RuntimeError(
                        "the network is not healthy, so the diagnosis capture would show "
                        "an incident; retry when the connection is up"
                    )
                app.handle_dashboard_action("full_diagnosis")
                self.enter("diagnosis")
        elif self.phase == "diagnosis":
            # The action runs on a worker thread; its result reaches the pane
            # through the UI tick, so the wait is on the thread, not on time.
            worker = app._action_thread
            if worker is None or not worker.is_alive():
                self.enter("settle")
            elif self.since_phase() > DIAGNOSIS_DEADLINE:
                raise TimeoutError(f"full diagnosis still running after {DIAGNOSIS_DEADLINE} s")
        elif self.phase == "settle":
            if self.since_phase() >= SETTLE_SECONDS:
                self.capture(app._dashboard.window, out / CAPTURES[1])
                app.allow_claude_diagnosis()
                self.enter("dialog")
        elif self.phase == "dialog":
            if "alert" in self.shown and self.since_phase() >= SETTLE_SECONDS:
                _alert, window = self.shown["alert"]
                self.capture(window, out / CAPTURES[2])
                window.orderOut_(None)
                self.enter("finish")
            elif "alert" in self.shown and not self.shown.get("placed"):
                # One tick after the dialog appears: moved now, rendered next tick.
                self.place(self.shown["alert"][1])
                self.shown["placed"] = True
            elif self.since_phase() > DIALOG_DEADLINE:
                raise TimeoutError(f"the consent dialog did not appear within {DIALOG_DEADLINE} s")
        elif self.phase == "finish":
            if self.timer is not None:
                self.timer.stop()
            missing = [name for name in CAPTURES if not (out / name).exists()]
            if missing:
                self.fail(f"missing captures: {', '.join(missing)}")
                return
            print("done", flush=True)
            self.quit()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    out = Path(argv[1]).resolve()
    refuse_owner_dir(out)
    out.mkdir(parents=True, exist_ok=True)
    os.environ["NETDNS_DISTRIBUTION"] = "appstore"
    sys.path.insert(0, str(REPO))
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from netdnsmonitor import ai_consent, credentials
    from netdnsmonitor import app as appmod

    config_path = write_isolated_config(out)
    icon_path = out / "AppIcon.icns"
    subprocess.run(
        [sys.executable, str(REPO / "scripts" / "appstore" / "make_icon.py"), str(icon_path)],
        check=True,
    )
    shown: dict = {}

    def factory(config_path: str):
        import rumps

        app = appmod.NetDnsMonitorApp(
            config_path=config_path,
            credential_store=credentials.CredentialStore(env={}, backend_factory=None),
            consent_store=ai_consent.ConsentStore(path=str(out / "ai-consent.json")),
            choice_prompt=make_confirm(icon_path, shown),
        )
        driver = Driver(app, out, shown)
        driver.timer = rumps.Timer(driver.tick, TICK_SECONDS)
        driver.timer.start()
        # rumps keeps a started timer, and so the driver its callback is bound
        # to, in its own registry; this attribute is for finding the driver
        # from the app while debugging, not for keeping it alive.
        app._screenshot_driver = driver
        return app

    watchdog = threading.Timer(
        RUN_DEADLINE, hard_exit, args=(f"still running after {RUN_DEADLINE} s",)
    )
    watchdog.daemon = True
    watchdog.start()
    appmod.main(app_factory=factory, config_path=str(config_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
