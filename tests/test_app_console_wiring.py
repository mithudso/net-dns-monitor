"""The console, as wired into the rumps shell and the dashboard.

`ConsoleWindowController.show` is monkeypatched throughout for the reason
test_app_dashboard_wiring records about the dashboard's own `show`: it calls
`activateIgnoringOtherApps_`, which would steal focus and flash a window across
the screen on every test run. Everything up to and including the call is still
exercised.

What these pin is the wiring, not the console itself -- which line does what,
what the limits are and how a result is rendered all live in console.py and are
covered by test_console.py without a window anywhere near them.
"""

import pytest

from netdnsmonitor.app import NetDnsMonitorApp


class FakeFlapGate:
    def __init__(self, state="healthy", consecutive_failures=0):
        self.state = state
        self.consecutive_failures = consecutive_failures


class FakeStateMachine:
    def __init__(self, flap_state="healthy", consecutive_failures=0):
        self.flap_gate = FakeFlapGate(flap_state, consecutive_failures)

    def tick(self):
        return None


@pytest.fixture(autouse=True)
def _no_real_window(monkeypatch):
    monkeypatch.setattr(
        "netdnsmonitor.console_window.ConsoleWindowController.show",
        lambda self: None,
    )


def make_app(tmp_path, flap_state="healthy", consecutive_failures=0):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.state_machine = FakeStateMachine(flap_state, consecutive_failures)
    return app


# --- reachability ------------------------------------------------------------


def test_constructing_the_app_creates_no_console(tmp_path):
    """Lazy for the same reason the dashboard is: a window per constructed app
    would pop one in every other suite that builds this class.
    """
    app = make_app(tmp_path)
    assert app.console is None


def test_the_menu_offers_the_console(tmp_path):
    app = make_app(tmp_path)
    assert "Open console" in list(app.menu.keys())


def test_the_dashboard_offers_the_console():
    """The button has to exist in the grid, not just be handled if clicked."""
    from netdnsmonitor.dashboard import ALL_ACTIONS

    assert "open_console" in {action_id for _, action_id, _ in ALL_ACTIONS}


def test_opening_the_console_builds_it(tmp_path):
    app = make_app(tmp_path)
    app.open_console()
    assert app.console is not None


# --- the invariant that makes it one console ---------------------------------


def test_opening_twice_reuses_the_one_controller(tmp_path):
    """A controller rebuilt per open would drop the window it owns, and would
    also reset the working directory and history the person was mid-way through.
    """
    app = make_app(tmp_path)
    app.open_console()
    first = app.console
    app.open_console()
    assert app.console is first


def test_the_dashboard_button_and_the_menu_share_one_console(tmp_path):
    """The failure this pins is silent: two controllers both work, and the cwd
    and history you built up in one are simply invisible in the other.
    """
    app = make_app(tmp_path)
    app.open_console()
    from_menu = app.console

    app.handle_dashboard_action("open_console")

    assert app.console is from_menu


def test_console_state_survives_reaching_it_from_the_other_surface(tmp_path):
    """The observable form of the test above: `cd` from one surface, and the
    other surface is still in that directory.
    """
    app = make_app(tmp_path)
    app.open_console()
    app.console.state.cwd = "/tmp"

    app.handle_dashboard_action("open_console")

    assert app.console.state.cwd == "/tmp"


def test_the_dashboard_button_does_not_fall_through_to_a_ladder_step(tmp_path, monkeypatch):
    """An id `handle_dashboard_action` does not answer explicitly reaches
    step_by_name and reports "Unknown step" into the results pane -- the bug
    dashboard.py already documents twice.

    Asserted against the fall-through path's own side effects rather than
    against `app.console`, which would still be set by a handler that opened the
    console *and then* went on to queue a bogus ladder step.
    """
    app = make_app(tmp_path)
    appended = []
    monkeypatch.setattr(app, "_append_output", lambda text: appended.append(text))

    app.handle_dashboard_action("open_console")

    assert app.console is not None
    assert appended == []


# --- what :status shows ------------------------------------------------------


def test_status_snapshot_reports_the_live_gate_state(tmp_path):
    app = make_app(tmp_path, flap_state="incident")
    app.last_classification = "dns"

    report = app.status_snapshot()

    assert "incident" in report
    assert "dns" in report


def test_status_snapshot_follows_the_gate_back_to_healthy(tmp_path):
    """Recovery produces no report at all (see state_machine.py), so a `:status`
    driven off the last report would still be claiming an incident here.
    """
    app = make_app(tmp_path)
    app.last_report_path = "/somewhere/report.md"

    report = app.status_snapshot()

    # Read off the state line rather than matching its padding: the columns are
    # cosmetic, and a test that pins them fails on a re-alignment that changed
    # nothing about what the console reports.
    assert report.splitlines()[0].split(":", 1)[1].strip() == "healthy"


def test_status_snapshot_works_before_the_first_ping(tmp_path):
    """The first seconds after launch, when no tick has run and `ping_stats` is
    still NO_PING_YET -- every reading None.

    This is not a corner case: a login-time launch plus an outage means the
    first `:status` anyone types lands here. `console.handle` catches whatever
    this raises and prints "failed to read monitor state", so a KeyError or a
    None-format here would not crash anything -- it would just replace the
    monitor state with an error string at the exact moment it is wanted.
    """
    app = make_app(tmp_path)

    report = app.status_snapshot()

    assert "state:" in report
    assert "healthy" in report


def test_status_snapshot_is_what_the_console_asks_for(tmp_path):
    """The controller has to be handed the bound method, or `:status` answers
    "monitor state is not available from here."
    """
    app = make_app(tmp_path)
    app.open_console()
    assert app.console.status is not None
    assert "state:" in app.console.status()
