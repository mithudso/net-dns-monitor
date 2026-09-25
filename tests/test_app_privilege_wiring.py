"""The Grant and Revoke buttons, as wired into the rumps shell.

`privileges.grant`, `privileges.revoke` and the two probes are replaced in every
test. Nothing here runs `osascript`, raises an authentication dialog, or touches
`/etc/sudoers.d` -- see test_privileges.py for the module itself, and
privileges.py for how narrow the grant is and why.
"""

import threading

import pytest

from netdnsmonitor import privileges
from netdnsmonitor.app import NetDnsMonitorApp


@pytest.fixture(autouse=True)
def _no_real_window(monkeypatch):
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.show",
        lambda self, activate=True: None,
    )
    # `show` is stubbed so no window flashes across the screen, which leaves the real
    # `is_visible()` answering False -- and the refresh paths now skip a hidden window.
    # A double that stubs the shower must also stub the observable it sets, or every
    # assertion about painted content tests the guard instead of the content.
    monkeypatch.setattr(
        "netdnsmonitor.dashboard.DashboardWindow.is_visible",
        lambda self: True,
    )


@pytest.fixture(autouse=True)
def _no_real_privilege_calls(monkeypatch):
    """A test that reached the real functions would prompt for a password.

    `granted_commands_now` is the one the app asks -- a single `sudo -l` listing
    answers both "is it granted" and "which interfaces" -- so that is what gets
    stubbed. Default: nothing granted.
    """
    monkeypatch.setattr(privileges, "granted_commands_now", lambda *a, **k: [])
    monkeypatch.setattr(privileges, "is_granted", lambda *a, **k: False)
    # The executor's `covered_interfaces_fn` seam is wired to this in production;
    # unstubbed it is a real `sudo -l` from inside the DHCP-renewal test below.
    monkeypatch.setattr(privileges, "granted_interfaces", lambda *a, **k: [])
    monkeypatch.setattr(privileges, "dhcp_interfaces", lambda *a, **k: ["en0", "en9"])
    monkeypatch.setattr(privileges, "primary_interface", lambda *a, **k: "en9")
    monkeypatch.setattr(
        privileges,
        "grant",
        lambda *a, **k: pytest.fail("the real grant() must never run in a test"),
    )
    monkeypatch.setattr(
        privileges,
        "revoke",
        lambda *a, **k: pytest.fail("the real revoke() must never run in a test"),
    )


def grants(*specs):
    """A `sudo -l` listing, already parsed, in which `specs` are granted."""
    return list(specs)


MDNS = "/usr/bin/killall -HUP mDNSResponder"


def build_app(tmp_path, probed=True):
    """`probed=True` by default: Grant refuses to prompt until the launch probe has
    landed, and most tests here are about what happens after that point.
    """
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-config.yaml"))
    if probed:
        app.privileges_probed = True
        app.dhcp_interfaces = ["en0", "en9"]
    return app


def finish(app):
    """Let both workers finish, then fold their results in on this thread.

    Two handles, not one: the status probe and a grant/revoke used to share a
    thread slot, which made an early Grant click report "Still working on the
    previous permission change" when no permission change was in progress.
    """
    for thread in (app._privilege_status_thread, app._privilege_thread):
        if thread is not None:
            thread.join(timeout=5)
    app._drain_privilege_results()


# --- granting --------------------------------------------------------------


def test_the_explanation_is_printed_before_the_password_prompt(monkeypatch, tmp_path):
    """Afterwards is too late to decline. The order is the whole point: someone has
    to be able to read what the grant permits and then cancel the macOS dialog.
    """
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append

    seen = {}

    def fake_grant(user, interfaces, **kwargs):
        seen["explained_first"] = bool(output)
        return {"ok": True, "cancelled": False, "message": "Granted."}

    monkeypatch.setattr(privileges, "grant", fake_grant)
    app.dhcp_interfaces = ["en0"]
    app.handle_dashboard_action("grant_privileges")
    finish(app)

    assert seen["explained_first"] is True
    assert "/usr/bin/killall -HUP mDNSResponder" in "".join(output)
    assert "any process running as you" in "".join(output)


def test_the_prompt_does_not_run_on_the_run_loop(tmp_path, monkeypatch):
    """The authentication dialog waits for a human. On the run loop that would
    freeze the window and all six timers until someone typed a password.
    """
    monkeypatch.setattr(
        privileges, "grant", lambda *a, **k: {"ok": True, "cancelled": False, "message": "Granted."}
    )
    app = build_app(tmp_path)
    app.handle_dashboard_action("grant_privileges")
    assert app._privilege_thread is not None
    assert app._privilege_thread.daemon is True
    finish(app)


def test_clicking_grant_before_the_launch_probe_lands_is_refused_not_approximated(
    tmp_path, monkeypatch
):
    """The consent defect this pins, which the first fix introduced.

    `self.dhcp_interfaces` is empty until the launch probe drains, so this is the
    ordinary startup race: open the window, click Grant. v1 shelled out to
    `ifconfig -l` inline on the run loop (freezing the window for up to 5s). v2
    moved that to the worker, which was worse in a different way -- it printed
    `explanation([])`, listing only the mDNSResponder command, while the worker
    re-enumerated and installed the ipconfig rules as well. Someone would have
    authenticated for a grant strictly larger than the one they were shown, in the
    one place where disclosure-before-consent is the entire safety property.

    So it refuses and says why. No dialog is raised, and nothing is installed.
    """
    monkeypatch.setattr(
        privileges,
        "grant",
        lambda *a, **k: pytest.fail("must not prompt before the interface list is known"),
    )
    app = build_app(tmp_path, probed=False)
    output = []
    app._append_output = output.append
    assert app.dhcp_interfaces == []

    app.handle_dashboard_action("grant_privileges")

    text = "".join(output)
    assert "try again in a moment" in text
    # The consent text must not have been printed at all.
    assert "any process running as you" not in text
    assert app._privilege_thread is None
    finish(app)


def test_the_early_refusal_does_not_shell_out_on_the_run_loop(tmp_path, monkeypatch):
    """The other half of the same history: whatever it does instead of prompting, it
    must not be a subprocess on the AppKit main thread.
    """
    called_on = []
    monkeypatch.setattr(
        privileges,
        "dhcp_interfaces",
        lambda *a, **k: called_on.append(threading.current_thread().name) or ["en0"],
    )
    app = build_app(tmp_path, probed=False)
    app._append_output = lambda text: None

    app.handle_dashboard_action("grant_privileges")
    assert threading.current_thread().name not in called_on
    finish(app)


def test_the_grant_installs_exactly_the_list_that_was_shown(tmp_path, monkeypatch):
    """Not a re-enumerated one. Re-enumerating in the worker was how the installed
    grant could be larger than the printed one.
    """
    seen = {}

    def fake_grant(user, interfaces, **kwargs):
        seen["interfaces"] = list(interfaces)
        return {"ok": True, "cancelled": False, "message": "Granted."}

    monkeypatch.setattr(privileges, "grant", fake_grant)
    # Not banned outright: re-reading the machine's interfaces *after* the grant is
    # how the status row refreshes, and that is fine. What must not happen is the
    # installed list being derived from anything other than what was consented to.
    monkeypatch.setattr(privileges, "dhcp_interfaces", lambda *a, **k: ["en0", "en9", "en5"])
    app = build_app(tmp_path)
    app.dhcp_interfaces = ["en0"]
    shown = []
    app._append_output = shown.append

    app.handle_dashboard_action("grant_privileges")
    finish(app)

    assert seen["interfaces"] == ["en0"]
    assert "ipconfig set en0 DHCP" in "".join(shown)
    assert "en5" not in "".join(shown)


def test_a_successful_grant_updates_the_status_and_reports_it(tmp_path, monkeypatch):
    monkeypatch.setattr(
        privileges,
        "grant",
        lambda *a, **k: {"ok": True, "cancelled": False, "message": "Granted. en0 covered."},
    )
    # The re-probe after granting has to see the new state, not the old one.
    monkeypatch.setattr(privileges, "granted_commands_now", lambda *a, **k: grants(MDNS))
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("grant_privileges")
    finish(app)
    assert app.privileges_granted is True
    assert "Granted. en0 covered." in "".join(output)


def test_a_cancelled_grant_leaves_the_status_alone_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(
        privileges,
        "grant",
        lambda *a, **k: {
            "ok": False,
            "cancelled": True,
            "message": "Cancelled -- nothing was changed.",
        },
    )
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("grant_privileges")
    finish(app)
    assert app.privileges_granted is False
    assert "Cancelled" in "".join(output)


def test_the_status_is_re_probed_rather_than_assumed_from_the_return_value(tmp_path, monkeypatch):
    """A grant that claims success but did not take effect -- sudoers.d not
    included, say -- must not leave the window reporting a privilege the machine
    does not have.
    """
    monkeypatch.setattr(
        privileges, "grant", lambda *a, **k: {"ok": True, "cancelled": False, "message": "Granted."}
    )
    monkeypatch.setattr(privileges, "granted_commands_now", lambda *a, **k: [])
    app = build_app(tmp_path)
    app._append_output = lambda text: None
    app.handle_dashboard_action("grant_privileges")
    finish(app)
    assert app.privileges_granted is False


def test_a_grant_that_raises_is_reported_rather_than_killing_the_worker(tmp_path, monkeypatch):
    def exploding(*a, **k):
        raise RuntimeError("unforeseen")

    monkeypatch.setattr(privileges, "grant", exploding)
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("grant_privileges")
    finish(app)
    assert "raised" in "".join(output)


def test_a_second_click_while_one_is_in_flight_is_refused(tmp_path):
    """Two authentication dialogs at once, or a grant racing a revoke."""

    class FakeThread:
        daemon = True

        def is_alive(self):
            return True

    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app._privilege_thread = FakeThread()
    app.handle_dashboard_action("grant_privileges")
    app.handle_dashboard_action("revoke_privileges")
    assert isinstance(app._privilege_thread, FakeThread)
    assert "Still working on the previous permission change." in "".join(output)


# --- revoking --------------------------------------------------------------


def test_revoking_updates_the_status_and_says_what_stops_working(tmp_path, monkeypatch):
    monkeypatch.setattr(
        privileges,
        "revoke",
        lambda *a, **k: {"ok": True, "cancelled": False, "message": "Revoked. Back to partial."},
    )
    app = build_app(tmp_path)
    app.privileges_granted = True
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("revoke_privileges")
    finish(app)
    assert app.privileges_granted is False
    assert "Revoked" in "".join(output)


def test_revoking_does_not_print_the_grant_explanation(tmp_path, monkeypatch):
    """Nothing is being permitted, so there is nothing to warn about."""
    monkeypatch.setattr(
        privileges,
        "revoke",
        lambda *a, **k: {"ok": True, "cancelled": False, "message": "Revoked."},
    )
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("revoke_privileges")
    finish(app)
    assert "any process running as you" not in "".join(output)


# --- status in the window ---------------------------------------------------


def test_the_launch_probe_runs_off_the_run_loop_and_says_nothing(tmp_path):
    """Two subprocesses, so not inline -- and no announcement, because telling
    someone at every login that they have not granted a permission is nagging.
    """
    app = build_app(tmp_path, probed=False)
    output = []
    app._append_output = output.append
    app._refresh_privilege_status()
    assert app._privilege_status_thread is not None
    assert app._privilege_status_thread.daemon is True
    finish(app)
    assert app.dhcp_interfaces == ["en0", "en9"]
    assert app.primary_dhcp_interface == "en9"
    assert app.privileges_probed is True
    assert output == []


def test_the_window_shows_a_permissions_section(tmp_path):
    app = build_app(tmp_path)
    app._refresh_privilege_status()
    finish(app)
    app.open_dashboard()
    stats = str(app._dashboard.stats_view.string())
    assert "PERMISSIONS" in stats
    assert "not granted" in stats


def test_a_blanket_nopasswd_rule_is_granted_in_the_window_too(tmp_path, monkeypatch):
    """`privileges.is_granted` already counts `(ALL) NOPASSWD: ALL`, so the repairs
    run. The window derives its own answer from the same listing and must agree:
    "Elevated permissions: not granted" beside "Interfaces the grant covers: (all,
    via a blanket NOPASSWD rule)" tells someone the machine is in two states at once.
    """
    monkeypatch.setattr(privileges, "granted_commands_now", lambda *a, **k: ["ALL"])
    app = build_app(tmp_path)
    app._refresh_privilege_status()
    finish(app)
    assert app.privileges_granted is True
    app.open_dashboard()
    assert "not granted" not in str(app._dashboard.stats_view.string())


def test_the_permissions_section_names_what_is_still_impossible(tmp_path):
    """Both of these look identical to "the grant did not work" otherwise: the
    interface toggle is withheld by choice, and the masked DNS names in the log are
    not a permission at all.
    """
    app = build_app(tmp_path)
    app._refresh_privilege_status()
    finish(app)
    app.open_dashboard()
    stats = str(app._dashboard.stats_view.string())
    assert "by choice" in stats
    assert "logging profile" in stats


def test_neither_permission_button_falls_through_to_the_repair_ladder(tmp_path, monkeypatch):
    """An id handle_dashboard_action does not recognise reaches step_by_name and
    reports "Unknown step" -- a button that looks wired and does nothing useful.
    """
    monkeypatch.setattr(
        privileges, "grant", lambda *a, **k: {"ok": True, "cancelled": False, "message": "Granted."}
    )
    monkeypatch.setattr(
        privileges,
        "revoke",
        lambda *a, **k: {"ok": True, "cancelled": False, "message": "Revoked."},
    )
    app = build_app(tmp_path)
    output = []
    app._append_output = output.append
    app.handle_dashboard_action("grant_privileges")
    finish(app)
    app.handle_dashboard_action("revoke_privileges")
    finish(app)
    assert "Unknown step" not in "".join(output)


def test_the_repair_executor_is_given_the_real_privilege_probes(tmp_path, monkeypatch):
    """`make_repair_executor` defaults to "no privilege, no interface" so that the
    many tests injecting a fake `run_fn` stay deterministic and acquire no extra
    subprocesses. Production has to override that default, or the grant would be
    installed and then never consulted -- and nothing else in the suite would
    notice, because the ungranted behaviour is what every other test asserts.

    The probes are bound when the executor is built, so they are patched before
    `build_state_machine` runs. What that binding buys is a probe called per step
    rather than a boolean captured at launch: granting mid-session takes effect
    without a restart.
    """
    from netdnsmonitor.app import build_state_machine
    from netdnsmonitor.config import load_config
    from netdnsmonitor.ladder import LadderStep

    calls = []
    monkeypatch.setattr(privileges, "is_granted", lambda *a, **k: calls.append("probed") or True)
    monkeypatch.setattr(privileges, "primary_interface", lambda *a, **k: None)

    machine = build_state_machine(load_config(str(tmp_path / "no-config.yaml")))
    outcome = machine.repair_executor(
        LadderStep("renew_dhcp_lease", "repair", needs_privilege=True)
    )

    assert calls == ["probed"]
    # Granted, so it got as far as looking for an interface -- with the default
    # `lambda: False` it would have stopped at NEEDS_PRIVILEGE instead.
    assert "cannot renew" in outcome
    assert "NEEDS_PRIVILEGE" not in outcome
