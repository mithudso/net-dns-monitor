"""Wiring tests for network failover: config -> executor -> ladder -> report,
and the failback call on the tick path. No rumps event loop is started.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

from netdnsmonitor.app import (
    NetDnsMonitorApp,
    build_failover,
    build_state_machine,
    failover_status_text,
)
from netdnsmonitor.classifier import Classification
from netdnsmonitor.config import DEFAULT_CONFIG
from netdnsmonitor.ladder import ladder_for
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report import build_report


def config(**overrides):
    cfg = dict(DEFAULT_CONFIG)
    cfg.update(overrides)
    return cfg


def enabled_config(**overrides):
    return config(
        failover_enabled=True,
        failover_preferred_service="AX88179B",
        failover_backup_service="Wi-Fi",
        **overrides,
    )


# --- build_failover ---------------------------------------------------------


def test_failover_is_off_by_default():
    assert build_failover(config()) is None


def test_failover_needs_both_service_names():
    assert build_failover(config(failover_enabled=True)) is None
    assert (
        build_failover(config(failover_enabled=True, failover_preferred_service="AX88179B")) is None
    )
    assert build_failover(config(failover_enabled=True, failover_backup_service="Wi-Fi")) is None


def test_identical_preferred_and_backup_is_refused():
    """Promoting a service above itself is not a failover."""
    assert (
        build_failover(
            config(
                failover_enabled=True,
                failover_preferred_service="Wi-Fi",
                failover_backup_service="Wi-Fi",
            )
        )
        is None
    )


def test_configured_failover_is_built_with_its_settings():
    failover = build_failover(
        enabled_config(
            failover_failback_threshold=5,
            failover_cooldown_seconds=60,
            failover_max_switches_per_hour=2,
        )
    )
    assert failover is not None
    assert failover.preferred_service == "AX88179B"
    assert failover.backup_service == "Wi-Fi"
    assert failover.failback_threshold == 5
    assert failover.cooldown_seconds == 60.0
    assert failover.max_switches_per_hour == 2
    assert failover.trigger_classifications == frozenset({"network"})


def test_dns_can_be_opted_into_via_config():
    failover = build_failover(enabled_config(failover_trigger_classifications=["network", "dns"]))
    assert failover.trigger_classifications == frozenset({"network", "dns"})


def test_an_explicitly_empty_trigger_list_is_honoured_not_re_armed():
    """Staging the feature inert while checking service names must not still
    rewrite the service order on the next incident.
    """
    cfg = enabled_config(failover_trigger_classifications=[])
    assert build_failover(cfg).trigger_classifications == frozenset()
    sm = build_state_machine(cfg)
    assert sm.failover_classifications == frozenset()
    assert ladder_for(Classification.NETWORK, sm.failover_classifications) == [
        s for s in ladder_for(Classification.NETWORK, frozenset())
    ]
    assert "switch_to_backup_network" not in [
        s.name for s in ladder_for(Classification.NETWORK, sm.failover_classifications)
    ]


def test_a_missing_trigger_key_still_defaults_to_network():
    cfg = enabled_config()
    del cfg["failover_trigger_classifications"]
    assert build_failover(cfg).trigger_classifications == frozenset({"network"})


# --- ladder -----------------------------------------------------------------


def test_network_ladder_includes_the_switch_step_last():
    names = [s.name for s in ladder_for(Classification.NETWORK)]
    assert names[-1] == "switch_to_backup_network"
    # Every cheaper repair is tried before the system config is rewritten.
    assert names.index("renew_dhcp_lease") < names.index("switch_to_backup_network")


def test_dns_ladder_excludes_the_switch_step_by_default():
    names = [s.name for s in ladder_for(Classification.DNS)]
    assert "switch_to_backup_network" not in names


def test_dns_ladder_includes_the_switch_step_when_opted_in():
    names = [s.name for s in ladder_for(Classification.DNS, frozenset({"network", "dns"}))]
    assert names[-1] == "switch_to_backup_network"
    assert names.index("flush_dns_cache") < names.index("switch_to_backup_network")


def test_healthy_never_gets_a_switch_step():
    assert ladder_for(Classification.HEALTHY, frozenset({"network", "dns", "healthy"})) == []


# --- repair executor dispatch ----------------------------------------------


def switch_step():
    return next(
        s for s in ladder_for(Classification.NETWORK) if s.name == "switch_to_backup_network"
    )


def test_unconfigured_failover_reports_disabled_not_success():
    executor = make_repair_executor(
        run_fn=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr="")
    )
    outcome = executor(switch_step(), "network")
    assert outcome.startswith("disabled:")


def test_configured_failover_receives_the_classification():
    seen = []
    executor = make_repair_executor(
        run_fn=lambda *a, **k: SimpleNamespace(returncode=0, stdout="", stderr=""),
        failover_fn=lambda classification: seen.append(classification) or "ok: switched",
    )
    assert executor(switch_step(), "network") == "ok: switched"
    assert seen == ["network"]


def test_existing_steps_still_work_without_a_classification():
    """The added parameter must not break the one-argument call."""
    executor = make_repair_executor(
        run_fn=lambda *a, **k: SimpleNamespace(returncode=0, stdout="out", stderr="")
    )
    step = next(s for s in ladder_for(Classification.NETWORK) if s.name == "check_interface_state")
    assert executor(step) == "out"


# --- state machine end to end ----------------------------------------------


class FailingProber:
    def __call__(self):
        return {"external_reachable": False, "dns_ok": False, "domain_results": {}}


def test_switch_outcome_reaches_the_incident_report():
    sm = build_state_machine(enabled_config())
    sm.prober = FailingProber()
    sm.escalator = lambda bundle: None
    sm.repair_executor = lambda step, classification=None: (
        "ok: switched" if step.name == "switch_to_backup_network" else "done"
    )
    assert sm.tick() is None  # first failure, below threshold
    report = sm.tick()
    assert report is not None
    steps = {r["name"]: r["outcome"] for r in report["ladder_results"]}
    assert steps["switch_to_backup_network"] == "ok: switched"
    assert "switch_to_backup_network: ok: switched" in report["repair_outcome"]


def test_no_switch_step_in_the_ladder_when_failover_is_disabled():
    sm = build_state_machine(config())
    sm.prober = FailingProber()
    sm.escalator = lambda bundle: None
    sm.repair_executor = lambda step, classification=None: "done"
    sm.tick()
    report = sm.tick()
    names = [r["name"] for r in report["ladder_results"]]
    assert "switch_to_backup_network" not in names


# --- tick path --------------------------------------------------------------


class RecordingFailover:
    def __init__(self, raises=False):
        self.calls = 0
        self.raises = raises
        self.last_event = None
        self.preferred_service = "AX88179B"
        self.backup_service = "Wi-Fi"

    def attempt_failback(self):
        self.calls += 1
        if self.raises:
            raise RuntimeError("networksetup exploded")
        return None


class QuietStateMachine:
    """A report-less tick -- what every healthy poll returns."""

    def __init__(self, report=None):
        self.flap_gate = SimpleNamespace(state="healthy", consecutive_failures=0)
        self._report = report

    def tick(self):
        return self._report


def make_app(tmp_path, failover, state_machine):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.config["reports_dir"] = str(tmp_path / "reports")
    app.failover = failover
    app.state_machine = state_machine
    app.notifier = lambda text: []
    return app


def test_failback_runs_on_a_report_less_tick(tmp_path):
    failover = RecordingFailover()
    app = make_app(tmp_path, failover, QuietStateMachine())
    app.tick()
    assert failover.calls == 1


def test_failback_is_skipped_on_a_tick_that_produced_a_report(tmp_path):
    """A failover and a failback must never interleave inside one tick."""
    now = datetime.now(timezone.utc)
    report = build_report(
        started_at=now,
        ended_at=now,
        classification=Classification.NETWORK,
        probe_results={},
        log_excerpts=[],
        ladder_results=[],
        repair_outcome=None,
        recheck_ok=False,
        escalation=None,
    )
    failover = RecordingFailover()
    app = make_app(tmp_path, failover, QuietStateMachine(report))
    app.tick()
    assert failover.calls == 0


def test_no_failover_configured_is_a_quiet_no_op(tmp_path):
    app = make_app(tmp_path, None, QuietStateMachine())
    app.tick()
    assert app.last_tick_error is None
    assert "healthy" in app.title.lower()


def test_a_raising_failback_cannot_kill_the_timer(tmp_path):
    """Nothing may escape into the rumps timer callback."""
    failover = RecordingFailover(raises=True)
    app = make_app(tmp_path, failover, QuietStateMachine())
    app.tick()  # must not raise
    assert app.last_tick_error is not None
    assert "RuntimeError" in app.last_tick_error
    assert app.title


# --- manual-only mode -------------------------------------------------------


def test_service_names_alone_give_a_manual_only_failover():
    """auto off + both names set is a real mode: the button works, nothing
    moves on its own. It is how you try this before trusting it unattended.
    """
    failover = build_failover(
        config(
            failover_enabled=False,
            failover_preferred_service="AX88179B",
            failover_backup_service="Wi-Fi",
        )
    )
    assert failover is not None
    assert failover.auto_enabled is False


def test_manual_only_mode_keeps_the_switch_step_off_the_ladder():
    cfg = config(
        failover_enabled=False,
        failover_preferred_service="AX88179B",
        failover_backup_service="Wi-Fi",
    )
    sm = build_state_machine(cfg)
    assert sm.failover_classifications == frozenset()
    assert "switch_to_backup_network" not in [
        s.name for s in ladder_for(Classification.NETWORK, sm.failover_classifications)
    ]


def test_manual_only_mode_refuses_automatic_switching():
    failover = build_failover(
        config(
            failover_enabled=False,
            failover_preferred_service="AX88179B",
            failover_backup_service="Wi-Fi",
        )
    )
    assert failover.attempt_failover("network").startswith("disabled:")
    assert failover.attempt_failback() is None


def test_no_names_means_no_failover_at_all():
    assert build_failover(config(failover_enabled=False)) is None


# --- menu indicator rows ----------------------------------------------------


class FakeFailoverForMenu:
    def __init__(self, snap):
        self.snap = snap
        self.switched = []
        self.preferred_service = "AX88179B"
        self.backup_service = "Wi-Fi"
        self.last_event = None

    def snapshot(self):
        if isinstance(self.snap, Exception):
            raise self.snap
        return self.snap

    def switch_now(self, target):
        self.switched.append(target)
        return "ok: switched"

    def attempt_failback(self):
        return None


MENU_SNAPSHOT = {
    "error": None,
    "active_side": "backup",
    "active_service": "Wi-Fi",
    "preferred": {"name": "AX88179B", "device": "en6", "found": True, "reachable": False},
    "backup": {"name": "Wi-Fi", "device": "en0", "found": True, "reachable": True},
    "auto_enabled": True,
    "last_event": None,
}


def test_menu_rows_show_active_preferred_and_backup(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "none.yaml"))
    app.failover = FakeFailoverForMenu(MENU_SNAPSHOT)
    app._refresh_failover_menu()
    titles = [row.title for row in app.failover_rows]
    assert "Wi-Fi" in titles[0]
    assert "AX88179B" in titles[1] and "en6" in titles[1] and "unreachable" in titles[1]
    assert "Wi-Fi" in titles[2] and "en0" in titles[2] and "reachable" in titles[2]
    assert titles[1].startswith("○") and titles[2].startswith("●")


def test_unconfigured_failover_leaves_no_blank_rows(tmp_path):
    """A blank title renders as an empty clickable-looking row."""
    app = NetDnsMonitorApp(config_path=str(tmp_path / "none.yaml"))
    app.failover = None
    app._refresh_failover_menu()
    assert all(row.title.strip() != "" or row.title == " " for row in app.failover_rows)
    assert "not configured" in app.failover_rows[0].title


def test_a_broken_snapshot_does_not_take_down_the_menu(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "none.yaml"))
    app.failover = FakeFailoverForMenu(RuntimeError("networksetup exploded"))
    app._refresh_failover_menu()  # must not raise
    assert "unavailable" in app.failover_rows[0].title
    assert "RuntimeError" in app.failover_rows[0].title


def test_the_switch_buttons_call_through_to_the_failover(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "none.yaml"))
    failover = FakeFailoverForMenu(MENU_SNAPSHOT)
    app.failover = failover
    notes = []
    import netdnsmonitor.app as app_module

    real_notification = app_module.rumps.notification
    app_module.rumps.notification = lambda *a, **k: notes.append(a)
    try:
        app.switch_to_backup(None)
        app.switch_to_preferred(None)
    finally:
        app_module.rumps.notification = real_notification
    assert failover.switched == ["backup", "preferred"]
    assert len(notes) == 2


# --- status text ------------------------------------------------------------


def test_status_text_when_disabled():
    assert "Disabled" in failover_status_text(None)


def test_status_text_distinguishes_idle_from_acted():
    failover = build_failover(enabled_config())
    idle = failover_status_text(failover)
    assert "No switch attempted" in idle
    failover.last_event = "ok: service order now starts with 'Wi-Fi'"
    acted = failover_status_text(failover)
    assert "Last attempt" in acted and "Wi-Fi" in acted
    assert idle != acted
