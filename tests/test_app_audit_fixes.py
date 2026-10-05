"""Regression tests for the app.py audit findings: failures that must show up as
data, and wording that must not claim more than was measured."""

import subprocess
import time

from netdnsmonitor import app as app_module
from netdnsmonitor.app import NetDnsMonitorApp, missing_key_text, recheck_text
from netdnsmonitor.forensic_log import DOWN, ForensicRecorder
from netdnsmonitor.ping import ping_once
from tests.test_app_appstore_wiring import DIRECT, STORE, build_app
from tests.test_app_dashboard_wiring import FakeStateMachine, make_app


def bare_app(tmp_path):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.forensic = ForensicRecorder(
        journal_path=str(tmp_path / "forensic.jsonl"),
        episodes_dir=str(tmp_path / "episodes"),
    )
    return app


# --- A1: a re-probe that could not tell is not "still failing" ---------------


def test_an_inconclusive_recheck_is_not_recorded_as_still_failing(tmp_path):
    app = bare_app(tmp_path)
    app._record_incident_forensics(
        {
            "classification": "dns",
            "probe_results": {},
            "ladder_results": [],
            "recheck_ok": None,
            "escalation": None,
        }
    )
    recheck = [e for e in app.forensic.episode["events"] if e["kind"] == "recheck"][0]
    assert "inconclusive" in recheck["result"]


def test_recheck_text_is_three_way():
    assert recheck_text(True) == "healthy again"
    assert recheck_text(False) == "still failing"
    assert "inconclusive" in recheck_text(None)


# --- A2: a tick that raises every run must not keep a green title ------------


class RaisingStateMachine(FakeStateMachine):
    def tick(self):
        raise UnicodeEncodeError("idna", "a..b", 0, 1, "empty label")


def test_a_tick_that_raises_every_run_stops_showing_healthy(tmp_path):
    app = make_app(tmp_path, state_machine=RaisingStateMachine())
    for _ in range(app.config["failure_threshold"]):
        app.tick()
    assert app.last_tick_error == "UnicodeEncodeError"
    assert "check failing" in app.title
    assert "healthy" not in app.title


def test_a_clean_tick_resets_the_failure_count(tmp_path):
    app = make_app(tmp_path, state_machine=RaisingStateMachine())
    for _ in range(app.config["failure_threshold"]):
        app.tick()
    app.state_machine = FakeStateMachine()
    app.tick()
    assert app._tick_failures == 0
    assert "check failing" not in app.title


# --- A3: the heartbeat survives a bad host and a raising job ------------------


def test_a_bad_fallback_host_does_not_blind_the_heartbeat():
    def fake_run(args, **kwargs):
        return subprocess.CompletedProcess(args, 2, stdout="", stderr="")

    def ping_fn(host, timeout_seconds):
        return ping_once(host, timeout_seconds, run_fn=fake_run)

    config = {
        "ping_host_v6": None,
        "ping_host": "8.8.8.8",
        "ping_fallback_host": "bad host",
        "ping_timeout_seconds": 2.0,
    }
    result = app_module.ping_heartbeat(config, ping_fn=ping_fn)
    assert result["ok"] is False
    assert "8.8.8.8" in result["error"]
    assert "bad host" in result["error"]


def test_a_value_error_on_one_host_does_not_skip_the_next():
    def ping_fn(host, timeout_seconds):
        if host == "bad":
            raise ValueError("refused")
        return {"ok": True, "rtt_ms": 1.0, "error": None}

    config = {
        "ping_host_v6": None,
        "ping_host": "bad",
        "ping_fallback_host": "good",
        "ping_timeout_seconds": 2.0,
    }
    result = app_module.ping_heartbeat(config, ping_fn=ping_fn)
    assert result["ok"] is True
    assert result["host"] == "good"


def test_a_raising_ping_job_is_recorded_without_inventing_a_reading(tmp_path):
    app = make_app(tmp_path)

    def job():
        raise OSError("boom")

    app.ping_job = job
    app._run_ping()
    assert app.last_tick_error == "ping heartbeat failed: OSError"
    assert app._ping_results.empty()


# --- A4: a failed delivery leaves a trace -------------------------------------


def test_a_failed_delivery_is_printed_to_stderr(tmp_path, capsys):
    app = make_app(tmp_path)
    app.notifier = lambda text: [{"channel": "slack", "error": "Slack webhook unreachable"}]
    app._send_notification("x")
    app._notification_thread.join(timeout=5)
    err = capsys.readouterr().err
    assert "[notify] slack: Slack webhook unreachable" in err


def test_an_empty_notifier_result_is_printed_once(tmp_path, capsys):
    app = make_app(tmp_path)
    app.notifier = lambda text: []
    app._send_notification("x")
    app._notification_thread.join(timeout=5)
    err = capsys.readouterr().err
    assert err.count("[notify]") == 1


def test_a_successful_delivery_prints_nothing(tmp_path, capsys):
    app = make_app(tmp_path)
    app.notifier = lambda text: [{"channel": "slack", "ok": True}]
    app._send_notification("x")
    app._notification_thread.join(timeout=5)
    assert "[notify]" not in capsys.readouterr().err


# --- A6: localization verdict wiring -----------------------------------------


class _SM:
    def __init__(self, probe):
        self.last_probe = probe


def localize_app(tmp_path, probe):
    app = bare_app(tmp_path)
    app.state_machine = _SM(probe)
    app.forensic.note(DOWN, "ping", reason="r", detail="d", result="x")
    return app


def test_the_verdict_passes_an_unprobed_field_through_as_none(tmp_path):
    app = localize_app(tmp_path, {"external_reachable": None, "dns_ok": False})
    app._localize_due_at = 0.0
    app._finish_localization_if_due()
    assert app._localize_due_at is None
    assert app.fault_verdict["evidence"]["our_external_reachable"] is None
    assert app.fault_verdict["evidence"]["our_dns_ok"] is False
    observed = [e for e in app.forensic.episode["events"] if e["kind"] == "observation"]
    assert observed and "fault localization:" in observed[0]["detail"]


def test_no_verdict_before_the_wait_has_elapsed(tmp_path):
    app = localize_app(tmp_path, {})
    app._localize_due_at = time.monotonic() + 60
    app._finish_localization_if_due()
    assert app.fault_verdict is None
    assert app._localize_due_at is not None


def test_no_verdict_when_nothing_is_pending(tmp_path):
    app = localize_app(tmp_path, {})
    app._localize_due_at = None
    app._finish_localization_if_due()
    assert app.fault_verdict is None


# --- F1: a raising manual step keeps the earlier steps ------------------------


def test_full_diagnosis_keeps_earlier_steps_when_a_later_step_raises(tmp_path):
    app = make_app(tmp_path)
    app.state_machine.prober = lambda: {"external_reachable": True, "dns_ok": False}
    calls = []

    def executor(step, classification=None):
        calls.append(step.name)
        if len(calls) == 3:
            raise OSError("secret detail")
        return f"ran {step.name}"

    app.state_machine.repair_executor = executor
    lines = app._full_diagnosis(events := [])
    text = "\n".join(lines)
    assert f"ran {calls[0]}" in text
    assert "failed: step raised OSError" in text
    assert "secret detail" not in text
    assert len(events) >= 3


def test_single_step_raise_is_reported_as_failed(tmp_path):
    app = make_app(tmp_path)

    def executor(step, classification=None):
        raise OSError("secret detail")

    app.state_machine.repair_executor = executor
    lines = app._single_step("flush_dns_cache", [])
    assert "failed: step raised OSError" in "\n".join(lines)


# --- F3: a non-https Slack URL is not "in use now" ----------------------------


def test_a_non_https_slack_webhook_is_not_reported_as_in_use(tmp_path):
    app = build_app(
        tmp_path,
        capabilities=DIRECT,
        secret_prompt=lambda title, message: "hooks.slack.com/services/T/B/x",
        slack_enabled=True,
    )
    outcome = app.set_credential("SLACK_WEBHOOK_URL")
    assert "in use now" not in outcome
    assert "https://" in outcome


# --- F4: the store build does not offer or write gated settings ---------------


def test_store_build_hides_the_settings_it_cannot_run(tmp_path):
    hidden = build_app(tmp_path, capabilities=STORE).hidden_setting_keys()
    assert {"router_enabled", "lan_ip", "failover_enabled", "log_view_enabled"} <= hidden
    assert "auto_open_console" in hidden
    assert "ping_host" not in hidden


def test_direct_build_hides_nothing(tmp_path):
    assert build_app(tmp_path, capabilities=DIRECT).hidden_setting_keys() == frozenset()


def test_store_build_settings_do_not_promise_a_restart_enables_the_router(tmp_path):
    from netdnsmonitor.settings_window import FIELDS, format_field

    app = build_app(tmp_path, capabilities=STORE)
    values = {k: format_field(kind, app.config.get(k)) for k, _l, kind in FIELDS}
    values["router_enabled"] = format_field("bool", True)
    note = app._save_settings(values)
    assert "router_enabled" not in note
    with open(app.config_path) as handle:
        assert "router_enabled" not in handle.read()


def test_store_build_settings_window_is_built_with_the_hidden_keys(tmp_path, monkeypatch):
    built = {}

    class FakeSettingsWindow:
        def __init__(self, **kwargs):
            built.update(kwargs)

        def load(self, config):
            pass

        def show(self):
            pass

        def set_status(self, text):
            pass

    monkeypatch.setattr(app_module, "SettingsWindow", FakeSettingsWindow)
    app = build_app(tmp_path, capabilities=STORE)
    app.open_settings()
    assert built["hidden_keys"] == app.hidden_setting_keys()
    assert "config_path_display" in built


def test_a_slack_url_with_an_upper_case_scheme_is_not_in_use(tmp_path):
    app = build_app(
        tmp_path,
        capabilities=DIRECT,
        slack_enabled=True,
        secret_prompt=lambda t, m: "HTTPS://hooks.slack.com/services/T/B/x",
    )
    assert "in use now" not in app.set_credential("SLACK_WEBHOOK_URL")


# --- F6: a relative reports_dir still opens -----------------------------------


def test_open_last_report_accepts_a_relative_path(tmp_path):
    app = make_app(tmp_path)
    opened = []
    app.url_opener = lambda url: opened.append(url) or True
    app.last_report_path = "reports/20260101.md"
    outcome = app.open_last_report(None)
    assert outcome.startswith("ok:")
    assert opened[0].startswith("file:///")


# --- credentials F1 -----------------------------------------------------------


def test_missing_key_text_names_an_unreadable_keychain():
    text = missing_key_text(DIRECT, -25308)
    assert "Keychain unreadable, OSStatus -25308" in text
    assert "Keychain unreadable" not in missing_key_text(DIRECT)


# --- router R1 ----------------------------------------------------------------


def test_the_router_is_built_with_the_primary_interface_lookup(tmp_path):
    seen = {}

    def factory(**kwargs):
        seen.update(kwargs)
        return object()

    config = tmp_path / "config.yaml"
    config.write_text("router_enabled: true\n")
    NetDnsMonitorApp(
        config_path=str(config),
        capabilities=DIRECT,
        router_factory=factory,
    )
    assert seen["primary_interface_fn"] is app_module.privileges.primary_interface


# --- dashboard F1: abandoned lookups are not failures -------------------------


def test_abandoned_resolution_findings_are_not_counted_as_failing(tmp_path):
    app = make_app(tmp_path)
    app.last_resolution_findings = [
        {"domain": "a", "resolved": True},
        {"domain": "b", "resolved": False},
        {"domain": "c", "resolved": False, "outcome": "abandoned"},
    ]
    failed, total, *_ = app._display_snapshot()
    assert (failed, total) == (1, 3)


# --- P-05: a grant that sudo does not list is not "Granted" -------------------


def test_a_grant_the_reprobe_cannot_see_says_nothing_is_granted(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    monkeypatch.setattr(
        app_module.privileges, "grant", lambda user, interfaces: {"ok": True, "message": "Granted."}
    )
    monkeypatch.setattr(app_module.privileges, "granted_commands_now", lambda: [])
    monkeypatch.setattr(app_module.privileges, "dhcp_interfaces", lambda: [])
    app._run_grant([])
    result = app._privilege_results.get_nowait()
    assert "nothing is granted" in result["message"]
    assert "Granted." not in result["message"]


# --- dashboard input: the ping reading carries its age ------------------------


def test_the_dashboard_gets_the_age_of_the_last_ping_reading(tmp_path):
    app = make_app(tmp_path)
    assert "age_seconds" not in app._ping_stats_with_age()
    app.ping_stats = {**app.ping_stats, "at": time.time() - 100}
    assert app._ping_stats_with_age()["age_seconds"] >= 100


def test_a_heartbeat_where_no_host_was_pinged_is_marked_unprobed():
    def ping_fn(host, timeout_seconds):
        return {"ok": False, "rtt_ms": None, "probed": False, "error": "did not resolve"}

    config = {
        "ping_host_v6": "",
        "ping_host": "host.example",
        "ping_fallback_host": "",
        "ping_timeout_seconds": 2.0,
    }
    assert app_module.ping_heartbeat(config, ping_fn=ping_fn)["probed"] is False


def test_one_real_echo_failure_makes_the_heartbeat_a_measured_failure():
    def ping_fn(host, timeout_seconds):
        if host == "8.8.8.8":
            return {"ok": False, "rtt_ms": None, "error": "no reply"}
        return {"ok": False, "rtt_ms": None, "probed": False, "error": "did not resolve"}

    config = {
        "ping_host_v6": "",
        "ping_host": "8.8.8.8",
        "ping_fallback_host": "host.example",
        "ping_timeout_seconds": 2.0,
    }
    assert "probed" not in app_module.ping_heartbeat(config, ping_fn=ping_fn)


def test_grant_with_an_interface_probe_that_failed_says_so_instead_of_raising(tmp_path):
    app = make_app(tmp_path)
    out = []
    app._append_output = out.append
    app.privileges_probed = True
    app.dhcp_interfaces = None
    app._grant_privileges()
    assert "could not list" in "".join(out).lower()
