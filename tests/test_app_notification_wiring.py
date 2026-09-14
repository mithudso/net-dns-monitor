"""Wiring tests for the two features that only exist once app.py glues the
tested modules together: notifying on a fresh report (redacted, once per
incident onset) and probing an auto-learned domain list that self-prunes.
"""

import json
import urllib.error
import urllib.request

from netdnsmonitor.app import (
    NetDnsMonitorApp,
    anchor_domains,
    build_domains_source,
    build_notifier,
)


def tick_and_deliver(app):
    """Tick, then wait for the notification worker to finish.

    The send moved off the run loop -- Slack and email are network I/O and this
    is called from a timer callback. That makes "did it send" a question about
    another thread, so these tests join it rather than asserting into a race
    that passes on a fast machine and fails on a loaded one.
    """
    app.tick()
    if app._notification_thread is not None:
        app._notification_thread.join(timeout=5)
        assert not app._notification_thread.is_alive(), "notification worker hung"


class FakeFlapGate:
    def __init__(self, state):
        self.state = state
        # Read by the title repaint at the end of every tick.
        self.consecutive_failures = 0


class FakeStateMachine:
    def __init__(self, report, flap_state="incident"):
        self._report = report
        self.flap_gate = FakeFlapGate(flap_state)

    def tick(self):
        return self._report


REPORT = {
    "classification": "dns",
    "started_at": "2026-08-05T12:00:00+00:00",
    "duration_seconds": 3.0,
    "resolved": False,
    "summary": "DNS-layer incident at corp.local, unresolved.",
    "repair_outcome": None,
    "escalation": None,
    "probe_results": {"external_reachable": True, "dns_ok": False},
    "log_excerpts": ["query for corp.local timed out"],
    "ladder_results": [],
}


def _app(tmp_path, **config_overrides):
    app = NetDnsMonitorApp(config_path=str(tmp_path / "no-such-config.yaml"))
    app.config.update(reports_dir=str(tmp_path / "reports"), **config_overrides)
    return app


def test_tick_notifies_when_a_report_is_produced(tmp_path):
    sent = []
    app = _app(tmp_path)
    app.notifier = lambda text: sent.append(text) or [{"delivered": True}]
    app.state_machine = FakeStateMachine(REPORT)

    tick_and_deliver(app)

    assert len(sent) == 1
    assert "dns" in sent[0]
    assert app.last_report_path.endswith(".md")
    assert app.last_notification_results == [{"delivered": True}]


def test_tick_does_not_notify_when_there_is_no_report(tmp_path):
    sent = []
    app = _app(tmp_path)
    app.notifier = lambda text: sent.append(text) or []
    app.state_machine = FakeStateMachine(None, flap_state="healthy")

    app.tick()

    assert sent == []


def test_notification_text_is_redacted_before_it_leaves_the_machine(tmp_path):
    sent = []
    app = _app(tmp_path, sensitive_strings=["corp.local"])
    app.notifier = lambda text: sent.append(text) or []
    app.state_machine = FakeStateMachine(REPORT)

    tick_and_deliver(app)

    assert "corp.local" not in sent[0]
    assert "[REDACTED]" in sent[0]


def test_tick_does_not_wait_for_a_slow_notifier(tmp_path):
    """The property the worker exists for.

    Slack and email are network I/O, and this runs from the poll timer's
    callback -- the same run loop that draws the window and drives the 5s
    heartbeat. Two channels at notify_timeout_seconds each is a 10-second freeze
    at the exact moment the network is known to be broken.

    Asserted by blocking the notifier outright rather than by checking that a
    thread was started: a thread is the current implementation, "the tick
    returned" is the requirement.
    """
    import threading

    release = threading.Event()
    entered = threading.Event()

    def blocking_notifier(_text):
        entered.set()
        release.wait(timeout=5)
        return [{"delivered": True}]

    app = _app(tmp_path)
    app.notifier = blocking_notifier
    app.state_machine = FakeStateMachine(REPORT)

    app.tick()

    # The send is genuinely in flight, and the tick is already back.
    assert entered.wait(timeout=5), "notifier was never called"
    assert app._notification_thread.is_alive()
    assert app.last_notification_results is None

    release.set()
    app._notification_thread.join(timeout=5)
    assert app.last_notification_results == [{"delivered": True}]


def test_a_raising_notifier_does_not_kill_the_worker_silently(tmp_path):
    """`notifier` records and swallows its own delivery failures, so this covers
    the case where it breaks its contract -- the result must still be published,
    or `:status` would report the previous incident's delivery forever.
    """
    app = _app(tmp_path)
    app.notifier = lambda _text: (_ for _ in ()).throw(OSError("boom"))
    app.state_machine = FakeStateMachine(REPORT)

    tick_and_deliver(app)

    assert app.last_notification_results == [
        {"channel": "unknown", "ok": False, "error": "OSError"}
    ]


def test_tick_notifies_and_classifies_even_when_the_report_cannot_be_saved(tmp_path, monkeypatch):
    """The gate reports only on the healthy->incident edge, so a save that raised
    used to cost the one alert, the forensic DOWN and the classification in the
    title -- and no later tick could produce them.
    """
    import netdnsmonitor.app as app_module

    def unwritable(report, directory):
        raise OSError("Read-only file system: /Volumes/reports/secret-name")

    monkeypatch.setattr(app_module, "save_report", unwritable)
    sent = []
    app = _app(tmp_path)
    app.last_report_path = "/earlier/incident.md"
    app.notifier = lambda text: sent.append(text) or [{"delivered": True}]
    app.state_machine = FakeStateMachine(REPORT)
    noted = []
    app.forensic.note = lambda kind, detector, **fields: noted.append(kind)

    tick_and_deliver(app)

    assert app.last_classification == "dns"
    assert len(sent) == 1
    assert "Full report" not in sent[0]
    assert app.last_report_path is None  # not the earlier incident's file
    assert app.last_tick_error == "report not saved: OSError"
    assert "secret-name" not in app.last_tick_error
    assert "down" in noted


def test_build_notifier_has_no_channels_without_credentials():
    config = {
        "slack_enabled": True,
        "email_enabled": True,
        "email_recipients": [],
        "notify_timeout_seconds": 5,
    }
    assert build_notifier(config, env={})("text") == []


def test_build_notifier_enables_slack_when_the_webhook_env_var_is_set(monkeypatch):
    config = {
        "slack_enabled": True,
        "email_enabled": False,
        "email_recipients": [],
        "notify_timeout_seconds": 5,
    }
    # urlopen is replaced rather than pointed at a closed local port: the suite
    # opens no sockets, and a system HTTP proxy can turn "refuses instantly"
    # into a multi-second wait.
    opened = []

    def refusing_urlopen(request, timeout=None):
        opened.append(request.full_url)
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", refusing_urlopen)
    notifier = build_notifier(config, env={"SLACK_WEBHOOK_URL": "https://hooks.slack.test/hook"})
    results = notifier("text")  # delivery must fail as data, never raise
    assert opened == ["https://hooks.slack.test/hook"]
    assert results == [{"channel": "slack", "error": "Slack webhook unreachable"}]


def test_build_notifier_skips_slack_when_disabled_in_config():
    config = {
        "slack_enabled": False,
        "email_enabled": False,
        "email_recipients": [],
        "notify_timeout_seconds": 5,
    }
    assert build_notifier(config, env={"SLACK_WEBHOOK_URL": "https://x.test"})("t") == []


def test_tick_survives_a_state_machine_that_raises(tmp_path):
    class ExplodingStateMachine(FakeStateMachine):
        def tick(self):
            raise OSError("read-only volume")

    app = _app(tmp_path)
    app.state_machine = ExplodingStateMachine(None)

    app.tick()  # a dead rumps timer is worse than a lost tick

    assert "OSError" in app.last_tick_error
    assert app.title  # title still refreshed


def test_build_domains_source_returns_a_plain_list_when_learning_is_off(tmp_path):
    config = {
        "domains": ["mine.example.com"],
        "control_domain": "example.com",
        "learn_domains_from_logs": False,
    }
    source, store = build_domains_source(config, log_watcher=lambda: [])
    assert source == ["mine.example.com", "example.com"]
    assert store is None


def test_build_domains_source_learns_failed_domains_from_the_log(tmp_path):
    config = {
        "domains": ["mine.example.com"],
        "control_domain": "example.com",
        "learn_domains_from_logs": True,
        "learned_domains_path": str(tmp_path / "learned.json"),
        "max_learned_domains": 20,
        "domain_learn_interval_seconds": 300,
    }
    # Synchronous spawn: the learner scans the log on a daemon thread, and this
    # asserts on what that scan stored.
    source, store = build_domains_source(
        config,
        log_watcher=lambda: ["query for broken.example.net timed out"],
        spawn=lambda fn: fn(),
    )
    assert source() == ["mine.example.com", "example.com", "broken.example.net"]
    assert store.domains == ["broken.example.net"]


def test_default_config_probes_the_control_domain_so_pruning_can_work(tmp_path):
    """Regression guard for the reviewed High: with no configured domains and
    no control domain, every probed name is a learned failure, so a dead name
    could never be identified as dead and would pin a false incident.
    """
    app = _app(tmp_path)
    assert anchor_domains(app.config) == [app.config["control_domain"]]
    assert app.config["control_domain"]


def test_the_wired_prober_evicts_a_dead_learned_domain_on_a_healthy_tick(tmp_path, monkeypatch):
    """Unit tests cover prune_dead_domains; this covers the wiring in
    build_state_machine that actually calls it on the probe path.
    """
    from netdnsmonitor.app import build_state_machine

    learned = tmp_path / "learned.json"
    learned.write_text('["dead.example.net"]')
    config = {
        "external_targets": [],
        "internal_targets": [],
        "domains": [],
        "control_domain": "example.com",
        "probe_timeout_seconds": 0.5,
        "learn_domains_from_logs": True,
        "learned_domains_path": str(learned),
        "max_learned_domains": 20,
        "domain_learn_interval_seconds": 10_000,
        "log_lookback": "5m",
        "failure_threshold": 2,
        "success_threshold": 2,
        "sensitive_strings": [],
    }

    # The control domain resolves, the learned name does not -> the name is
    # dead, not the resolver. make_prober is replaced rather than its default
    # resolve_fn patched, because that default is bound at definition time and
    # a module-level patch would leave the test hitting real DNS.
    def fake_make_prober(external_targets, internal_targets, domains, timeout=2.0):
        def prober():
            names = list(domains() if callable(domains) else domains)
            results = {name: name == "example.com" for name in names}
            return {
                "external_reachable": True,
                "internal_reachable": None,
                "dns_ok": all(results.values()) if results else None,
                "domain_results": results,
            }

        return prober

    monkeypatch.setattr("netdnsmonitor.app.make_prober", fake_make_prober)
    probe = build_state_machine(config).prober()

    assert probe["domain_results"]["example.com"] is True
    assert probe["domain_results"]["dead.example.net"] is False
    assert json.loads(learned.read_text()) == []
