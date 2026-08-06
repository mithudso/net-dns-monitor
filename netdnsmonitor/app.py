"""Menu bar shell. Every decision (classification, ladder, anti-flap,
escalation gate, redaction, domain learning/pruning, notification formatting)
lives in already-tested modules; this file only wires them to a rumps timer
and a status-item title.
"""

import os
import pathlib
import webbrowser

import rumps

from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.config import load_config
from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    make_domain_learner,
    prune_dead_domains,
)
from netdnsmonitor.escalation import redact
from netdnsmonitor.failover import BACKUP, PREFERRED, FailoverStore, NetworkFailover
from netdnsmonitor.interface_probe import make_interface_prober
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.notifications import (
    format_notification,
    make_email_notifier,
    make_notifier,
    make_slack_notifier,
)
from netdnsmonitor.prober import make_prober
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import build_failover_lines, build_title
from netdnsmonitor.throughput import make_throughput_meter

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")


def build_notifier(config: dict, env: dict = None):
    """Slack and email are opt-in by presence of their credential in the
    environment, mirroring the ANTHROPIC_API_KEY branch: no webhook URL and no
    SMTP recipients means no channels and a notifier that is a cheap no-op,
    never a crash and never a silent half-configured send.
    """
    env = os.environ if env is None else env
    channels = []

    webhook_url = env.get("SLACK_WEBHOOK_URL")
    if config.get("slack_enabled") and webhook_url:
        channels.append(
            make_slack_notifier(
                webhook_url=webhook_url,
                timeout=float(config["notify_timeout_seconds"]),
            )
        )

    recipients = config.get("email_recipients") or []
    if config.get("email_enabled") and recipients:
        channels.append(
            make_email_notifier(
                host=config["smtp_host"],
                port=int(config["smtp_port"]),
                recipients=list(recipients),
                sender=config["email_from"],
                username=config.get("smtp_username"),
                password=env.get("SMTP_PASSWORD"),
                use_starttls=bool(config.get("smtp_starttls", True)),
                timeout=float(config["notify_timeout_seconds"]),
            )
        )

    return make_notifier(channels)


def anchor_domains(config: dict) -> list[str]:
    """The names that are probed but never learned and never pruned: the user's
    own `domains` plus the control domain.

    The control domain is what makes dead-name pruning possible at all. Learned
    domains are by definition names that *failed*, so on the default config
    (`domains: []`) every probed name is a learned failure and "some other
    domain resolved" can never be true -- one dead name would pin a permanent
    false DNS incident. A name known to resolve breaks that tie: control up +
    learned name down means the name is dead; control down means DNS really is
    broken and nothing is pruned.
    """
    anchors = list(config.get("domains") or [])
    control = config.get("control_domain")
    if control and control not in anchors:
        anchors.append(control)
    return anchors


def build_domains_source(config: dict, log_watcher):
    """Returns (domains_source, store). domains_source is what the prober asks
    each tick; store is None when log learning is turned off.
    """
    anchors = anchor_domains(config)
    if not config.get("learn_domains_from_logs"):
        return anchors, None
    store = LearnedDomainStore(
        path=config["learned_domains_path"],
        max_domains=int(config["max_learned_domains"]),
    )
    learner = make_domain_learner(
        log_watcher=log_watcher,
        store=store,
        configured_domains=anchors,
        interval_seconds=float(config["domain_learn_interval_seconds"]),
    )
    return learner, store


def build_failover(config: dict):
    """Returns a NetworkFailover, or None when the feature is off or not fully
    configured.

    Both service names are required and neither is guessed. The machine this
    was written for has three wired adapters with near-identical names, so a
    "helpful" default here would reorder the wrong physical link.
    """
    preferred = config.get("failover_preferred_service")
    backups = failover_backup_names(config)
    if not preferred or not backups:
        return None
    return NetworkFailover(
        preferred_service=preferred,
        backup_services=backups,
        throughput_meter=make_throughput_meter(
            host=config.get("failover_speedtest_host", ""),
            path=config["failover_speedtest_path"],
            port=int(config["failover_speedtest_port"]),
            timeout=float(config["failover_speedtest_timeout_seconds"]),
            max_bytes=int(config["failover_speedtest_max_bytes"]),
        ),
        store=FailoverStore(config["failover_state_path"]),
        # Reachability is judged against the same external targets the ordinary
        # probe uses, but forced out of a specific interface.
        interface_prober=make_interface_prober(
            targets=[tuple(t) for t in config["external_targets"]],
            timeout=float(config.get("probe_timeout_seconds", 2.0)),
        ),
        failback_threshold=int(config["failover_failback_threshold"]),
        cooldown_seconds=float(config["failover_cooldown_seconds"]),
        max_switches_per_hour=max(0, int(config["failover_max_switches_per_hour"])),
        trigger_classifications=failover_trigger_classifications(config),
        auto_enabled=bool(config.get("failover_enabled")),
    )


def failover_backup_names(config: dict) -> list[str]:
    """The ordered backup list, however it was written.

    The singular key stays accepted because most setups have exactly one
    backup and a list of one is noise. Duplicates are collapsed and the
    preferred service is refused as its own backup -- promoting a service above
    itself is not a failover.
    """
    names: list[str] = []
    for name in [config.get("failover_backup_service")] + list(
        config.get("failover_backup_services") or []
    ):
        if name and name not in names and name != config.get("failover_preferred_service"):
            names.append(name)
    return names


def failover_trigger_classifications(config: dict) -> frozenset:
    """An explicitly empty list means "nothing triggers a switch" and must be
    honoured. `config.get(key) or [...]` would treat it as absent and re-arm
    the default, so setting `failover_trigger_classifications: []` to stage the
    feature inert while checking service names would still rewrite the service
    order on the next incident. Only a missing or null key takes the default.
    """
    if not config.get("failover_enabled"):
        # Manual-only mode: the menu bar button still switches, but no incident
        # puts the failover step on the ladder.
        return frozenset()
    configured = config.get("failover_trigger_classifications")
    if configured is None:
        configured = ["network"]
    return frozenset(configured)


def failover_status_text(failover) -> str:
    """What the menu item reports. States "no switch has been attempted"
    distinctly from "a switch happened": an operator reading this needs to be
    able to tell the feature being idle apart from it having acted.
    """
    if failover is None:
        return "Disabled (set failover_enabled and both service names in config.yaml)."
    if failover.last_event is None:
        return (
            f"Enabled: preferred '{failover.preferred_service}', backup "
            f"'{failover.backup_service}'. No switch attempted this session."
        )
    return f"Last attempt: {failover.last_event}"


def build_state_machine(config: dict, failover=None) -> StateMachine:
    """`failover` is passed in by the app so the ladder step and the tick-path
    failback share one instance and therefore one set of counters. It is
    derived from the config when omitted, so that a caller who forgets gets a
    state machine that matches the config rather than one that silently drops
    the switch step.
    """
    if failover is None:
        failover = build_failover(config)

    external_targets = [tuple(t) for t in config["external_targets"]]
    internal_targets = [tuple(t) for t in config["internal_targets"]]

    log_watcher = make_log_watcher(lookback=config["log_lookback"])
    domains_source, store = build_domains_source(config, log_watcher)

    base_prober = make_prober(
        external_targets=external_targets,
        internal_targets=internal_targets,
        domains=domains_source,
        timeout=float(config.get("probe_timeout_seconds", 2.0)),
    )

    if store is None:
        prober = base_prober
    else:

        anchors = anchor_domains(config)

        def prober() -> dict:
            # Prune on the probe path, not on the incident path: a dead learned
            # name has to be evicted on ordinary healthy ticks, which is
            # exactly when the state machine returns no report at all.
            probe = base_prober()
            prune_dead_domains(
                store,
                probe.get("domain_results", {}),
                configured_domains=anchors,
                anchor_domains=anchors,
            )
            return probe

    repair_executor = make_repair_executor(
        failover_fn=failover.attempt_failover if failover else None
    )

    if os.environ.get("ANTHROPIC_API_KEY"):
        escalator = make_escalator(client=default_client())
    else:
        escalator = lambda bundle: {  # noqa: E731 - trivial fallback, no client configured
            "error": "ANTHROPIC_API_KEY not set; skipped LLM escalation"
        }

    return StateMachine(
        prober=prober,
        repair_executor=repair_executor,
        escalator=escalator,
        log_watcher=log_watcher,
        failure_threshold=config["failure_threshold"],
        success_threshold=config["success_threshold"],
        sensitive_strings=config["sensitive_strings"],
        failover_classifications=(
            failover_trigger_classifications(config) if failover else frozenset()
        ),
    )


class NetDnsMonitorApp(rumps.App):
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        super().__init__(name="net-dns-monitor", title="Net/DNS: starting...")
        self.config = load_config(config_path)
        self.failover = build_failover(self.config)
        self.state_machine = build_state_machine(self.config, self.failover)
        self.notifier = build_notifier(self.config)
        self.last_classification = None
        self.last_report_path = None
        self.last_notification_results = None
        self.last_tick_error = None
        # Indicator rows carry no callback, which is what greys them out: they
        # are readouts, not actions. Titles are set by _refresh_failover_menu.
        self.failover_rows = [rumps.MenuItem(f"failover-row-{i}") for i in range(3)]
        self.menu = [
            *self.failover_rows,
            None,
            rumps.MenuItem("Switch to backup now", callback=self.switch_to_backup),
            rumps.MenuItem("Switch back to preferred now", callback=self.switch_to_preferred),
            rumps.MenuItem("Refresh network status", callback=self.refresh_failover),
            None,
            rumps.MenuItem("Open console…", callback=self.open_console),
            rumps.MenuItem("Open last report", callback=self.open_last_report),
        ]
        self.console_window = None
        self._refresh_failover_menu()
        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()

    def tick(self, _sender=None):
        # A raise here lands in the rumps timer callback and kills monitoring
        # for the rest of the session, so every tick is guarded. Real triggers
        # exist: a TCC-denied /etc/resolver listing in the ladder, or a
        # read-only volume under reports_dir.
        try:
            self._tick()
        except Exception as exc:  # noqa: BLE001 - a dead timer is worse than a lost tick
            self.last_tick_error = f"{type(exc).__name__}: {exc}"
            try:
                # The recovery path must not raise either, or the guard has
                # merely moved the crash one frame out.
                self.title = build_title(
                    self.state_machine.flap_gate.state, self.last_classification
                )
            except Exception:  # noqa: BLE001
                self.title = "⚪ Net/DNS: check failed"

    def _tick(self):
        report = self.state_machine.tick()
        if report is not None:
            paths = save_report(report, self.config["reports_dir"])
            self.last_report_path = paths["markdown_path"]
            self.last_classification = report["classification"]
            # Redact on the way out for the same reason escalation does: Slack
            # and email are off-machine, and the on-disk report is not.
            text = redact(
                format_notification(report, paths["markdown_path"]),
                self.config["sensitive_strings"],
            )
            self.last_notification_results = self.notifier(text)
            # An incident may have run the failover ladder step, so the
            # indicator is stale.
            self._refresh_failover_menu()
        elif self.failover is not None:
            # Failback rides the probe path for the same reason dead-domain
            # pruning does: recovery produces no report, so the healthy ticks
            # when the preferred link should be reclaimed are exactly the ticks
            # the state machine returns None on. Skipped when a report was
            # produced, so a failover and a failback can never interleave
            # within one tick.
            if self.failover.attempt_failback() is not None:
                # Only when something was actually attempted -- a refresh costs
                # a subprocess and two probes, which is not an every-tick price.
                self._refresh_failover_menu()
        self.title = build_title(self.state_machine.flap_gate.state, self.last_classification)

    def _refresh_failover_menu(self):
        """Repaint the three indicator rows. Never raises: this runs from menu
        callbacks and from the tick guard, and a broken indicator must not take
        anything else down with it.
        """
        try:
            snapshot = self.failover.snapshot() if self.failover else None
            lines = build_failover_lines(snapshot)
        except Exception as exc:  # noqa: BLE001 - an indicator is not worth a crash
            lines = [f"Failover: status unavailable ({type(exc).__name__})"]
        for row, text in zip(self.failover_rows, lines + [""] * len(self.failover_rows)):
            # An empty title would leave a clickable-looking blank row.
            row.title = text or " "

    def _manual_switch(self, target: str, label: str):
        if self.failover is None:
            rumps.notification(
                "Net/DNS Monitor",
                "Network failover",
                "Not configured — set failover_preferred_service and "
                "failover_backup_service in config.yaml.",
            )
            return
        try:
            outcome = self.failover.switch_now(target)
        except Exception as exc:  # noqa: BLE001 - report it, never crash the menu
            outcome = f"failed: {type(exc).__name__}: {exc}"
        self._refresh_failover_menu()
        rumps.notification("Net/DNS Monitor", f"Switch to {label}", outcome)

    def switch_to_backup(self, _sender):
        self._manual_switch(BACKUP, "backup")

    def switch_to_preferred(self, _sender):
        self._manual_switch(PREFERRED, "preferred")

    def refresh_failover(self, _sender):
        self._refresh_failover_menu()
        rumps.notification(
            "Net/DNS Monitor", "Network failover", failover_status_text(self.failover)
        )

    def open_console(self, _sender):
        """Imported here rather than at module scope: window.py touches AppKit
        window classes, and a failure to build one must cost the console, not
        the monitoring.
        """
        try:
            from netdnsmonitor.window import ConsoleWindowController

            if self.console_window is None:
                self.console_window = ConsoleWindowController(self.config)
            self.console_window.show()
        except Exception as exc:  # noqa: BLE001
            rumps.notification(
                "Net/DNS Monitor",
                "Console",
                f"Could not open the console window ({type(exc).__name__}). "
                "`python3 -m netdnsmonitor.cli console` does the same thing in a terminal.",
            )

    def open_last_report(self, _sender):
        if self.last_report_path:
            # as_uri() percent-encodes: the default reports_dir sits under
            # "Application Support", and a raw space makes an invalid file URL.
            webbrowser.open(pathlib.Path(self.last_report_path).as_uri())
        else:
            rumps.notification("Net/DNS Monitor", "", "No report has been generated yet.")


def main():
    NetDnsMonitorApp().run()


if __name__ == "__main__":
    main()
