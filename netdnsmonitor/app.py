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
from netdnsmonitor.failover import FailoverStore, NetworkFailover
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
from netdnsmonitor.status import build_title

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
    if not config.get("failover_enabled"):
        return None
    preferred = config.get("failover_preferred_service")
    backup = config.get("failover_backup_service")
    if not preferred or not backup or preferred == backup:
        return None
    return NetworkFailover(
        preferred_service=preferred,
        backup_service=backup,
        store=FailoverStore(config["failover_state_path"]),
        # Reachability is judged against the same external targets the ordinary
        # probe uses, but forced out of a specific interface.
        interface_prober=make_interface_prober(
            targets=[tuple(t) for t in config["external_targets"]],
            timeout=float(config.get("probe_timeout_seconds", 2.0)),
        ),
        failback_threshold=int(config["failover_failback_threshold"]),
        cooldown_seconds=float(config["failover_cooldown_seconds"]),
        max_switches_per_hour=int(config["failover_max_switches_per_hour"]),
        trigger_classifications=frozenset(
            config.get("failover_trigger_classifications") or ["network"]
        ),
    )


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
            frozenset(config.get("failover_trigger_classifications") or ["network"])
            if failover
            else frozenset()
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
        self.menu = ["Open last report", "Network failover status"]
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
        elif self.failover is not None:
            # Failback rides the probe path for the same reason dead-domain
            # pruning does: recovery produces no report, so the healthy ticks
            # when the preferred link should be reclaimed are exactly the ticks
            # the state machine returns None on. Skipped when a report was
            # produced, so a failover and a failback can never interleave
            # within one tick.
            self.failover.attempt_failback()
        self.title = build_title(self.state_machine.flap_gate.state, self.last_classification)

    @rumps.clicked("Network failover status")
    def show_failover_status(self, _sender):
        rumps.notification(
            "Net/DNS Monitor", "Network failover", failover_status_text(self.failover)
        )

    @rumps.clicked("Open last report")
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
