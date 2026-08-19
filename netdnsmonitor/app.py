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
from netdnsmonitor.console_window import ConsoleWindowController
from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    make_domain_learner,
    prune_dead_domains,
)
from netdnsmonitor.escalation import redact
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
from netdnsmonitor.status import build_status_report, build_title
from netdnsmonitor.router import Router

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


def build_state_machine(config: dict) -> StateMachine:
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

    repair_executor = make_repair_executor()

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
    )


class NetDnsMonitorApp(rumps.App):
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        super().__init__(name="net-dns-monitor", title="Net/DNS: starting...")
        self.config = load_config(config_path)
        self.state_machine = build_state_machine(self.config)
        self.notifier = build_notifier(self.config)
        self.last_classification = None
        self.last_report_path = None
        self.last_notification_results = None
        self.last_tick_error = None
        # Built on first open, then kept: the controller owns the NSWindow, and
        # a controller that went out of scope would take the window with it.
        self.console = None
        self.menu = [
            "Open last report", 
            "Open console", 
            rumps.MenuItem("Router"),
            "Start at Login"
        ]

        agent_path = os.path.expanduser("~/Library/LaunchAgents/com.netdnsmonitor.plist")
        if os.path.exists(agent_path):
            self.menu["Start at Login"].state = True

        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()
        if self.config.get("auto_open_console", True):
            try:
                self.open_console(None)
            except Exception:
                pass

        if self.config.get("router_enabled"):
            self.router = Router(
                wan_if=self.config.get("wan_interface", "en3"),
                lan_if=self.config.get("lan_interface", "en0"),
                lan_ip=self.config.get("lan_ip", "192.168.10.1"),
                lan_netmask=self.config.get("lan_netmask", "255.255.255.0"),
                dhcp_start=self.config.get("dhcp_start", "192.168.10.100"),
                dhcp_end=self.config.get("dhcp_end", "192.168.10.200")
            )
            self.router.start()
        else:
            self.router = None

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
        self.title = build_title(self.state_machine.flap_gate.state, self.last_classification)

    def status_snapshot(self) -> str:
        """What the console's `:status` shows. Read live off the state machine
        for the same reason the title is (see status.py): the gate's current
        state is the truth, and "last report" goes stale the moment the network
        recovers, because recovery produces no report.
        """
        return build_status_report(
            flap_state=self.state_machine.flap_gate.state,
            last_classification=self.last_classification,
            last_report_path=self.last_report_path,
            last_tick_error=self.last_tick_error,
            poll_interval_seconds=self.config.get("poll_interval_seconds"),
            domains=anchor_domains(self.config),
        )

    @rumps.clicked("Open console")
    def open_console(self, _sender):
        if self.console is None:
            self.console = ConsoleWindowController(status=self.status_snapshot)
        self.console.show()

    @rumps.clicked("Open last report")
    def open_last_report(self, _sender):
        if self.last_report_path:
            # as_uri() percent-encodes: the default reports_dir sits under
            # "Application Support", and a raw space makes an invalid file URL.
            webbrowser.open(pathlib.Path(self.last_report_path).as_uri())
        else:
            rumps.notification("Net/DNS Monitor", "", "No report has been generated yet.")




    @rumps.clicked("Router", "Configure...")
    def configure_router(self, _sender):
        import subprocess
        config_path = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")
        subprocess.run(["open", "-t", config_path], check=False)

    @rumps.clicked("Router", "Start")
    def start_router(self, _sender):
        if self.router: self.router.start()

    @rumps.clicked("Router", "Stop")
    def stop_router(self, _sender):
        if self.router: self.router.stop()

    @rumps.clicked("Router", "List Interfaces")
    def list_interfaces(self, _sender):
        import subprocess
        output = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
        rumps.alert(title="Network Interfaces", message=output)

    @rumps.clicked("Router", "Troubleshoot")
    def troubleshoot_router(self, _sender):
        import subprocess
        try:
            pf_out = subprocess.check_output(["sudo", "pfctl", "-s", "nat"], text=True)
            ip_fwd = subprocess.check_output(["sysctl", "net.inet.ip.forwarding"], text=True)
            is_bootpd = "bootpd" in subprocess.check_output(["ps", "aux"], text=True)
            status = f"IP Forwarding: {ip_fwd}\nNAT Rules:\n{pf_out}\nDHCP Server Running: {is_bootpd}"
            rumps.alert(title="Router Diagnostics", message=status)
        except Exception as e:
            rumps.alert(title="Router Diagnostics Error", message=f"Need sudo for full diagnostics.\n{e}")

    @rumps.clicked("Start at Login")
    def toggle_login(self, sender):
        import os, plistlib
        agent_dir = os.path.expanduser("~/Library/LaunchAgents")
        os.makedirs(agent_dir, exist_ok=True)
        plist_path = os.path.join(agent_dir, "com.netdnsmonitor.plist")
        sender.state = not sender.state
        
        if sender.state:
            plist_data = {
                "Label": "com.netdnsmonitor",
                "ProgramArguments": [
                    "/bin/bash", "-c",
                    "cd /Users/mitch.hudson/dev/net-dns-monitor && /Users/mitch.hudson/dev/net-dns-monitor/.venv/bin/python -m netdnsmonitor.app"
                ],
                "RunAtLoad": True,
                "KeepAlive": False
            }
            with open(plist_path, "wb") as f:
                plistlib.dump(plist_data, f)
        else:
            if os.path.exists(plist_path):
                os.remove(plist_path)

def main():
    NetDnsMonitorApp().run()


if __name__ == "__main__":
    main()
