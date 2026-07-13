"""Menu bar shell. Every decision (classification, ladder, anti-flap,
escalation gate, redaction, report contents) lives in already-tested modules;
this file only wires them to a rumps timer and a status-item title.
"""

import os
import webbrowser

import rumps

from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.config import load_config
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.prober import make_prober
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import build_title, next_status

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")


def build_state_machine(config: dict) -> StateMachine:
    external_targets = [tuple(t) for t in config["external_targets"]]
    internal_targets = [tuple(t) for t in config["internal_targets"]]

    prober = make_prober(
        external_targets=external_targets,
        internal_targets=internal_targets,
        domains=config["domains"],
    )
    repair_executor = make_repair_executor()
    log_watcher = make_log_watcher(lookback=config["log_lookback"])

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
        self.status = "healthy"
        self.last_report_path = None
        self.menu = ["Open last report"]
        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()

    def tick(self, _sender=None):
        report = self.state_machine.tick()
        if report is not None:
            paths = save_report(report, self.config["reports_dir"])
            self.last_report_path = paths["markdown_path"]
        self.status = next_status(self.status, report)
        self.title = build_title(self.status, report)

    @rumps.clicked("Open last report")
    def open_last_report(self, _sender):
        if self.last_report_path:
            webbrowser.open(f"file://{self.last_report_path}")
        else:
            rumps.notification("Net/DNS Monitor", "", "No report has been generated yet.")


def main():
    NetDnsMonitorApp().run()


if __name__ == "__main__":
    main()
