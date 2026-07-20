"""Menu bar shell. Every decision (classification, ladder, anti-flap,
escalation gate, redaction, report contents) lives in already-tested modules;
this file only wires them to a rumps timer and a status-item title.
"""

import os
import webbrowser
from typing import Callable

import rumps

from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.config import load_config
from netdnsmonitor.dock_icon import set_dock_icon
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.prober import make_prober
from netdnsmonitor.query_log import extract_top_domains, make_query_log_reader
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.resolution_log import append_resolution_findings
from netdnsmonitor.resolution_prober import resolve_domains_parallel
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import NETWORK_GLYPH, build_title, status_state

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")
DISPLAY_NAME = "Net-DNS-Monitor"


def set_app_display_name(name: str) -> None:
    """Without a real .app bundle, macOS shows the bare interpreter's
    default name ("Python") in several places, each sourced differently:
    CFBundleName drives the bold app-menu title, while NSProcessInfo's
    processName is what the Dock tooltip, Force Quit, and Activity Monitor
    actually read -- overriding only one leaves "Python" showing in the
    other (confirmed empirically: the Dock tooltip still said "Python"
    after the CFBundleName-only fix). Cosmetic only, so a failure here
    must never take the monitor down with it.
    """
    try:
        from Foundation import NSBundle, NSProcessInfo

        NSBundle.mainBundle().infoDictionary()["CFBundleName"] = name
        NSProcessInfo.processInfo().setProcessName_(name)
    except Exception:  # noqa: BLE001 - cosmetic, never fatal
        pass


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


def build_resolution_job(config: dict) -> Callable[[], list[dict]]:
    """Returns a callable that mines the local DNS query log for the top
    `resolution_top_n` queried domains, resolves each in parallel, and
    appends the outcome to the resolution log -- the 5-minute cadence job,
    separate from the incident-detection poll loop above.
    """
    query_log_reader = make_query_log_reader(lookback=config["resolution_lookback"])

    def job() -> list[dict]:
        domains = extract_top_domains(query_log_reader(), limit=config["resolution_top_n"])
        findings = resolve_domains_parallel(
            domains,
            timeout=config["resolution_timeout_seconds"],
            max_workers=config["resolution_max_workers"],
        )
        append_resolution_findings(findings, config["resolution_log_path"])
        return findings

    return job


class NetDnsMonitorApp(rumps.App):
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        set_app_display_name(DISPLAY_NAME)
        super().__init__(name=DISPLAY_NAME, title=f"{NETWORK_GLYPH} Net/DNS: starting...")
        self.config = load_config(config_path)
        self.state_machine = build_state_machine(self.config)
        self.resolution_job = build_resolution_job(self.config)
        self.last_classification = None
        self.last_report_path = None
        self.last_resolution_findings: list[dict] = []
        self.menu = ["Open last report"]
        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()
        self.resolution_timer = rumps.Timer(
            self.resolution_tick, self.config["resolution_interval_seconds"]
        )
        self.resolution_timer.start()
        set_dock_icon("healthy")

    def tick(self, _sender=None):
        report = self.state_machine.tick()
        if report is not None:
            paths = save_report(report, self.config["reports_dir"])
            self.last_report_path = paths["markdown_path"]
            self.last_classification = report["classification"]
        self._refresh_title()

    def resolution_tick(self, _sender=None):
        self.last_resolution_findings = self.resolution_job()
        self._refresh_title()

    def _refresh_title(self):
        resolution_failed = resolution_total = None
        if self.last_resolution_findings:
            resolution_total = len(self.last_resolution_findings)
            resolution_failed = sum(
                1 for finding in self.last_resolution_findings if not finding["resolved"]
            )
        flap_gate = self.state_machine.flap_gate
        self.title = build_title(
            flap_gate.state,
            self.last_classification,
            flap_gate.consecutive_failures,
            resolution_failed,
            resolution_total,
        )
        set_dock_icon(status_state(flap_gate.state, flap_gate.consecutive_failures))

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
