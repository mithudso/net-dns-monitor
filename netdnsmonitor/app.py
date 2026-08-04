"""Menu bar shell. Every decision (classification, ladder, anti-flap,
escalation gate, redaction, report contents, alerting policy) lives in
already-tested modules; this file only wires them to rumps timers and a
status-item title.

Three timers, three different cadences, and they are deliberately not merged:

  poll_interval_seconds (30)       incident detection. TCP reachability + DNS
                                   through the anti-flap gate; the only path
                                   that runs repairs, escalates, or writes a
                                   report.
  ping_interval_seconds (5)        liveness heartbeat. One ICMP ping plus a
                                   throughput reading; drives the menu bar
                                   stats, the Dock tile, and the alert.
  resolution_interval_seconds(300) the stalled-domain resolution batch.

The heartbeat is the fast one because an outage should be visible in seconds,
and it is cheap enough to run at that rate. Incident detection stays slow and
debounced because acting on it costs something -- flushed caches and API calls.
"""

import os
import queue
import threading
import time
import traceback
import webbrowser
from typing import Callable, Optional

import rumps

from netdnsmonitor import alert
from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.config import load_config
from netdnsmonitor.dock_icon import set_dock_icon
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.net_stats import ThroughputMeter, read_interface_counters
from netdnsmonitor.ping import ping_once
from netdnsmonitor.ping_monitor import PingMonitor
from netdnsmonitor.prober import make_prober
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.resolution_log import append_resolution_findings
from netdnsmonitor.resolution_prober import resolve_domains_parallel
from netdnsmonitor.stall_log import select_stalled_domains
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import STATS_UNKNOWN, build_title, format_stats, status_state

DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")
DISPLAY_NAME = "Net-DNS-Monitor"

NO_PING_YET = {
    "rtt_ms": None,
    "loss_pct": None,
    "down_bps": None,
    "up_bps": None,
    "down": False,
}


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
    """Returns a callable that reads back every domain that has ever stalled
    (per this machine's own resolution log), re-resolves them in parallel, and
    appends the outcome to that same log -- the 5-minute cadence job, separate
    from the incident-detection poll loop above.

    This replaces the previous "top-N busiest domains from the query log"
    selection. See `stall_log.py` for what counts as a stall and why the
    query-log mining path was retired.
    """

    def job() -> list[dict]:
        domains = select_stalled_domains(
            config["resolution_log_path"],
            stall_seconds=config["resolution_stall_seconds"],
        )
        findings = resolve_domains_parallel(
            domains,
            timeout=config["resolution_timeout_seconds"],
            max_workers=config["resolution_max_workers"],
            deadline_seconds=config["resolution_batch_deadline_seconds"],
        )
        append_resolution_findings(findings, config["resolution_log_path"])
        return findings

    return job


def build_ping_job(config: dict) -> Callable[[], tuple[dict, Optional[tuple[int, int]]]]:
    """One heartbeat's worth of work: ping, then read the interface counters.

    Both are subprocesses, which is why this runs on a worker thread rather
    than inline on the run loop -- see NetDnsMonitorApp.ping_tick.
    """

    def job() -> tuple[dict, Optional[tuple[int, int]]]:
        result = ping_once(
            config["ping_host"],
            timeout_seconds=config["ping_timeout_seconds"],
        )
        return result, read_interface_counters()

    return job


class NetDnsMonitorApp(rumps.App):
    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        set_app_display_name(DISPLAY_NAME)
        super().__init__(name=DISPLAY_NAME, title=f"{STATS_UNKNOWN} Net/DNS: starting...")
        self.config = load_config(config_path)
        self.state_machine = build_state_machine(self.config)
        self.resolution_job = build_resolution_job(self.config)
        self.ping_job = build_ping_job(self.config)
        self.last_classification = None
        self.last_report_path = None
        self.last_resolution_findings: list[dict] = []
        self._resolution_thread: Optional[threading.Thread] = None

        self.ping_monitor = PingMonitor(
            failure_threshold=self.config["ping_failure_threshold"],
            loss_window=self.config["ping_loss_window"],
            alert_repeat_seconds=self.config["ping_alert_repeat_seconds"],
        )
        self.throughput = ThroughputMeter()
        self.ping_stats = dict(NO_PING_YET)
        self._ping_thread: Optional[threading.Thread] = None
        # A queue, not a shared attribute: the drain below folds in every result
        # in order, so a cycle the main thread happens to miss cannot swallow a
        # failure edge and with it the alert.
        self._ping_results: queue.Queue = queue.Queue()

        self.menu = ["Open last report", "Test network alert"]
        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()
        self.resolution_timer = rumps.Timer(
            self.resolution_tick, self.config["resolution_interval_seconds"]
        )
        self.resolution_timer.start()
        self.ping_timer = rumps.Timer(self.ping_tick, self.config["ping_interval_seconds"])
        self.ping_timer.start()
        set_dock_icon("healthy")

    def tick(self, _sender=None):
        report = self.state_machine.tick()
        if report is not None:
            paths = save_report(report, self.config["reports_dir"])
            self.last_report_path = paths["markdown_path"]
            self.last_classification = report["classification"]
        self._refresh_title()

    def resolution_tick(self, _sender=None):
        """Runs the resolution batch on a worker thread, not the run loop.

        `getaddrinfo` is not interruptible and the stall list only grows, so a
        batch can outlast its own 5-minute cadence. Running it inline here (as
        this did previously) would block the run loop -- and with it the 30s
        incident tick, which is the app's primary job. If the previous batch is
        still going, skip this cycle rather than piling threads up.

        The worker deliberately does not touch the title: AppKit status-item
        updates are not thread-safe. The next incident tick picks the findings
        up and repaints on the main thread.
        """
        if self._resolution_thread is not None and self._resolution_thread.is_alive():
            return
        self._resolution_thread = threading.Thread(
            target=self._run_resolution, name="resolution-batch", daemon=True
        )
        self._resolution_thread.start()

    def _run_resolution(self):
        try:
            # Single attribute rebind, so the main thread only ever observes
            # the old list or the new one -- never a partially built one.
            self.last_resolution_findings = self.resolution_job()
        except Exception:  # noqa: BLE001 - a batch failure must surface, not die silently
            # Without this, a job that raises every cycle (an unwritable
            # resolution_log_path, say) leaves last_resolution_findings at its
            # initial [] forever. _refresh_title then renders no resolution
            # suffix at all -- visually identical to "every domain resolved
            # fine". The monitor would be dead and the menu bar would look
            # clean.
            traceback.print_exc()

    def ping_tick(self, _sender=None):
        """Fold in whatever the last heartbeat produced, then start the next one.

        Draining first and pinging second means the display trails the ping by
        one cadence (~5s). That is the same trade resolution_tick already makes
        and it buys the thing that matters: the ping itself never runs on the run
        loop. A failed ping takes about 3 seconds to give up (measured against an
        unroutable address), so doing it inline here would wedge the UI and both
        other timers for most of every cycle for the entire length of an outage.

        Alerting and repainting therefore both happen here, on the main thread,
        because AppKit status-item and Dock updates are not thread-safe.
        """
        self._drain_ping_results()

        if self._ping_thread is not None and self._ping_thread.is_alive():
            # A ping that outran its cadence. Skip rather than stack threads.
            return
        self._ping_thread = threading.Thread(
            target=self._run_ping, name="ping-heartbeat", daemon=True
        )
        self._ping_thread.start()

    def _run_ping(self):
        try:
            result, counters = self.ping_job()
            self._ping_results.put((result, counters, time.monotonic()))
        except Exception:  # noqa: BLE001 - must surface, not kill the heartbeat
            # ping_once and read_interface_counters both swallow their own
            # failures, so reaching here means something unforeseen. Without
            # this the heartbeat would stop for the rest of the process's life
            # while the menu bar kept displaying the last good reading.
            traceback.print_exc()

    def _drain_ping_results(self):
        """Main thread only. Every queued result is recorded in order, so the
        alert can't be missed; the last one drives what gets drawn.
        """
        drained = False
        while True:
            try:
                result, counters, at = self._ping_results.get_nowait()
            except queue.Empty:
                break
            drained = True
            was_down = self.ping_stats["down"]
            snapshot = self.ping_monitor.record(result, now=at)
            down_bps, up_bps = self.throughput.sample(counters, now=at)
            self.ping_stats = {
                "rtt_ms": snapshot["rtt_ms"],
                "loss_pct": snapshot["loss_pct"],
                "down_bps": down_bps,
                "up_bps": up_bps,
                "down": snapshot["down"],
            }
            host = self.config["ping_host"]
            if snapshot["alert"]:
                alert.network_failed(host, error=snapshot["error"])
            elif was_down and not snapshot["down"]:
                alert.network_recovered(host)

        if drained:
            self._refresh_title()

    def _refresh_title(self):
        # Snapshot once. The resolution worker rebinds this attribute
        # concurrently, and reading it three separate times (confirmed via
        # `dis`) lets one batch's total splice with a newer batch's failure
        # count -- rendering e.g. "7/2 resolution fails". The rebind itself is
        # atomic; a reader that reads three times is not.
        findings = self.last_resolution_findings
        resolution_failed = resolution_total = None
        if findings:
            resolution_total = len(findings)
            resolution_failed = sum(1 for finding in findings if not finding["resolved"])

        # Same reason, even though ping_stats is only rebound on this thread:
        # one read keeps the title and the Dock tile describing the same moment.
        ping = self.ping_stats
        ping_down = ping["down"]
        stats = format_stats(
            rtt_ms=ping["rtt_ms"],
            loss_pct=ping["loss_pct"],
            down_bps=ping["down_bps"],
            up_bps=ping["up_bps"],
            ping_down=ping_down,
        )

        flap_gate = self.state_machine.flap_gate
        self.title = build_title(
            flap_gate.state,
            self.last_classification,
            flap_gate.consecutive_failures,
            resolution_failed,
            resolution_total,
            stats=stats,
            ping_down=ping_down,
        )
        set_dock_icon(
            status_state(flap_gate.state, flap_gate.consecutive_failures, ping_down),
            rtt_ms=ping["rtt_ms"],
            ping_down=ping_down,
        )

    @rumps.clicked("Open last report")
    def open_last_report(self, _sender):
        if self.last_report_path:
            webbrowser.open(f"file://{self.last_report_path}")
        else:
            rumps.notification("Net/DNS Monitor", "", "No report has been generated yet.")

    @rumps.clicked("Test network alert")
    def test_network_alert(self, _sender):
        """Fire the alert on demand.

        Whether macOS actually draws a notification banner depends on
        notification authorisation for this bundle, which the process cannot
        observe from the inside. This makes that answerable in one click instead
        of by waiting for a real outage.
        """
        alert.network_failed(self.config["ping_host"], error="test alert, not a real outage")


def main():
    NetDnsMonitorApp().run()


if __name__ == "__main__":
    main()
