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
import socket as socket_module
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from typing import Callable, Optional

import rumps

from netdnsmonitor import alert, forensic_log, peer_net
from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.classifier import classify
from netdnsmonitor.config import load_config
from netdnsmonitor.dashboard import (
    DashboardWindow,
    dashboard_sections,
    install_main_menu,
    render_dashboard_text,
)
from netdnsmonitor.dock_icon import set_dock_icon
from netdnsmonitor.forensic_log import ForensicRecorder
from netdnsmonitor.history import SampleHistory
from netdnsmonitor.ladder import ladder_for, step_by_name
from netdnsmonitor.localize import localize
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.mini_window import MiniWindow, mini_text
from netdnsmonitor.net_stats import ThroughputMeter, read_interface_counters
from netdnsmonitor.peer_net import PeerNetwork
from netdnsmonitor.peers import PeerRegistry, load_record, save_record
from netdnsmonitor.ping import ping_once
from netdnsmonitor.ping_monitor import PingMonitor
from netdnsmonitor.prober import make_prober
from netdnsmonitor.query_log import extract_top_domains, make_query_log_reader
from netdnsmonitor.repair_executor import make_repair_executor
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.resolution_log import append_resolution_findings
from netdnsmonitor.resolution_prober import resolve_domains_parallel
from netdnsmonitor.settings_window import SettingsWindow, collect, restart_note, save_config
from netdnsmonitor.stall_log import select_stalled_domains
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import STATS_UNKNOWN, build_title, format_stats, status_state

OPEN_BIN = "/usr/bin/open"

# How many of the most-queried names the prewarm button resolves.
PREWARM_LIMIT = 50

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
        self._ping_failures_this_episode = 0

        self.forensic = ForensicRecorder(
            journal_path=self.config["forensic_log_path"],
            episodes_dir=self.config["forensic_episodes_dir"],
        )
        # Created on first open, never here: eleven tests construct this class
        # directly and would each pop a window.
        self._dashboard: Optional[DashboardWindow] = None
        self._dashboard_text = ""
        # Retained: an unretained notification observer token is deallocated and
        # the block then silently never fires.
        self._activation_observer = None
        self._main_menu_target = None
        self._opening_dashboard = False
        self._action_thread: Optional[threading.Thread] = None
        self._action_results: queue.Queue = queue.Queue()
        self._last_flap_state = "healthy"

        # A fresh id per process. Two instances on one machine are genuinely two
        # instances, and a hostname is not unique enough to key on.
        self.instance_id = uuid.uuid4().hex[:16]
        self.peer_registry = PeerRegistry(
            self_id=self.instance_id,
            current_seconds=self.config["peer_current_seconds"],
            recent_seconds=self.config["peer_recent_seconds"],
        )
        # Loading the previous run's record here is what makes "try to connect to
        # them on startup" possible -- otherwise a fresh process knows nobody
        # until somebody else happens to announce.
        self.peer_registry.load(load_record(self.config["peer_record_path"]))
        self.peer_network: Optional[PeerNetwork] = None
        self._peers_dirty = True

        self.history = SampleHistory(
            path=self.config["history_path"],
            max_samples=self.config["history_max_samples"],
        )
        self.history.load()
        # The most recent peer-assisted fault verdict, and the deadline for
        # computing the next one. See _begin_localization.
        self.fault_verdict: Optional[dict] = None
        self._localize_due_at: Optional[float] = None
        # Same lazy rule as the dashboard: built on first use, never in __init__.
        self._mini: Optional[MiniWindow] = None
        # See _refresh_dock_icon: the Dock call is expensive, so it is rate-limited
        # except when the status itself changes.
        self._dock_state = "healthy"
        self._dock_updated_at = 0.0
        self._settings: Optional[SettingsWindow] = None
        self.config_path = config_path

        self.menu = [
            "Open dashboard",
            "Toggle mini window",
            "Open last report",
            "Test network alert",
        ]
        self.timer = rumps.Timer(self.tick, self.config["poll_interval_seconds"])
        self.timer.start()
        self.resolution_timer = rumps.Timer(
            self.resolution_tick, self.config["resolution_interval_seconds"]
        )
        self.resolution_timer.start()
        self.ping_timer = rumps.Timer(self.ping_tick, self.config["ping_interval_seconds"])
        self.ping_timer.start()
        self.ui_timer = rumps.Timer(self.ui_tick, self.config["ui_refresh_seconds"])
        self.ui_timer.start()
        self.peer_timer = rumps.Timer(self.peer_tick, self.config["peer_announce_seconds"])
        self.peer_timer.start()
        # Runs once, then stops itself. Everything in it needs a live
        # NSApplication and a turning run loop, and none of it may happen in
        # __init__ where the tests would each get a window.
        self.launch_timer = rumps.Timer(self.launch_tick, 1)
        self.launch_timer.start()
        set_dock_icon("healthy")

    # --- launch-time UI setup ----------------------------------------------

    def launch_tick(self, _sender=None):
        """One-shot: give the app a real application menu, start watching for
        activation, and open the window if configured to.
        """
        self.launch_timer.stop()
        try:
            self._main_menu_target = install_main_menu(self.handle_dashboard_action)
        except Exception:  # noqa: BLE001 - a missing menu must not stop the monitor
            traceback.print_exc()
        self._install_activation_observer()
        if self.config["open_dashboard_at_launch"]:
            # activate=False: ordered front without stealing focus at login.
            self.open_dashboard(activate=False)

    def _install_activation_observer(self):
        """Open the dashboard when the app is brought to the front.

        This is what makes clicking the Dock icon do something. macOS asks the
        application delegate (`applicationShouldHandleReopen:`), which rumps does
        not implement, so a Dock click on an app owning no windows activated it
        and nothing else happened -- exactly the reported symptom.

        Observing NSApplicationDidBecomeActiveNotification instead of subclassing
        rumps' delegate keeps this out of rumps' internals. Note the notification
        does NOT fire when the app is already frontmost; the application menu item
        covers that case.
        """
        try:
            import AppKit
            from Foundation import NSNotificationCenter

            self._activation_observer = (
                NSNotificationCenter.defaultCenter().addObserverForName_object_queue_usingBlock_(
                    AppKit.NSApplicationDidBecomeActiveNotification,
                    None,
                    None,  # posting thread, i.e. the main thread
                    self._on_app_activated,
                )
            )
        except Exception:  # noqa: BLE001 - the menu item still works without it
            traceback.print_exc()

    def _on_app_activated(self, _notification):
        # show() activates the app, which can re-post this notification. The
        # guard is released in a finally so an exception in between cannot leave
        # it stuck on -- that would silently disable the Dock click for the rest
        # of the process's life.
        if self._opening_dashboard:
            return
        self._opening_dashboard = True
        try:
            self.open_dashboard()
        except Exception:  # noqa: BLE001 - never raise into an AppKit callback
            traceback.print_exc()
        finally:
            self._opening_dashboard = False

    # --- LAN peer discovery ------------------------------------------------

    def peer_tick(self, _sender=None):
        """Announce, heartbeat every known peer, and persist the record.

        Starts discovery on the first tick rather than in `__init__`: binding a
        socket and spawning a reader thread there would do both in every test that
        constructs this class, and doing it from a timer keeps launch itself free
        of any network work at all -- the requirement was that startup not block.
        """
        if not self.config["peer_discovery_enabled"]:
            return
        if self.peer_network is None and not self._start_peer_network():
            return

        # Announce first, so a peer that has just come up learns about us in the
        # same sweep it would otherwise be probed in.
        self.peer_network.announce()
        # Every bucket, not just the live ones: a machine last seen yesterday is
        # exactly the one worth probing.
        self.peer_network.probe(self.peer_registry.addresses_to_probe())
        self._save_peer_record()

    def _start_peer_network(self) -> bool:
        network = PeerNetwork(
            registry=self.peer_registry,
            host=socket_module.gethostname(),
            bind_port=self.config["peer_port"],
            status_fn=self._peer_status,
            # Looked up on the module rather than taken as a default argument, so
            # the tests can substitute loopback and never broadcast onto a real
            # network from a test run.
            broadcast_fn=peer_net.broadcast_addresses,
            on_change=self._mark_peers_dirty,
            state_fn=self._peer_state,
        )
        if not network.start():
            # Deliberately not fatal and not retried on a tighter loop: a monitor
            # that will not run because a discovery socket was busy has its
            # priorities backwards. The next tick tries again.
            print(
                f"[peers] discovery unavailable: {network.start_error}",
                file=sys.stderr,
                flush=True,
            )
            return False
        self.peer_network = network
        return True

    def _peer_status(self) -> str:
        """What we advertise about ourselves: the same three-state decision the
        menu bar shows, and nothing else.
        """
        flap_gate = self.state_machine.flap_gate
        return status_state(
            flap_gate.state, flap_gate.consecutive_failures, self.ping_stats["down"]
        )

    def _peer_state(self) -> dict:
        """What we tell peers about our own connectivity.

        Taken from the anti-flap gate's last probe rather than re-probed: a fresh
        probe seconds later can disagree with the one the gate acted on, and a peer
        would then be localizing a different event from the one we reported.
        """
        probe = getattr(self.state_machine, "last_probe", None) or {}
        return {
            "external_reachable": probe.get("external_reachable"),
            "dns_ok": probe.get("dns_ok"),
        }

    def _mark_peers_dirty(self):
        """Called from the listener thread -- so it only sets a flag. The record
        file is written and the window repainted from the main thread.
        """
        self._peers_dirty = True

    def _save_peer_record(self):
        save_record(self.peer_registry, self.config["peer_record_path"])
        self._peers_dirty = False

    def tick(self, _sender=None):
        report = self.state_machine.tick()
        if report is not None:
            paths = save_report(report, self.config["reports_dir"])
            self.last_report_path = paths["markdown_path"]
            self.last_classification = report["classification"]
            self._record_incident_forensics(report)
        self._note_gate_recovery()
        self._refresh_title()

    # --- forensic record ---------------------------------------------------

    def _record_incident_forensics(self, report: dict):
        """Fold a declared incident into the open episode.

        The state machine stays ignorant of forensics -- it returns a report and
        this translates it -- which keeps its orchestration logic testable
        without a recorder.
        """
        classification = report.get("classification", "unknown")
        self.forensic.note(
            forensic_log.DOWN,
            "flap_gate",
            reason=(
                f"{self.config['failure_threshold']} consecutive failed probes; "
                f"classified as {classification}"
            ),
            detail=f"probe results: {report.get('probe_results')}",
            result=f"{classification} incident declared",
        )
        for step in report.get("ladder_results") or []:
            self.forensic.note(
                forensic_log.STEP,
                "flap_gate",
                detail=step.get("name", "?"),
                reason=step.get("reason", ""),
                result=step.get("outcome", ""),
            )
        self.forensic.note(
            forensic_log.RECHECK,
            "flap_gate",
            reason="Re-probe after the ladder, so 'repaired' means something was measured",
            result="healthy again" if report.get("recheck_ok") else "still failing",
        )
        escalation = report.get("escalation")
        if escalation:
            self.forensic.note(
                forensic_log.ESCALATION,
                "flap_gate",
                reason="The ladder ran and the recheck still failed",
                result=str(escalation.get("error") or "analysis received from Claude"),
            )

    def _network_is_up(self) -> bool:
        """Both detectors have to agree before an episode closes.

        A DNS incident can be declared while ICMP to the ping host still answers
        perfectly, so closing on ping recovery alone would leave a gate-opened
        episode open forever.
        """
        return not self.ping_stats["down"] and self.state_machine.flap_gate.state != "incident"

    def _note_gate_recovery(self):
        """The gate clears an incident silently -- that transition produces no
        report at all (see status.py) -- so it has to be watched for here.
        """
        state = self.state_machine.flap_gate.state
        was = self._last_flap_state
        self._last_flap_state = state
        if was == "incident" and state != "incident" and self._network_is_up():
            self.forensic.note(
                forensic_log.UP,
                "flap_gate",
                reason=f"{self.config['success_threshold']} consecutive healthy probes",
                result="incident cleared",
            )

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
            if snapshot["down"]:
                self._ping_failures_this_episode = snapshot["consecutive_failures"]
            self.history.record(
                rtt_ms=snapshot["rtt_ms"],
                loss_pct=snapshot["loss_pct"],
                down_bps=down_bps,
                up_bps=up_bps,
                down=snapshot["down"],
            )
            if snapshot["alert"]:
                alert.network_failed(host, error=snapshot["error"])
                # Ask the peers while it is actually happening.
                self._begin_localization()
                self.forensic.note(
                    forensic_log.DOWN,
                    "ping",
                    reason=(
                        f"{snapshot['consecutive_failures']} consecutive failed ping(s) to "
                        f"{host}, threshold is {self.config['ping_failure_threshold']}"
                    ),
                    detail=f"ping {host}",
                    result=snapshot["error"] or "no reply",
                )
            elif was_down and not snapshot["down"]:
                alert.network_recovered(host)
                if self._network_is_up():
                    self.forensic.note(
                        forensic_log.UP,
                        "ping",
                        reason="Pings answered again",
                        detail=f"ping {host}",
                        result=(
                            f"reply in {snapshot['rtt_ms']:.0f}ms after "
                            f"{self._ping_failures_this_episode} failed ping(s)"
                            if snapshot["rtt_ms"] is not None
                            else "reply received"
                        ),
                    )
                self._ping_failures_this_episode = 0

        if drained:
            self._refresh_title()

    def _refresh_dock_icon(self, state: str, rtt_ms, ping_down: bool):
        """Repaint the Dock tile, but not on every heartbeat.

        `setApplicationIconImage_` is synchronous and costs ~2 seconds per call
        (measured), on the main thread. Called every 5-second heartbeat -- which is
        what the round-trip number changing means -- that would block the run loop
        for a large fraction of every cycle and starve the other three timers.

        So: a status change goes through immediately, because that is the urgent
        and rare case, and a change to the number alone waits for
        `dock_refresh_seconds`. dock_icon.set_dock_icon additionally skips
        identical content, so a quiet network costs nothing at all.
        """
        now = time.monotonic()
        status_changed = state != self._dock_state
        if not status_changed and now - self._dock_updated_at < self.config["dock_refresh_seconds"]:
            return
        set_dock_icon(state, rtt_ms=rtt_ms, ping_down=ping_down)
        self._dock_state = state
        self._dock_updated_at = now

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
        self._refresh_dock_icon(
            status_state(flap_gate.state, flap_gate.consecutive_failures, ping_down),
            ping["rtt_ms"],
            ping_down,
        )

    # --- peer-assisted fault localization ----------------------------------

    def _begin_localization(self):
        """An outage just started: ask every known peer, right now.

        Deliberately not waiting for the 5-minute sweep. The whole value of a peer
        here is what it sees *during* the outage; a reading from four minutes ago
        answers a different question.

        The verdict is computed a few seconds later rather than immediately,
        because pongs arrive asynchronously on the listener thread -- see
        _finish_localization_if_due.
        """
        if not self.config["peer_discovery_enabled"] or self.peer_network is None:
            return
        self.peer_network.probe(self.peer_registry.addresses_to_probe())
        self._localize_due_at = time.monotonic() + self.config["peer_probe_wait_seconds"]

    def _finish_localization_if_due(self):
        """Main thread. Compute and record the verdict once pongs have had time to
        arrive.
        """
        if self._localize_due_at is None or time.monotonic() < self._localize_due_at:
            return
        self._localize_due_at = None

        probe = getattr(self.state_machine, "last_probe", None) or {}
        # A fresh window rather than the `current` bucket: mid-outage the question
        # is whether a peer answered in the last few seconds, and a peer last heard
        # from nine minutes ago is still `current` while telling you nothing.
        fresh = max(self.config["peer_probe_wait_seconds"] * 3, 15)
        verdict = localize(
            our_external_reachable=probe.get("external_reachable"),
            our_dns_ok=probe.get("dns_ok"),
            peers=self.peer_registry.localization_view(fresh_seconds=fresh),
        )
        self.fault_verdict = verdict
        self.forensic.note(
            forensic_log.OBSERVATION,
            "peers",
            detail=f"fault localization: {verdict['summary']}",
            reason=verdict["reason"],
            result=f"{verdict['verdict']} (confidence {verdict['confidence']}); "
            f"evidence {verdict['evidence']}",
        )

    # --- dashboard window --------------------------------------------------

    def ui_tick(self, _sender=None):
        """Repaint the window and collect any finished troubleshooting step.

        Its own timer, at 1s, rather than riding the 5s heartbeat: a button whose
        result appears up to five seconds later feels broken. While the window is
        closed this costs a queue poll and a string comparison.
        """
        self._drain_action_results()
        self._finish_localization_if_due()
        self._refresh_mini()
        if self._peers_dirty:
            # A peer was heard from on the listener thread. Persisting from here
            # keeps all file writing on the main thread.
            self._save_peer_record()
        self._refresh_dashboard()

    def _ensure_dashboard(self) -> DashboardWindow:
        if self._dashboard is None:
            # Retained on the instance. An NSWindow with no strong Python
            # reference is collected out from under AppKit, which looks exactly
            # like the window never opening.
            self._dashboard = DashboardWindow(on_action=self.handle_dashboard_action)
        return self._dashboard

    def open_dashboard(self, _sender=None, activate: bool = True):
        dashboard = self._ensure_dashboard()
        self._refresh_dashboard(force=True)
        dashboard.show(activate=activate)

    def open_settings(self):
        if self._settings is None:
            self._settings = SettingsWindow(on_save=self._save_settings)
        self._settings.load(self.config)
        self._settings.show()

    def _save_settings(self, values: Optional[dict]) -> str:
        """Parse, write, and report. Called from the window's Save button.

        `None` means Reload: re-read the file from disk and repopulate, which is
        how someone backs out of edits they have not saved.

        Deliberately does NOT reconfigure the running app beyond `self.config`.
        Most of these are read once in __init__ -- timer intervals, thresholds,
        the peer windows -- and half-applying them would leave the app in a state
        that matches neither the file nor a fresh start. The message says which
        need a restart.
        """
        if values is None:
            self.config = load_config(self.config_path)
            if self._settings is not None:
                self._settings.load(self.config)
            return "Reloaded from disk."

        updates = collect(values)  # raises ValueError, which the window reports
        result = save_config(self.config_path, updates)
        self.config = load_config(self.config_path)
        note = restart_note(updates)
        if result["backup"]:
            note += f"\nPrevious config saved as {os.path.basename(result['backup'])}"
        return note

    def toggle_mini_window(self):
        """Collapse to the glanceable panel, or put it away."""
        if self._mini is not None and self._mini.is_visible():
            self._mini.hide()
            return
        if self._mini is None:
            self._mini = MiniWindow()
        self._refresh_mini()
        self._mini.show()

    def _refresh_mini(self):
        # Runs every second for the life of the process, so it returns
        # immediately until the panel has been built at least once. It does keep
        # refreshing a hidden panel: formatting one short string is cheaper than
        # tracking visibility, and it means the text is already correct the
        # instant it is shown rather than a second stale.
        if self._mini is None:
            return
        flap_gate = self.state_machine.flap_gate
        ping = self.ping_stats
        self._mini.set_text(
            mini_text(
                status_state(flap_gate.state, flap_gate.consecutive_failures, ping["down"]),
                rtt_ms=ping["rtt_ms"],
                loss_pct=ping["loss_pct"],
            )
        )

    def _refresh_dashboard(self, force: bool = False):
        if self._dashboard is None:
            return
        flap_gate = self.state_machine.flap_gate
        episode = self.forensic.episode
        text = render_dashboard_text(
            dashboard_sections(
                ping_stats=self.ping_stats,
                flap_state=flap_gate.state,
                consecutive_failures=flap_gate.consecutive_failures,
                config=self.config,
                last_classification=self.last_classification,
                last_report_path=self.last_report_path,
                resolution_findings=self.last_resolution_findings,
                episode_open=self.forensic.is_open,
                episode_started_at=episode.get("started_at") if episode else None,
                peers=self.peer_registry.buckets()
                if self.config["peer_discovery_enabled"]
                else None,
                fault_verdict=self.fault_verdict,
            )
        )
        # Only push when something changed: setString_ resets the pane's scroll
        # position, and at 1s that would fight anyone reading it.
        if force or text != self._dashboard_text:
            self._dashboard_text = text
            self._dashboard.set_stats(text)
            # Re-rendered alongside the text, so the numbers and the lines always
            # describe the same moment.
            self._dashboard.set_graphs(
                {field: self.history.series(field) for field in ("rtt_ms", "down_bps", "up_bps")}
            )

    def handle_dashboard_action(self, action_id: str):
        """A button was clicked. Main thread.

        Anything that shells out goes to a worker: repair_executor allows 5s per
        step and a full ladder is four of them, so running inline would freeze the
        window and all four timers for up to half a minute -- the same reason the
        ping does not run here.
        """
        if action_id == "open_settings":
            self.open_settings()
            return
        if action_id == "toggle_mini":
            self.toggle_mini_window()
            return
        if action_id == "open_dashboard":
            # The application menu dispatches through here too. Without this the
            # id falls through to the ladder-step branch and reports "Unknown
            # step" into a window that isn't open yet -- a menu item that looks
            # wired and does nothing, which is the whole bug class this fixes.
            self.open_dashboard()
            return
        if action_id == "open_last_report":
            self.open_last_report(None)
            return
        if action_id == "open_forensic_dir":
            self._open_path(self.config["forensic_episodes_dir"], make_dir=True)
            return
        if action_id == "test_alert":
            self.test_network_alert(None)
            self._append_output("Fired a test alert: the Dock should bounce.\n")
            return

        if self._action_thread is not None and self._action_thread.is_alive():
            self._append_output("Still running the previous step -- ignored.\n")
            return

        self._append_output(f"\n>>> {action_id}\n")
        self._action_thread = threading.Thread(
            target=self._run_action, args=(action_id,), name="dashboard-action", daemon=True
        )
        self._action_thread.start()

    def _run_action(self, action_id: str):
        """Worker thread. Produces text and forensic events; records neither.

        Deliberately does not touch the recorder or the window: the recorder's
        episode state is mutated by the main-thread ping drain, and AppKit views
        are not thread-safe. Everything comes back through the queue.
        """
        lines: list[str] = []
        events: list[dict] = []
        try:
            if action_id == "ping_now":
                result = ping_once(
                    self.config["ping_host"],
                    timeout_seconds=self.config["ping_timeout_seconds"],
                )
                rtt = result["rtt_ms"]
                lines.append(
                    f"ping {self.config['ping_host']}: "
                    + (f"reply in {rtt:.1f}ms" if result["ok"] and rtt is not None else "")
                    + ("" if result["ok"] else f"FAILED -- {result['error']}")
                )
            elif action_id == "prewarm_dns":
                lines.extend(self._prewarm_dns(events))
            elif action_id == "full_diagnosis":
                lines.extend(self._full_diagnosis(events))
            else:
                lines.extend(self._single_step(action_id, events))
        except Exception:  # noqa: BLE001 - a click must not kill the app
            traceback.print_exc()
            lines.append("This step raised; see the app log for the traceback.")

        self._action_results.put((action_id, "\n".join(lines) + "\n", events))

    def _single_step(self, action_id: str, events: list) -> list:
        step = step_by_name(action_id)
        if step is None:
            return [f"Unknown step {action_id!r}."]
        outcome = self.state_machine.repair_executor(step)
        events.append({"detail": step.name, "reason": step.reason, "result": outcome})
        return [f"why: {step.reason}", f"result: {outcome}"]

    def _prewarm_dns(self, events: list) -> list:
        """Resolve the 50 most-queried names so their answers are already cached.

        Reuses the query-log miner that the resolution monitor retired: reading
        the top-N busiest domains was the wrong basis for deciding *which domains
        to watch* (see stall_log.py), but it is exactly the right basis for
        deciding which answers are worth having warm.

        Worker thread only. `log show --last 1h` can take several seconds and
        return a lot of text, and 50 getaddrinfo calls follow it.
        """
        reader = make_query_log_reader(lookback=self.config["log_lookback"])
        domains = extract_top_domains(reader(), limit=PREWARM_LIMIT)
        if not domains:
            return [
                "No queried domains found in the log. Either nothing has resolved "
                "recently, or reading the unified log needs permission -- the same "
                "permission the incident log watcher uses."
            ]

        findings = resolve_domains_parallel(
            domains,
            timeout=self.config["resolution_timeout_seconds"],
            max_workers=self.config["resolution_max_workers"],
            deadline_seconds=self.config["resolution_batch_deadline_seconds"],
        )
        resolved = sum(1 for f in findings if f.get("resolved"))
        slowest = sorted(
            (f for f in findings if f.get("elapsed_seconds") is not None),
            key=lambda f: f["elapsed_seconds"],
            reverse=True,
        )[:5]

        lines = [f"prewarmed {resolved}/{len(findings)} of the top {len(domains)} queried names"]
        failed = [f["domain"] for f in findings if not f.get("resolved")]
        if failed:
            lines.append(f"did not resolve: {', '.join(failed[:10])}")
        if slowest:
            lines.append("slowest:")
            lines.extend(f"    {f['domain']} {f['elapsed_seconds']:.2f}s" for f in slowest)
        events.append(
            {
                "detail": f"prewarm_dns ({len(domains)} names)",
                "reason": "Resolve the most-queried names so their answers are "
                "already cached when something asks for them.",
                "result": f"{resolved}/{len(findings)} resolved",
            }
        )
        return lines

    def _full_diagnosis(self, events: list) -> list:
        probe = self.state_machine.prober()
        classification = classify(probe.get("external_reachable"), probe.get("dns_ok"))
        lines = [
            f"probe: {probe}",
            f"classified as: {classification.value}",
        ]
        steps = ladder_for(classification)
        if not steps:
            lines.append(
                "No ladder for this classification -- nothing is broken, or "
                "`domains` is empty so DNS could not be judged."
            )
            return lines
        for step in steps:
            outcome = self.state_machine.repair_executor(step)
            lines.append(f"[{step.kind}] {step.name}")
            lines.append(f"    why: {step.reason}")
            lines.append(f"    result: {outcome}")
            events.append({"detail": step.name, "reason": step.reason, "result": outcome})
        return lines

    def _drain_action_results(self):
        """Main thread: append output and record the forensic events."""
        while True:
            try:
                _action_id, text, events = self._action_results.get_nowait()
            except queue.Empty:
                return
            for event in events:
                self.forensic.note(
                    forensic_log.STEP,
                    "manual",
                    detail=event["detail"],
                    reason=event["reason"],
                    result=event["result"],
                )
            self._append_output(text)

    def _append_output(self, text: str):
        if self._dashboard is not None:
            self._dashboard.append_output(text)

    def _open_path(self, path: str, make_dir: bool = False):
        """Hand a path to Finder. Absolute /usr/bin/open for explicitness; see ping.py."""
        try:
            if make_dir:
                os.makedirs(path, exist_ok=True)
            subprocess.run([OPEN_BIN, path], check=False, timeout=10)
        except (subprocess.SubprocessError, OSError):
            traceback.print_exc()

    # --- menu --------------------------------------------------------------

    @rumps.clicked("Open dashboard")
    def open_dashboard_clicked(self, sender):
        self.open_dashboard(sender)

    @rumps.clicked("Toggle mini window")
    def toggle_mini_window_clicked(self, _sender):
        self.toggle_mini_window()

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
