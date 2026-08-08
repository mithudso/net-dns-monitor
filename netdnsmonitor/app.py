"""Menu bar shell. Every decision (classification, ladder, anti-flap,
escalation gate, redaction, report contents, alerting policy, domain
learning/pruning, notification formatting) lives in already-tested modules;
this file only wires them to rumps timers and a status-item title.

Six timers, six different cadences, deliberately not merged:

  poll_interval_seconds (30)       incident detection. TCP reachability + DNS
                                   through the anti-flap gate; the only path
                                   that runs repairs, escalates, or writes a
                                   report.
  ping_interval_seconds (5)        liveness heartbeat. One ICMP ping plus a
                                   throughput reading; drives the menu bar
                                   stats, the Dock tile, and the alert.
  resolution_interval_seconds(300) the stalled-domain resolution batch.
  ui_refresh_seconds (1)           repaint the window, drain worker queues.
  peer_announce_seconds (300)      announce to and heartbeat LAN peers.
  log_view_poll_seconds (30)       read the network parts of the unified log.

The heartbeat is the fast one because an outage should be visible in seconds,
and it is cheap enough to run at that rate. Incident detection stays slow and
debounced because acting on it costs something -- flushed caches and API calls.
The log poll is slow for the opposite reason to the heartbeat: nothing displayed
depends on it, and `log show` measured 1.4s per read.

Everything that shells out does so on a worker thread and returns through a
queue, because the run loop this all hangs off is also what draws the window.
"""

import getpass
import os
import pathlib
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

from netdnsmonitor import alert, forensic_log, peer_net, privileges, system_log
from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.classifier import classify
from netdnsmonitor.config import load_config
from netdnsmonitor.console_window import ConsoleWindowController
from netdnsmonitor.dashboard import (
    DashboardWindow,
    dashboard_sections,
    install_main_menu,
    render_dashboard_text,
)
from netdnsmonitor.dock_icon import set_dock_icon
from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    make_domain_learner,
    prune_dead_domains,
)
from netdnsmonitor.escalation import redact
from netdnsmonitor.forensic_log import ForensicRecorder
from netdnsmonitor.history import SampleHistory
from netdnsmonitor.ladder import ladder_for, step_by_name
from netdnsmonitor.localize import localize
from netdnsmonitor.log_watcher import make_log_watcher
from netdnsmonitor.mini_window import MiniWindow, mini_text
from netdnsmonitor.net_stats import ThroughputMeter, read_interface_counters
from netdnsmonitor.notifications import (
    format_notification,
    make_email_notifier,
    make_notifier,
    make_slack_notifier,
)
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
from netdnsmonitor.status import (
    STATS_UNKNOWN,
    build_status_report,
    build_title,
    format_stats,
    status_state,
)

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

    # The real privilege probes are passed in here rather than defaulted inside
    # make_repair_executor, so that every test constructing an executor with a fake
    # run_fn keeps describing an ungranted machine and runs no extra subprocesses.
    # `log_watcher` is already built above -- build_domains_source needs it to
    # feed the learner, so this no longer makes a second one.
    repair_executor = make_repair_executor(
        is_granted_fn=privileges.is_granted,
        primary_interface_fn=privileges.primary_interface,
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
        self.notifier = build_notifier(self.config)
        self.last_notification_results = None
        # Set by the tick guard below. Initialised here because `tick` only
        # assigns it on a failure, and `:status` reads it on every call.
        self.last_tick_error = None
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

        # --- system log viewer ---------------------------------------------
        # Held in memory only. The buffer de-duplicates, because the poll window
        # is longer than the poll interval on purpose (nothing falls in the gap
        # between two reads, so everything arrives about twice).
        self.log_buffer = system_log.LogBuffer(max_entries=self.config["log_view_max_entries"])
        self.log_reader = system_log.make_log_reader(
            timeout=self.config["log_view_timeout_seconds"]
        )
        # Runtime state, seeded from config: the button above the pane flips this,
        # and it decides both the predicate and what the pane shows.
        self.log_errors_only = self.config["log_view_errors_only"]
        self.log_error: Optional[str] = None
        self.new_log_errors = 0
        # Last text pushed to each view, so the 1s refresh only calls setString_
        # when something changed -- it resets the scroll position, which at 1s
        # would fight anyone reading the pane.
        self._log_pane_text = ""
        self._log_status_text = ""
        self._log_thread: Optional[threading.Thread] = None
        self._log_results: queue.Queue = queue.Queue()

        # --- elevated permissions ------------------------------------------
        # Cached rather than probed on every repaint: the check shells out to
        # `sudo -n -l`, and the window refreshes every second. Re-probed after a
        # grant or revoke, and once at launch.
        self.privileges_granted = False
        self.dhcp_interfaces: list[str] = []
        # What the installed grant covers, which is not the same set as the
        # interfaces the machine has -- see privileges.granted_interfaces.
        self.granted_interfaces: list[str] = []
        self.primary_dhcp_interface: Optional[str] = None
        # False until the launch probe has answered. Clicking Grant before then
        # would show a consent list built from an empty interface set.
        self.privileges_probed = False
        # Two handles, not one. They used to share `_privilege_thread`, so a Grant
        # click during the launch probe was refused with "Still working on the
        # previous permission change" -- and no permission change was in progress.
        self._privilege_status_thread: Optional[threading.Thread] = None
        self._privilege_thread: Optional[threading.Thread] = None
        self._privilege_results: queue.Queue = queue.Queue()

        # Built on first open, then kept. The controller owns the NSWindow, so a
        # controller that went out of scope would take the window with it -- and
        # keeping the one instance is also what makes the menu bar item and the
        # dashboard button the *same* console, sharing one cwd and one history
        # rather than opening two that silently disagree.
        self.console: Optional[ConsoleWindowController] = None

        self.menu = [
            "Open dashboard",
            "Open console",
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
        # Its own cadence again, and a slow one: this shells out to `log show`,
        # which measured 1.4s for a 1-minute window. Nothing about the network
        # display depends on it, so it is the one timer that can afford to be late.
        self.log_timer: Optional[rumps.Timer] = None
        if self.config["log_view_enabled"]:
            self.log_timer = rumps.Timer(self.log_tick, self.config["log_view_poll_seconds"])
            self.log_timer.start()
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
        # Backfill the log pane here rather than waiting for the first poll: at a
        # 30-second cadence the pane would otherwise sit empty for half a minute
        # after launch, which is exactly when someone is looking at it.
        self._start_log_read(self.config["log_view_backfill_window"], announce=False)
        self._refresh_privilege_status()
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
            #
            # Sent inline on the run loop, which this line's architecture note
            # otherwise forbids. It is bounded -- notify_timeout_seconds (5s)
            # per channel -- and by default there are no channels at all: Slack
            # needs SLACK_WEBHOOK_URL and email needs a non-empty
            # email_recipients, so the notifier is a no-op until someone
            # configures one. Worth moving to a worker if that stops being true.
            text = redact(
                format_notification(report, paths["markdown_path"]),
                self.config["sensitive_strings"],
            )
            self.last_notification_results = self.notifier(text)
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

    # --- system log viewer -------------------------------------------------

    def log_tick(self, _sender=None):
        """Fold in the last read, then start the next. Same shape as ping_tick.

        `log show` is a subprocess that measured 1.4s for a 1-minute window, so it
        cannot run on the run loop -- that would stall the 5-second heartbeat and
        the window for the duration of every poll.

        `ui_tick` drains the same queue every second, which is what actually gets a
        finished read on screen promptly; draining here as well keeps this method
        correct on its own terms if the UI timer is ever not the faster of the two.
        """
        self._drain_log_results()
        self._start_log_read(self.config["log_view_poll_window"])

    def _start_log_read(self, window: str, announce: bool = True) -> bool:
        """Kick a read on a worker thread, unless one is already running.

        Returns whether a read was actually started. Callers that announce a re-read
        have to check: this returns early when the viewer is switched off, and while
        a previous read is still running, and the buttons used to print "re-reading
        the last 1m" regardless -- so with `log_view_enabled: false` the controls
        claimed work that would never happen.

        Skipping rather than queueing, the same choice the ping and resolution
        workers make: a read that outran its cadence means the machine is busy,
        and stacking threads is the wrong response to that.

        `announce=False` for the launch backfill. Everything it returns is up to
        `log_view_backfill_window` old, so reporting it as new would be a lie in
        three places at once: the results pane would open with a burst of "new"
        errors from a quarter of an hour ago, the Monitor row would credit them to
        "reported since launch" when nothing was reported, and with
        `open_dashboard_at_launch: false` the count would climb while
        `_append_output` no-ops into a window that does not exist. History, not
        news.
        """
        if not self.config["log_view_enabled"]:
            return False
        if self._log_thread is not None and self._log_thread.is_alive():
            return False
        self._log_thread = threading.Thread(
            target=self._run_log_read,
            args=(window, announce),
            name="system-log-read",
            daemon=True,
        )
        self._log_thread.start()
        return True

    def _run_log_read(self, window: str, announce: bool = True):
        """Worker thread. Reads, parses, and hands the result over -- it touches
        neither the buffer nor any view, because both belong to the main thread.
        """
        try:
            result = dict(self.log_reader(window, self.log_errors_only))
            result["announce"] = announce
            self._log_results.put(result)
        except Exception:  # noqa: BLE001 - a failed read must not kill the poller
            # make_log_reader already turns every expected failure into an error
            # string, so reaching here is something unforeseen. Without this the
            # thread dies silently and the pane freezes at its last contents while
            # looking perfectly normal.
            traceback.print_exc()

    def _drain_log_results(self):
        """Main thread: store what is new, and report the new errors."""
        while True:
            try:
                result = self._log_results.get_nowait()
            except queue.Empty:
                return
            self.log_error = result["error"]
            added = self.log_buffer.add(result["entries"])
            # Stored either way -- the pane shows the backfill. Only the reporting
            # is suppressed; see _start_log_read.
            if result.get("announce", True):
                self._announce_new_log_errors(added)

    def _announce_new_log_errors(self, added: list):
        """Report new network errors from the system log without being asked.

        This is the automatic half of the feature, and the reason it exists: a log
        pane only helps someone already looking at it, and the point of a monitor
        is that nobody is. So new error and fault lines are also echoed into the
        results pane on the left, counted for the Monitor section, and -- while an
        outage episode is open -- written into that episode, so the forensic record
        includes what the OS itself said at the time rather than only what this app
        measured.

        Capped by `log_view_announce_limit`. The cap is on the announcement only;
        everything still lands in the log pane. Without it, one repeating message
        would push every manual troubleshooting result out of the results pane.
        """
        noise = tuple(self.config["log_view_noise_patterns"] or ())
        errors = [
            entry
            for entry in added
            if system_log.is_error(entry) and not system_log.is_noise(entry, noise)
        ]
        if not errors:
            return
        self.new_log_errors += len(errors)

        rows = system_log.coalesce(errors)
        limit = max(0, int(self.config["log_view_announce_limit"]))
        shown = rows[:limit]
        lines = [f"\n>>> system log: {len(errors)} new network error line(s)"]
        lines.extend("    " + system_log.format_entry(row) for row in shown)
        if len(rows) > len(shown):
            lines.append(f"    ...and {len(rows) - len(shown)} more -- see the log pane")
        self._append_output("\n".join(lines) + "\n")

        if self.forensic.is_open:
            # `rows`, not `shown`: log_view_announce_limit caps how much is printed
            # into the results pane, and an episode write-up that silently kept 3 of
            # 12 error lines would be evidence with a hole in it -- the "...and N
            # more" note goes to the pane, not to the episode.
            for row in rows:
                self.forensic.note(
                    forensic_log.OBSERVATION,
                    "system_log",
                    reason="macOS logged a network error while this episode was open",
                    # Truncated: a folded multi-line framework message can run to
                    # thousands of characters, and this lands in a markdown table.
                    detail=f"{row.get('process') or '?'}: {row.get('message', '')[:200]}",
                    result=f"{row.get('count', 1)}x, most recently {row.get('time', '')}",
                )

    def _refresh_log_pane(self, force: bool = False):
        """Re-filter and repaint the pane, from the search box's current contents.

        The box is read every refresh rather than mirrored onto this object, so the
        pane cannot disagree with what is typed in it. Both views are only pushed
        when their text changed -- `setString_` resets scroll position.
        """
        if self._dashboard is None:
            return
        # Same guard as _refresh_dashboard: LogBuffer.view() is a full filter-and-coalesce
        # pass over up to log_view_max_entries, and it was running once a second for a
        # hidden window.
        if not force and not self._dashboard.is_visible():
            return
        query = self._dashboard.search_query()
        view = self.log_buffer.view(
            query=query,
            errors_only=self.log_errors_only,
            noise_patterns=self.config["log_view_noise_patterns"] or (),
            limit=self.config["log_view_row_limit"],
        )
        text = view["text"] or self._empty_log_pane_text(query)
        if text != self._log_pane_text:
            self._log_pane_text = text
            self._dashboard.set_log(text)
        status = system_log.summarize(
            total=view["total"],
            shown=view["shown"],
            errors=view["errors"],
            query=query,
            error=self.log_error,
            captured=view["captured"],
        )
        if status != self._log_status_text:
            self._log_status_text = status
            self._dashboard.set_log_status(status)

    def _empty_log_pane_text(self, query: str) -> str:
        """Say which kind of empty this is.

        A blank pane otherwise means all of "the log is quiet", "your search
        matched nothing", "the viewer is switched off", and "the read failed" --
        and only some of those say anything about the network.
        """
        if not self.config["log_view_enabled"]:
            return "The system log viewer is switched off (log_view_enabled).\n"
        if self.log_error:
            return self.log_error + "\n"
        if query.strip():
            return f"Nothing in the captured log matches {query.strip()!r}.\n"
        captured = len(self.log_buffer.entries())
        if captured:
            # Captured, then filtered away. Distinguished from a silent log because
            # this is the state that most resembles a healthy network and least is:
            # entries exist, and every one of them was suppressed.
            return (
                f"{captured} entries captured, all of them filtered out.\n"
                "Every one matched log_view_noise_patterns"
                + (" or is below error level.\n" if self.log_errors_only else ".\n")
            )
        if self.log_errors_only:
            return (
                "No network errors or faults in the system log yet.\n"
                'Use "Errors only" to switch to every network log entry.\n'
            )
        return "No network entries captured from the system log yet.\n"

    def _log_level_title(self) -> str:
        return "Errors only" if self.log_errors_only else "All levels"

    def _log_read_refused_reason(self) -> str:
        """Why `_start_log_read` declined, in words, so a control never claims work
        it did not do.
        """
        if not self.config["log_view_enabled"]:
            return "The system log viewer is switched off (log_view_enabled).\n"
        return "A read is already in flight; this one was skipped.\n"

    def _toggle_log_level(self):
        """Switch between errors-and-faults and every network entry.

        Re-reads rather than just re-filtering: the level is part of the predicate,
        so entries at other levels were never fetched and are not in the buffer to
        filter. The re-read covers the poll window only, so the pane fills forward
        from now rather than retroactively.
        """
        self.log_errors_only = not self.log_errors_only
        if self._dashboard is not None:
            self._dashboard.set_log_level_title(self._log_level_title())
        window = self.config["log_view_poll_window"]
        if not self._start_log_read(window):
            # The filter flipped, but nothing was re-read -- say so rather than
            # describing a read that did not happen.
            self._append_output(
                f"System log filter is now {self._log_level_title().lower()}. "
                + self._log_read_refused_reason()
            )
            return
        if self.log_errors_only:
            self._append_output(
                f"System log: errors and faults only, re-reading the last {window}.\n"
            )
        else:
            self._append_output(
                f"System log: all network levels, re-reading the last {window}. This is "
                "noisy -- measured at roughly 6,000 entries a minute on this machine, so "
                "older entries will be dropped as the buffer fills.\n"
            )

    # --- elevated permissions ----------------------------------------------

    def _refresh_privilege_status(self):
        """Re-probe what is granted, on a worker thread.

        Three subprocesses (`sudo -n -k -l`, `ifconfig -l`, `route get default`), so
        not on the run loop, and cached rather than repeated -- the window repaints
        every second.

        Called at launch and again whenever the window is opened. Not only after a
        Grant or Revoke click: the sudoers file this app writes tells its reader
        "Delete this file to withdraw the grant", so the privilege can disappear
        without this app being involved at all, and a status cached from launch would
        keep claiming it for the rest of the session.
        """
        if self._privilege_status_thread is not None and self._privilege_status_thread.is_alive():
            return
        if self._privilege_thread is not None and self._privilege_thread.is_alive():
            # A grant or revoke is in flight. Both re-probe when they finish, so nothing is
            # lost by skipping -- and racing them is worse than skipping: authenticating at
            # the macOS dialog makes this app frontmost, which fires the activation observer,
            # which opens the dashboard, which starts a probe. That probe reads sudo before
            # the privileged script's `mv` has landed the file, and whichever of the two
            # finishes last wins the queue. The result was a results pane reading "Granted."
            # above a Permissions section reading "not granted".
            return
        self._privilege_status_thread = threading.Thread(
            target=self._run_privilege_status, name="privilege-status", daemon=True
        )
        self._privilege_status_thread.start()

    def _run_privilege_status(self):
        try:
            # One `sudo -l` listing answers both questions, so this does not pay for
            # a second subprocess to find out which interfaces are covered.
            granted_commands = privileges.granted_commands_now()
            self._privilege_results.put(
                {
                    "granted": " ".join(privileges.MDNS_HUP) in granted_commands,
                    "interfaces": privileges.dhcp_interfaces(),
                    "granted_interfaces": privileges.granted_interfaces_from(granted_commands),
                    "primary": privileges.primary_interface(),
                    "probed": True,
                }
            )
        except Exception:  # noqa: BLE001 - a status probe must not kill anything
            traceback.print_exc()

    def _drain_privilege_results(self):
        """Main thread: adopt the new status and print whatever it had to say.

        The message is only present for a grant or revoke -- the launch-time probe
        has nothing to report, and announcing "not granted" unprompted at every
        login would be nagging.
        """
        while True:
            try:
                result = self._privilege_results.get_nowait()
            except queue.Empty:
                return
            self.privileges_granted = result["granted"]
            self.dhcp_interfaces = result["interfaces"]
            # Absent from a grant/revoke result, which has no reason to re-probe the
            # routing table; keep the last known answer rather than blanking it.
            self.primary_dhcp_interface = result.get("primary", self.primary_dhcp_interface)
            self.granted_interfaces = result.get("granted_interfaces", self.granted_interfaces)
            self.privileges_probed = self.privileges_probed or result.get("probed", False)
            if result.get("message"):
                self._append_output(result["message"] + "\n")

    def _grant_privileges(self):
        """Explain first, then ask macOS for authorisation, on a worker thread.

        The explanation is printed before the prompt appears rather than after,
        because afterwards is too late to decline. The prompt itself waits for a
        human, which is precisely why this cannot run on the run loop -- it would
        freeze the window and every timer until someone typed a password.
        """
        if self._privilege_thread is not None and self._privilege_thread.is_alive():
            self._append_output("Still working on the previous permission change.\n")
            return

        # Refused, not approximated, until the launch probe has answered.
        #
        # `self.dhcp_interfaces` is empty until then, and an earlier version went
        # ahead and printed `explanation([])` -- which lists only the mDNSResponder
        # command -- while the worker re-enumerated and installed the ipconfig rules
        # as well. That has someone authenticating at the macOS dialog for a grant
        # strictly larger than the one they were shown, in the one place where
        # "disclosure precedes the point of no return" is the whole safety property.
        # A short wait is a much smaller cost than an incomplete consent list.
        #
        # It cannot deadlock: the probe is kicked off in launch_tick and takes at
        # most three 5s subprocesses.
        if not self.privileges_probed:
            self._refresh_privilege_status()
            self._append_output(
                "Still working out which interfaces to authorise -- try again in a "
                "moment, so the list you approve is the list that gets installed.\n"
            )
            return

        interfaces = list(self.dhcp_interfaces)
        self._append_output("\n" + privileges.explanation(interfaces) + "\n")
        self._privilege_thread = threading.Thread(
            target=self._run_grant,
            args=(interfaces,),
            name="privilege-grant",
            daemon=True,
        )
        self._privilege_thread.start()

    def _run_grant(self, interfaces: list):
        try:
            # Exactly the list that was shown and consented to -- no re-enumeration
            # here. Re-enumerating was how the installed grant could end up larger
            # than the one printed; _grant_privileges now refuses to prompt until it
            # has a real list instead.
            outcome = privileges.grant(getpass.getuser(), interfaces)
            granted_commands = privileges.granted_commands_now()
            self._privilege_results.put(
                {
                    "granted": " ".join(privileges.MDNS_HUP) in granted_commands,
                    "interfaces": privileges.dhcp_interfaces(),
                    "granted_interfaces": privileges.granted_interfaces_from(granted_commands),
                    "message": outcome["message"],
                }
            )
        except Exception:  # noqa: BLE001 - never raise out of a worker
            traceback.print_exc()
            self._privilege_results.put(
                {
                    "granted": self.privileges_granted,
                    "interfaces": self.dhcp_interfaces,
                    "message": "Granting raised; see the app log for the traceback.",
                }
            )

    def _revoke_privileges(self):
        if self._privilege_thread is not None and self._privilege_thread.is_alive():
            self._append_output("Still working on the previous permission change.\n")
            return
        self._privilege_thread = threading.Thread(
            target=self._run_revoke, name="privilege-revoke", daemon=True
        )
        self._privilege_thread.start()

    def _run_revoke(self):
        try:
            outcome = privileges.revoke()
            granted_commands = privileges.granted_commands_now()
            self._privilege_results.put(
                {
                    "granted": " ".join(privileges.MDNS_HUP) in granted_commands,
                    "interfaces": self.dhcp_interfaces,
                    "granted_interfaces": privileges.granted_interfaces_from(granted_commands),
                    "message": outcome["message"],
                }
            )
        except Exception:  # noqa: BLE001 - never raise out of a worker
            traceback.print_exc()
            self._privilege_results.put(
                {
                    "granted": self.privileges_granted,
                    "interfaces": self.dhcp_interfaces,
                    "message": "Revoking raised; see the app log for the traceback.",
                }
            )

    def ui_tick(self, _sender=None):
        """Repaint the window and collect any finished troubleshooting step.

        Its own timer, at 1s, rather than riding the 5s heartbeat: a button whose
        result appears up to five seconds later feels broken. While the window is
        closed this costs a queue poll and a string comparison.
        """
        self._drain_action_results()
        self._drain_log_results()
        self._drain_privilege_results()
        self._finish_localization_if_due()
        self._refresh_mini()
        if self._peers_dirty:
            # A peer was heard from on the listener thread. Persisting from here
            # keeps all file writing on the main thread.
            self._save_peer_record()
        self._refresh_dashboard()
        self._refresh_log_pane()

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
        # The level button ships with a title from the LOG_ACTIONS table; this is
        # what makes it agree with the filter actually in force, which may have come
        # from config rather than from a click.
        dashboard.set_log_level_title(self._log_level_title())
        self._refresh_log_pane(force=True)
        # Cheap (it self-skips while a probe is running) and necessary: the grant can
        # be withdrawn with `sudo rm`, which is what the file itself suggests, and a
        # status cached at launch would keep claiming it all session.
        self._refresh_privilege_status()
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
        # `_dashboard` is assigned once and never cleared, and the window has no close
        # delegate, so the red button hides it while the handle stays live. Without this the
        # "costs a queue poll and a string comparison" claim above was false from the first
        # open onward: every tick rendered the full stats block for a window nobody could see.
        if not force and not self._dashboard.is_visible():
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
                log_entries=len(self.log_buffer.entries()),
                log_errors=self.log_buffer.error_count(),
                new_log_errors=self.new_log_errors,
                log_error=self.log_error,
                permissions=privileges.status_rows(
                    granted=self.privileges_granted,
                    # What the grant covers, not what the machine has.
                    interfaces=self.granted_interfaces,
                    primary=self.primary_dhcp_interface,
                ),
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
        if action_id == "open_console":
            # Straight to the menu bar handler, not a fresh controller: two
            # controllers would be two consoles with two working directories and
            # two histories, so `cd /tmp` from the menu bar would be invisible to
            # the button and vice versa.
            self.open_console()
            return
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

        # The log column's own controls. Handled here, before the ladder-step
        # branch below, for the reason recorded against "open_dashboard": an id
        # this method does not recognise falls through to step_by_name and reports
        # "Unknown step", i.e. a button that looks wired and does nothing useful.
        if action_id == "log_refresh":
            if self._start_log_read(self.config["log_view_poll_window"]):
                self._append_output("Re-reading the system log...\n")
            else:
                self._append_output(self._log_read_refused_reason())
            return
        if action_id == "log_toggle_level":
            self._toggle_log_level()
            return
        if action_id == "log_clear_search":
            if self._dashboard is not None:
                self._dashboard.set_search_query("")
            return
        if action_id == "log_clear_buffer":
            self.log_buffer.clear()
            self.new_log_errors = 0
            self.log_error = None
            self._append_output("Emptied the captured system log.\n")
            return
        if action_id == "log_search":
            # Return pressed in the search box. The pane already re-filters on the
            # 1s refresh, so there is nothing to do -- but it has to be swallowed
            # here rather than reaching the ladder.
            return

        if action_id == "grant_privileges":
            self._grant_privileges()
            return
        if action_id == "revoke_privileges":
            self._revoke_privileges()
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

    def status_snapshot(self) -> str:
        """What the console's `:status` shows.

        Read live off the state machine and the ping monitor for the reason
        status.py records about the title: the gate's current state is the
        truth, and anything driven off "last report" goes stale the moment the
        network recovers, because recovery produces no report at all.

        Each attribute is snapshotted exactly once, for the reason spelled out
        in `_refresh_title`: the resolution worker rebinds
        `last_resolution_findings` from another thread, and a reader that reads
        it more than once can splice one batch's total onto another's failure
        count.
        """
        findings = self.last_resolution_findings
        resolution_failed = resolution_total = None
        if findings:
            resolution_total = len(findings)
            resolution_failed = sum(1 for finding in findings if not finding["resolved"])

        ping = self.ping_stats
        ping_down = ping["down"]
        flap_gate = self.state_machine.flap_gate
        return build_status_report(
            flap_state=flap_gate.state,
            last_classification=self.last_classification,
            consecutive_failures=flap_gate.consecutive_failures,
            ping_down=ping_down,
            stats=format_stats(
                rtt_ms=ping["rtt_ms"],
                loss_pct=ping["loss_pct"],
                down_bps=ping["down_bps"],
                up_bps=ping["up_bps"],
                ping_down=ping_down,
            ),
            resolution_failed=resolution_failed,
            resolution_total=resolution_total,
            last_report_path=self.last_report_path,
            last_tick_error=self.last_tick_error,
            poll_interval_seconds=self.config.get("poll_interval_seconds"),
            # anchor_domains, not config["domains"]: the control domain is
            # probed too, and after the reconcile the learned names are what
            # make the probe list interesting in the first place.
            domains=anchor_domains(self.config),
        )

    @rumps.clicked("Open console")
    def open_console(self, _sender=None):
        """Open the console, building it on first use.

        Takes `_sender=None` so the dashboard button can call this directly:
        both surfaces land on the one controller held at `self.console`, which
        is what keeps them the same console rather than two with separate
        working directories and separate history.
        """
        if self.console is None:
            self.console = ConsoleWindowController(status=self.status_snapshot)
        self.console.show()

    @rumps.clicked("Toggle mini window")
    def toggle_mini_window_clicked(self, _sender):
        self.toggle_mini_window()

    @rumps.clicked("Open last report")
    def open_last_report(self, _sender):
        if self.last_report_path:
            # as_uri() percent-encodes: the default reports_dir sits under
            # "Application Support", and a raw space makes an invalid file URL.
            webbrowser.open(pathlib.Path(self.last_report_path).as_uri())
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
