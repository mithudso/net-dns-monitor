"""The monitor with no windows: detect, repair, report to the fleet server.

For an administrator who puts the monitor on a teammate's Mac. Nothing here
draws, opens a menu or needs a GUI session once the process is running; it is
the same state machine, ladder and notifier the menu-bar app builds, driven by
a loop instead of rumps timers. It is started by `netdns headless`, or at login
by the LaunchAgent that `netdns headless --install` writes.

**What it does each poll.** One `state_machine.tick()`. On the healthy->incident
edge that returns the report: it is saved to `reports_dir`, sent to Slack/email
if configured (redacted, exactly as the app does), and queued for the fleet
server with the ladder steps it ran. When the gate later clears, the recovery is
queued too. The reporter's own thread does the sending and the retrying, so a
server that cannot be reached never delays the next poll.

**What it does not do.** No peer discovery, ping heartbeat, log viewer, forensic
episodes or dashboard: those exist to be looked at, and nobody is looking. The
saved report and the server's event log are the record.

**Nothing raises out of a poll** (CLAUDE.md non-negotiable 5). `step` wraps the
whole poll; a failure is kept as the class name in `last_error` and the loop
carries on. Recovery bookkeeping runs even when the poll itself raised, so an
incident is never left open on the server because the tick after it failed.

**Recovery is credited to nobody.** The `resolved` event lists the steps that
ran and says the network recovered. The gate clears on consecutive healthy
probes, which is what happened; it does not know why.
"""

import contextlib
import os
import plistlib
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable
from typing import Any, Optional

from netdnsmonitor import fleet_protocol as proto
from netdnsmonitor.escalation import redact
from netdnsmonitor.fleet_client import FleetReporter
from netdnsmonitor.notifications import format_notification
from netdnsmonitor.report_storage import save_report
from netdnsmonitor.status import status_state

AGENT_LABEL = "com.netdnsmonitor.headless"
LAUNCHCTL = "/bin/launchctl"


class HeadlessMonitor:
    def __init__(
        self,
        config: dict,
        state_machine,
        reporter: Optional[FleetReporter] = None,
        notifier: Optional[Callable[[str], Any]] = None,
        failover=None,
        failback_enabled: bool = False,
        save_report_fn: Callable[[dict, str], dict] = save_report,
        now_fn: Callable[[], float] = time.monotonic,
        log: Callable[[str], None] = lambda text: print(text, file=sys.stderr, flush=True),
    ):
        self.config = config
        self.state_machine = state_machine
        self.reporter = reporter
        self.notifier = notifier
        self.failover = failover
        self.failback_enabled = failback_enabled
        self.save_report_fn = save_report_fn
        self.now_fn = now_fn
        self.log = log
        self.last_error: Optional[str] = None
        self.polls = 0
        self.ticked = False
        self._open: Optional[dict] = None
        self._last_state = "healthy"

    def status(self) -> str:
        """What the heartbeat says: unknown until a poll has finished."""
        if not self.ticked:
            return proto.STATUS_UNKNOWN
        gate = self.state_machine.flap_gate
        return status_state(gate.state, gate.consecutive_failures)

    def step(self) -> None:
        """One poll. Never raises."""
        self.polls += 1
        self.last_error = None
        try:
            self._poll()
        except Exception as exc:  # noqa: BLE001 - the loop must outlive any one poll
            self.last_error = type(exc).__name__
            traceback.print_exc()
        try:
            self._note_recovery()
        except Exception as exc:  # noqa: BLE001
            self.last_error = type(exc).__name__
            traceback.print_exc()

    def _poll(self) -> None:
        report = self.state_machine.tick()
        self.ticked = True
        if report is not None:
            self._on_incident(report)
        elif self.failover is not None and self.failback_enabled:
            self.failover.attempt_failback()

    def _on_incident(self, report: dict) -> None:
        # Before anything that can fail: the gate offers this edge once.
        self._open = {
            "classification": report.get("classification", "unknown"),
            "started_at": report.get("started_at", ""),
            "steps": list(report.get("ladder_results") or []),
            "since": self.now_fn(),
        }
        if self.reporter is not None:
            self.reporter.incident(report)
        try:
            path = self.save_report_fn(report, self.config["reports_dir"])["markdown_path"]
        except Exception as exc:  # noqa: BLE001 - a lost file must not cost the alert
            path = None
            self.last_error = f"report not saved: {type(exc).__name__}"
        if self.notifier is not None:
            text = redact(format_notification(report, path), self.config["sensitive_strings"])
            threading.Thread(
                target=self._notify, args=(text,), name="headless-notify", daemon=True
            ).start()

    def _notify(self, text: str) -> None:
        try:
            if self.notifier is not None:
                self.notifier(text)
        except Exception as exc:  # noqa: BLE001 - belt and braces; notifiers swallow
            self.log(f"[notify] failed: {type(exc).__name__}")

    def _note_recovery(self) -> None:
        state = self.state_machine.flap_gate.state
        was = self._last_state
        self._last_state = state
        if was == "incident" and state != "incident" and self._open is not None:
            opened, self._open = self._open, None
            if self.reporter is not None:
                self.reporter.resolved(
                    opened["classification"],
                    self.now_fn() - opened["since"],
                    opened["steps"],
                    occurred_at=opened["started_at"],
                )

    def run(self, stop: threading.Event) -> None:
        interval = float(self.config["poll_interval_seconds"])
        while not stop.is_set():
            self.step()
            stop.wait(interval)


def default_credentials():
    """Environment first, then this app's Keychain items (see credentials.py)."""
    from netdnsmonitor import credentials

    return credentials.CredentialStore(backend_factory=credentials.make_keychain_backend)


def store_secret_from_environment(env=None, credential_store=None) -> Optional[str]:
    """Move FLEET_SHARED_SECRET from the installer's environment into the Keychain.

    The LaunchAgent starts with no shell environment, so a secret exported in the
    administrator's terminal would never reach it. Returns a line saying what
    happened, or None when the variable is not set. The value is never echoed.
    """
    env = os.environ if env is None else env
    value = env.get("FLEET_SHARED_SECRET")
    if not value:
        return None
    store = credential_store or default_credentials()
    try:
        outcome = store.set("FLEET_SHARED_SECRET", value)
    except Exception as exc:  # noqa: BLE001 - reported as data, class name only
        return f"failed: the shared secret was not saved to the Keychain ({type(exc).__name__})"
    return f"shared secret: {outcome}"


def fleet_secret(credential_store) -> Optional[str]:
    try:
        return credential_store.get("FLEET_SHARED_SECRET") or None
    except Exception:  # noqa: BLE001 - no secret means unsigned, which the server decides
        return None


def build_reporter(
    config: dict, secret: Optional[str], status_fn, version: str = ""
) -> FleetReporter:
    sensitive = config.get("sensitive_strings") or []
    return FleetReporter(
        machine_id=machine_identity(config),
        host=config.get("fleet_machine_name") or socket.gethostname(),
        server_address=config.get("fleet_server_address", ""),
        port=config["fleet_port"],
        secret=secret,
        redact_fn=lambda text: redact(text, sensitive),
        status_fn=status_fn,
        heartbeat_seconds=float(config["fleet_heartbeat_seconds"]),
        version=version,
    )


def machine_identity(config: dict) -> str:
    """A stable id for this machine, so a restart does not look like a new one.

    The configured name when there is one, else the host name. A process-random
    id (as peer discovery uses) would make every restart a new machine in the
    server's table, and leave the old entry open at "incident" forever.
    """
    name = config.get("fleet_machine_name") or socket.gethostname()
    return proto.clean(name, 64)


def run_headless(
    config_path: str,
    stop: Optional[threading.Event] = None,
    build_app_parts: Optional[Callable[..., dict]] = None,
) -> int:
    """Build everything from the config and run until stopped. Exit code."""
    from netdnsmonitor import app as app_module
    from netdnsmonitor import distribution
    from netdnsmonitor.config import load_config

    stop = stop or threading.Event()
    capabilities = distribution.detect()
    try:
        config = load_config(
            os.path.expanduser(config_path), distribution.default_overrides(capabilities)
        )
    except Exception as exc:  # noqa: BLE001 - reported as one line, exit 2
        print(f"config error: {config_path}: {type(exc).__name__}", file=sys.stderr)
        return 2

    credential_store = app_module.default_credential_store()
    failover = app_module.build_failover(config)
    remediation_store = app_module.build_remediation_store(capabilities, config=config)
    state_machine = app_module.build_state_machine(
        config,
        failover,
        capabilities=capabilities,
        credential_store=credential_store,
        consent=None,
        remediation_store=remediation_store,
    )
    notifier = app_module.build_notifier(config, env=credential_store.as_env())
    secret = fleet_secret(credential_store)

    monitor = HeadlessMonitor(
        config,
        state_machine,
        notifier=notifier,
        failover=failover,
        failback_enabled=bool(failover and capabilities.network_order_write),
    )
    if config["fleet_reporting_enabled"]:
        monitor.reporter = build_reporter(config, secret, monitor.status)
        monitor.reporter.start()
        if not secret and not config["fleet_allow_unsigned"]:
            print(
                "[fleet] no FLEET_SHARED_SECRET: reports go out unsigned and a server "
                "that requires signatures will refuse them",
                file=sys.stderr,
                flush=True,
            )

    server = None
    if config["fleet_server_enabled"]:
        server = start_server(config, secret)

    for name in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(ValueError):  # not the main thread
            signal.signal(name, lambda *_: stop.set())
    print("[headless] running; Ctrl-C to stop", file=sys.stderr, flush=True)
    try:
        monitor.run(stop)
    finally:
        if monitor.reporter is not None:
            monitor.reporter.stop()
        if server is not None:
            server.stop()
    return 0


def start_server(config: dict, secret: Optional[str]):
    """Build and start the fleet server from config. None if it cannot start."""
    from netdnsmonitor.fleet_server import FleetServer
    from netdnsmonitor.fleet_store import FleetStore

    store = FleetStore(
        config["fleet_server_log_path"],
        config["fleet_server_state_path"],
        stale_seconds=float(config["fleet_stale_seconds"]),
    )
    server = FleetServer(
        store,
        port=config["fleet_port"],
        secret=secret,
        allow_unsigned=config["fleet_allow_unsigned"],
    )
    if not server.start():
        print(f"[fleet] server unavailable: {server.start_error}", file=sys.stderr, flush=True)
        return None
    print(f"[fleet] listening on UDP {server.port}", file=sys.stderr, flush=True)
    if not secret and not config["fleet_allow_unsigned"]:
        print(
            "[fleet] no FLEET_SHARED_SECRET and fleet_allow_unsigned is false: "
            "every report will be refused",
            file=sys.stderr,
            flush=True,
        )
    return server


# --- LaunchAgent -----------------------------------------------------------


def agent_path(agents_dir: Optional[str] = None) -> str:
    base = agents_dir or os.path.expanduser("~/Library/LaunchAgents")
    return os.path.join(base, f"{AGENT_LABEL}.plist")


def agent_plist(executable: str, source_root: str, config_path: str, log_path: str) -> dict:
    """The LaunchAgent that keeps the headless monitor running.

    KeepAlive, unlike the menu-bar app's login item: nobody is at the screen to
    notice that it stopped. The paths are the ones in use now, not a fixed
    location, for the reason `login_agent_plist` gives.
    """
    return {
        "Label": AGENT_LABEL,
        "ProgramArguments": [
            executable,
            "-m",
            "netdnsmonitor.cli",
            "--config",
            config_path,
            "headless",
        ],
        "WorkingDirectory": source_root,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "StandardErrorPath": log_path,
        "StandardOutPath": log_path,
        "EnvironmentVariables": {"LANG": "en_US.UTF-8"},
    }


def install_agent(
    config_path: str,
    executable: str,
    source_root: str,
    agents_dir: Optional[str] = None,
    log_path: Optional[str] = None,
    start: bool = True,
    run_fn: Callable = subprocess.run,
    uid: Optional[int] = None,
) -> str:
    """Write the LaunchAgent and (unless start is False) load it. Returns a line
    saying exactly what happened -- written, loaded, or why not.
    """
    path = agent_path(agents_dir)
    log_path = log_path or os.path.expanduser("~/Library/Logs/net-dns-monitor-headless.log")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(path, "wb") as handle:
        plistlib.dump(
            agent_plist(executable, source_root, os.path.abspath(config_path), log_path), handle
        )
    os.chmod(path, 0o644)
    if not start:
        return f"written: {path} (not loaded; it starts at next login)"
    domain = f"gui/{os.getuid() if uid is None else uid}"
    # bootout first so a reinstall picks up the new plist; its failure (not loaded
    # yet) is expected and ignored.
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        run_fn([LAUNCHCTL, "bootout", f"{domain}/{AGENT_LABEL}"], capture_output=True, timeout=20)
    try:
        result = run_fn(
            [LAUNCHCTL, "bootstrap", domain, path], capture_output=True, text=True, timeout=20
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return f"written: {path}; not loaded ({type(exc).__name__}). Load it with: launchctl bootstrap {domain} {path}"
    if result.returncode != 0:
        return (
            f"written: {path}; launchctl bootstrap exited {result.returncode}. "
            f"It will start at next login, or run: launchctl bootstrap {domain} {path}"
        )
    return f"installed and running: {path}"


def uninstall_agent(
    agents_dir: Optional[str] = None,
    run_fn: Callable = subprocess.run,
    uid: Optional[int] = None,
) -> str:
    path = agent_path(agents_dir)
    domain = f"gui/{os.getuid() if uid is None else uid}"
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        run_fn([LAUNCHCTL, "bootout", f"{domain}/{AGENT_LABEL}"], capture_output=True, timeout=20)
    try:
        os.remove(path)
    except FileNotFoundError:
        return f"nothing to remove: {path} does not exist"
    except OSError as exc:
        return f"failed: could not remove {path} ({type(exc).__name__})"
    return f"removed: {path}"
