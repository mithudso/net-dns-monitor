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

import os
import pathlib
import plistlib
import pwd
import queue
import socket as socket_module
import subprocess
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Mapping
from typing import Callable, Optional

import rumps
import yaml

from netdnsmonitor import (
    ai_consent,
    alert,
    console,
    credentials,
    credentials_prompt,
    distribution,
    forensic_log,
    peer_net,
    privileges,
    system_log,
)
from netdnsmonitor.anthropic_escalator import default_client, make_escalator
from netdnsmonitor.classifier import classify
from netdnsmonitor.config import ConfigError, load_config
from netdnsmonitor.console_window import ConsoleWindowController
from netdnsmonitor.dashboard import (
    DashboardWindow,
    dashboard_sections,
    install_main_menu,
    render_dashboard_text,
)
from netdnsmonitor.distribution import Capabilities
from netdnsmonitor.dock_icon import set_dock_icon
from netdnsmonitor.domain_learner import (
    LearnedDomainStore,
    make_domain_learner,
    prune_dead_domains,
)
from netdnsmonitor.escalation import redact
from netdnsmonitor.failover import (
    BACKUP,
    PREFERRED,
    build_failover,
    failover_backup_names,  # noqa: F401 - re-exported; moved to failover.py
    failover_probe_targets,  # noqa: F401 - re-exported; moved to failover.py
    failover_probe_timeout,  # noqa: F401 - re-exported; moved to failover.py
    failover_trigger_classifications,
)
from netdnsmonitor.forensic_log import ForensicRecorder
from netdnsmonitor.history import SampleHistory
from netdnsmonitor.ladder import ladder_for, step_by_name
from netdnsmonitor.localize import localize
from netdnsmonitor.log_watcher import NO_EVIDENCE_PREFIX, make_log_watcher
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
from netdnsmonitor.router import PF_ANCHOR, Router
from netdnsmonitor.router_window import (
    RouterWindowController,
    collect_diagnostics,
    get_interfaces,
)
from netdnsmonitor.settings_window import (
    NEEDS_RESTART,
    SERVICE_RESTART_HINT,
    STORE_RESTART_HINT,
    SettingsWindow,
    collect,
    restart_note,
    save_config,
)
from netdnsmonitor.stall_log import select_stalled_domains
from netdnsmonitor.state_machine import StateMachine
from netdnsmonitor.status import (
    STATS_UNKNOWN,
    build_failover_lines,
    build_status_report,
    build_title,
    format_stats,
    status_state,
)

OPEN_BIN = "/usr/bin/open"
PFCTL_BIN = "/sbin/pfctl"

# Router menu reads (interface list, diagnostics) are bounded by this. The admin
# dialog behind Start and Stop is bounded by router.DEFAULT_TIMEOUT_SECONDS.
ROUTER_COMMAND_TIMEOUT_SECONDS = 5.0

# peers.json is rewritten at most this often from the UI tick. A busy LAN marks
# the registry dirty on every peer message, and the tick runs every second.
PEER_SAVE_MIN_INTERVAL_SECONDS = 30.0

# The LaunchAgent the "Start at Login" item writes, and the one
# scripts/net-dns-monitor-service installs. Either one can start the app at login.
LOGIN_AGENT_LABEL = "com.netdnsmonitor"
SERVICE_AGENT_LABEL = "com.mitchhudson.net-dns-monitor"

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

# Dashboard buttons that exist in every build but act only where the feature does.
# The action grid is the same in both builds; in one without the feature, the click
# prints the unavailable text instead of acting. (action id -> (capability, what))
GATED_DASHBOARD_ACTIONS = {
    "open_console": ("shell_console", "the console"),
    "open_router_window": ("router", "the router console"),
    "grant_privileges": ("privileged_repairs", "granting elevated permissions"),
    "revoke_privileges": ("privileged_repairs", "revoking elevated permissions"),
    # Prewarming reads its names out of `log show`, so it goes with the log.
    "prewarm_dns": ("unified_log", "prewarming DNS from the system log's query history"),
    "log_refresh": ("unified_log", "reading the system log"),
    "log_toggle_level": ("unified_log", "reading the system log"),
    "log_clear_buffer": ("unified_log", "reading the system log"),
}

# The Info.plist key setup.py writes for the store build (Guideline 5.1.1(i)
# wants the privacy policy reachable from inside the app, not only in App Store
# Connect).
PRIVACY_POLICY_URL_KEY = "NDMPrivacyPolicyURL"

CREDENTIALS_MENU = "Credentials"
REMOVE_CREDENTIALS_ITEM = "Remove saved credentials"
CONSENT_ITEM = "Allow Claude diagnosis…"
WITHDRAW_CONSENT_ITEM = "Withdraw Claude permission"
PRIVACY_POLICY_ITEM = "Privacy Policy"

# (menu title, credential name, what the dialog says). The dialog also says the
# environment wins, before anything is typed: a key saved here while the same
# variable is exported is saved but not used.
CREDENTIAL_ITEMS = (
    (
        "Set Anthropic API key…",
        "ANTHROPIC_API_KEY",
        "Used for Claude diagnosis when the troubleshooting ladder cannot resolve an incident.",
    ),
    (
        "Set Slack webhook URL…",
        "SLACK_WEBHOOK_URL",
        "The incoming-webhook URL Slack alerts are posted to. The URL is itself a credential.",
    ),
    (
        "Set SMTP password…",
        "SMTP_PASSWORD",
        "The password for smtp_username on smtp_host, used for email alerts.",
    ),
)
CREDENTIAL_STORAGE_NOTE = (
    "It is saved in your macOS Keychain. If the same name is set as an environment "
    "variable, that value is used instead."
)


def default_credential_store() -> credentials.CredentialStore:
    """Environment first, then this app's Keychain items.

    The factory is looked up on the module at call time. CredentialStore's own
    default argument was bound when credentials.py was imported, so it cannot be
    replaced from outside, and tests/conftest.py relies on this lookup to keep the
    suite away from the real Keychain.
    """
    return credentials.CredentialStore(backend_factory=credentials.make_keychain_backend)


def bundled_privacy_policy_url() -> Optional[str]:
    """The policy URL from this bundle's Info.plist, or None.

    None from a source run, which has no such key. None as well for anything that
    is not an http(s) URL: NSWorkspace opens files and launches apps just as
    readily as it opens web pages.
    """
    try:
        from Foundation import NSBundle

        value = NSBundle.mainBundle().objectForInfoDictionaryKey_(PRIVACY_POLICY_URL_KEY)
    except Exception:  # noqa: BLE001 - no bundle means no URL, never a crash
        return None
    text = str(value or "").strip()
    return text if text.lower().startswith(("https://", "http://")) else None


def open_url_with_workspace(url: str) -> bool:
    """NSWorkspace rather than `webbrowser`. On macOS `webbrowser` pipes an
    AppleScript into /usr/bin/osascript, and sending Apple Events to another app
    needs an entitlement the store build does not carry.
    """
    from AppKit import NSWorkspace
    from Foundation import NSURL

    ns_url = NSURL.URLWithString_(url)
    if ns_url is None:
        return False
    return bool(NSWorkspace.sharedWorkspace().openURL_(ns_url))


def missing_key_text(capabilities: Capabilities) -> str:
    if capabilities.is_app_store:
        # A sandboxed app launched from Finder never sees a shell's exports, so the
        # Keychain is the only place a key can come from in this build.
        return (
            "ANTHROPIC_API_KEY not set; skipped LLM escalation (save a key in the Keychain "
            f"from the menu: {CREDENTIALS_MENU} > {CREDENTIAL_ITEMS[0][0]})"
        )
    return "ANTHROPIC_API_KEY not set; skipped LLM escalation"


def build_escalator(
    capabilities: Capabilities,
    credential_store: credentials.CredentialStore,
    consent: Optional[ai_consent.ConsentStore] = None,
) -> Callable[[dict], dict]:
    """The state machine's escalator, from the key the credential store finds now.

    Separate from build_state_machine so the Credentials menu can rebuild it in
    place: a key saved from the menu then applies to the next incident, without a
    restart.
    """
    key = credential_store.get("ANTHROPIC_API_KEY")
    if key:
        escalator = make_escalator(client=default_client(api_key=key))
    else:
        message = missing_key_text(capabilities)

        def escalator(bundle: dict) -> dict:
            return {"error": message}

    if capabilities.requires_ai_consent:
        # Wrapped outside the key check. Whether a key exists says nothing about
        # whether this person agreed to send incident data to Anthropic.
        consent = ai_consent.ConsentStore() if consent is None else consent
        escalator = ai_consent.gate_escalator(escalator, consent.granted)
    return escalator


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


def build_notifier(config: dict, env: Optional[Mapping[str, str]] = None):
    """Slack and email are opt-in by presence of their credential in the
    environment, mirroring the ANTHROPIC_API_KEY branch: no webhook URL and no
    SMTP recipients means no channels and a notifier that is a cheap no-op,
    never a crash and never a silent half-configured send.

    The app passes `CredentialStore.as_env()`, so "the environment" here also
    covers a value saved in the Keychain. Only `.get` is called on it.
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


def build_domains_source(
    config: dict,
    log_watcher,
    spawn=None,
    capabilities: Optional[Capabilities] = None,
):
    """Returns (domains_source, store). domains_source is what the prober asks
    each tick; store is None when log learning is turned off.

    `spawn` runs the learner's log scan. None keeps the learner's own daemon
    thread; a test passes a synchronous one to observe the scan's result.

    A build that cannot read the unified log gets no learner whatever the config
    says: its watcher only ever returns the "unavailable" line, so there is nothing
    to learn from, and nothing should parse that sentence as log evidence.
    """
    capabilities = distribution.detect() if capabilities is None else capabilities
    anchors = anchor_domains(config)
    if not config.get("learn_domains_from_logs") or not capabilities.unified_log:
        return anchors, None
    store = LearnedDomainStore(
        path=config["learned_domains_path"],
        max_domains=int(config["max_learned_domains"]),
    )
    options = {} if spawn is None else {"spawn": spawn}
    learner = make_domain_learner(
        log_watcher=log_watcher,
        store=store,
        configured_domains=anchors,
        interval_seconds=float(config["domain_learn_interval_seconds"]),
        **options,
    )
    return learner, store


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


def dhcp_lease_granted(interface: str) -> bool:
    """Does the installed grant cover a DHCP renewal on this interface?

    Asked per step, not captured at launch, so a grant or revoke takes effect
    without a restart. The grant lists the interfaces that existed when it was
    made, so a dock or USB adapter that appeared since is not covered.
    """
    return privileges.covers(
        privileges.granted_commands_now(), (privileges.IPCONFIG, "set", interface, "DHCP")
    )


def unified_log_unavailable_watcher() -> Callable[[], list[str]]:
    """The log watcher for a build that may not read the unified log.

    One line, not `[]`. An empty excerpt list reads as "nothing was logged", which
    is a statement about the network; this line says the log was never read. The
    prefix is log_watcher's own "no evidence" marker, the one domain_learner
    already skips.
    """
    line = f"{NO_EVIDENCE_PREFIX} " + distribution.unavailable(
        "unified_log", "reading the system log"
    )

    def watcher() -> list[str]:
        return [line]

    return watcher


def build_state_machine(
    config: dict,
    failover=None,
    capabilities: Optional[Capabilities] = None,
    credential_store: Optional[credentials.CredentialStore] = None,
    consent: Optional[ai_consent.ConsentStore] = None,
) -> StateMachine:
    """`failover` is passed in by the app so the ladder step and the tick-path
    failback share one instance and therefore one set of counters. It is
    derived from the config when omitted, so that a caller who forgets gets a
    state machine that matches the config rather than one that silently drops
    the switch step.

    `capabilities` is detected from the environment when omitted, for the same
    reason: a caller who forgets must not get a sandboxed state machine that
    tries to rewrite the service order or read the unified log.
    """
    capabilities = distribution.detect() if capabilities is None else capabilities
    if failover is None:
        failover = build_failover(config)

    external_targets = [tuple(t) for t in config["external_targets"]]
    internal_targets = [tuple(t) for t in config["internal_targets"]]

    if capabilities.unified_log:
        log_watcher = make_log_watcher(lookback=config["log_lookback"])
    else:
        log_watcher = unified_log_unavailable_watcher()
    domains_source, store = build_domains_source(config, log_watcher, capabilities=capabilities)

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
    if capabilities.privileged_repairs:
        privilege_options = {
            "is_granted_fn": privileges.is_granted,
            "primary_interface_fn": privileges.primary_interface,
            "dhcp_granted_fn": dhcp_lease_granted,
        }
    else:
        # A constant "no" instead of the real probes, which run `sudo -n -l` and
        # `route`: a build that may never use root has no question to ask them.
        # unavailable_fn makes the two root steps say why they did nothing.
        privilege_options = {
            "is_granted_fn": lambda: False,
            "unavailable_fn": lambda what: distribution.unavailable("privileged_repairs", what),
        }

    if capabilities.network_order_write:
        failover_fn = failover.attempt_failover if failover else None
    else:
        # Set whether or not failover is configured. The write is impossible in
        # this build either way, and "not configured" would send someone to
        # config.yaml to fix something that no setting can fix.
        def failover_fn(_classification: str) -> str:
            return distribution.unavailable(
                "network_order_write", "switching to the backup network"
            )

    repair_executor = make_repair_executor(failover_fn=failover_fn, **privilege_options)

    escalator = build_escalator(
        capabilities,
        default_credential_store() if credential_store is None else credential_store,
        consent,
    )

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


def config_error_text(exc: BaseException) -> str:
    """How a config read failure is shown. A ConfigError's message names the
    key and the refused value, which is the part someone needs to fix it. Any
    other exception is shown by class name only: a YAML parser's message quotes
    file content.
    """
    if isinstance(exc, ConfigError):
        return f"{type(exc).__name__}: {exc}"
    return type(exc).__name__


def login_agent_path(label: str) -> str:
    return os.path.join(os.path.expanduser("~/Library/LaunchAgents"), f"{label}.plist")


def login_item_installed() -> bool:
    """True when either LaunchAgent is on disk. The service script's agent also
    starts the app at login (while its supervision flag is set), so a checkmark
    that ignored it would read "off" on a machine that starts the app anyway.
    """
    return any(
        os.path.exists(login_agent_path(label))
        for label in (LOGIN_AGENT_LABEL, SERVICE_AGENT_LABEL)
    )


def login_agent_plist(frozen: bool, executable: str, source_root: str) -> dict:
    """The LaunchAgent that starts this copy of the app at login.

    Frozen, `executable` is the bundle's own executable, which is what
    net-dns-monitor-service points its agent at. From source it is the running
    interpreter, run with `-m` from the checkout the package was imported from.
    Neither is a fixed path: the agent this replaced named one user's home
    directory, so on any other account it started nothing.
    """
    plist = {
        "Label": LOGIN_AGENT_LABEL,
        "RunAtLoad": True,
        "KeepAlive": False,
        # launchd starts jobs with no locale; see write_plist in
        # scripts/net-dns-monitor-service for what that broke.
        "EnvironmentVariables": {"LANG": "en_US.UTF-8"},
    }
    if frozen:
        plist["ProgramArguments"] = [executable]
    else:
        plist["ProgramArguments"] = [executable, "-m", "netdnsmonitor.app"]
        plist["WorkingDirectory"] = source_root
    return plist


def _bundle_executable() -> str:
    try:
        from Foundation import NSBundle

        path = NSBundle.mainBundle().executablePath()
        if path:
            return str(path)
    except Exception:  # noqa: BLE001 - fall back to the interpreter path
        pass
    return sys.executable


def router_nat_text(run_fn: Callable[..., object]) -> str:
    """The NAT rules the app's router loaded, or why they were not read.

    `sudo -n`: reading pf needs root, and a sudo that may prompt waits on a
    terminal this app does not have.
    """
    argv = [privileges.SUDO, "-n", PFCTL_BIN, "-a", PF_ANCHOR, "-s", "nat"]
    try:
        result = run_fn(
            argv, capture_output=True, text=True, timeout=ROUTER_COMMAND_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        return f"NAT rules in {PF_ANCHOR}: not checked ({type(exc).__name__})"
    code = getattr(result, "returncode", 1)
    if code != 0:
        return f"NAT rules in {PF_ANCHOR}: not checked (sudo -n exit {code}; needs root)"
    rules = (getattr(result, "stdout", "") or "").strip()
    return f"NAT rules in {PF_ANCHOR}:\n{rules or '(none loaded)'}"


class NetDnsMonitorApp(rumps.App):
    def __init__(
        self,
        config_path: str = DEFAULT_CONFIG_PATH,
        router_factory: Callable[..., object] = Router,
        capabilities: Optional[Capabilities] = None,
        credential_store: Optional[credentials.CredentialStore] = None,
        consent_store: Optional[ai_consent.ConsentStore] = None,
        secret_prompt: Callable[[str, str], Optional[str]] = credentials_prompt.prompt_for_secret,
        choice_prompt: Callable[[str, str, str, str], bool] = credentials_prompt.confirm,
        url_opener: Callable[[str], bool] = open_url_with_workspace,
        privacy_policy_url_fn: Callable[[], Optional[str]] = bundled_privacy_policy_url,
    ):
        set_app_display_name(DISPLAY_NAME)
        super().__init__(name=DISPLAY_NAME, title=f"{STATS_UNKNOWN} Net/DNS: starting...")
        # Decided once, here, and never re-read: what this build may do does not
        # change while it runs, and every gate below reads this one object.
        self.capabilities = distribution.detect() if capabilities is None else capabilities
        self.credentials = (
            default_credential_store() if credential_store is None else credential_store
        )
        # Only the store build asks. The direct build's opt-in is setting a key.
        self.consent: Optional[ai_consent.ConsentStore] = None
        if self.capabilities.requires_ai_consent:
            self.consent = ai_consent.ConsentStore() if consent_store is None else consent_store
        # Both dialogs are modal and wait for a person, so they come in as
        # parameters: the suite passes fakes and never opens one.
        self.secret_prompt = secret_prompt
        self.choice_prompt = choice_prompt
        self.url_opener = url_opener
        self.privacy_policy_url_fn = privacy_policy_url_fn
        self.config = load_config(config_path)
        self.failover = build_failover(self.config)
        self.state_machine = build_state_machine(
            self.config,
            self.failover,
            capabilities=self.capabilities,
            credential_store=self.credentials,
            consent=self.consent,
        )
        self.notifier = build_notifier(self.config, env=self.credentials.as_env())
        self.last_notification_results = None
        self._notification_thread: Optional[threading.Thread] = None
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
        # None until the first save, so the first dirty UI tick writes at once.
        self._peers_saved_at: Optional[float] = None

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
        # Seeded with the reason in a build that may not read the log, so the pane,
        # its status line and the Monitor row all say why they are empty instead of
        # "nothing captured yet", which reads as a quiet network.
        self.log_error: Optional[str] = (
            None if self.capabilities.unified_log else self._log_unavailable_text()
        )
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
        # Whether this app's own sudoers rule is listed. None until probed, which
        # status_rows reads as "follow privileges_granted".
        self.privileges_file_rule_listed: Optional[bool] = None
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
        # A console command still running at quit would outlive the app.
        # `callbacks` is a set, so the many apps a test run builds register once.
        rumps.events.before_quit.register(console.kill_running)
        self.router_window = None
        # Router menu work runs on workers and reports through this queue: Start
        # and Stop wait on the macOS admin dialog, and the reads shell out.
        self.router_run_fn: Callable[..., object] = subprocess.run
        self._router_thread: Optional[threading.Thread] = None
        self._router_info_thread: Optional[threading.Thread] = None
        self._router_results: queue.Queue = queue.Queue()

        # Indicator rows carry no callback, which is what greys them out: they
        # are readouts, not actions. Titles are set by _refresh_failover_menu.
        self.failover_rows = [rumps.MenuItem(f"failover-row-{i}") for i in range(3)]
        self.menu = self._menu_layout()
        self._refresh_consent_menu()
        self._refresh_failover_menu()
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
        if self._log_view_enabled():
            self.log_timer = rumps.Timer(self.log_tick, self.config["log_view_poll_seconds"])
            self.log_timer.start()
        # Runs once, then stops itself. Everything in it needs a live
        # NSApplication and a turning run loop, and none of it may happen in
        # __init__ where the tests would each get a window.
        self.launch_timer = rumps.Timer(self.launch_tick, 1)
        self.launch_timer.start()
        set_dock_icon("healthy")

        if self.capabilities.launch_agent_login_item:
            self.menu["Start at Login"].state = login_item_installed()

        # Built but never started here. Starting runs a root script behind the
        # macOS admin dialog, and __init__ runs on every launch and login: the
        # dialog appeared unasked, and the app waited on it before any timer ran.
        # The menu's Start item and the router window are the only ways to start it.
        self.router = None
        if self.config["router_enabled"] and self.capabilities.router:
            self.router = router_factory(
                wan_if=self.config["wan_interface"],
                lan_if=self.config["lan_interface"],
                lan_ip=self.config["lan_ip"],
                lan_netmask=self.config["lan_netmask"],
                dhcp_start=self.config["dhcp_start"],
                dhcp_end=self.config["dhcp_end"],
            )

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
        if self.peer_network is not None and not self.peer_network.alive():
            # The reader thread ended (its socket closed under it). Announcing
            # from a dead network would look like discovery still worked.
            self.peer_network.stop()
            self.peer_network = None
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
        self._peers_saved_at = time.monotonic()

    def tick(self, _sender=None):
        # rumps 0.4.0 catches an exception in Timer.callback_, so the timer
        # survives a raise. What does not survive is the rest of the tick: the
        # title repaint, the gate-recovery note, and on an incident edge the
        # alert, which the gate never offers again. So every tick is guarded.
        try:
            self._tick()
        except Exception as exc:  # noqa: BLE001 - the rest of the tick must still run
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
            # Before anything that can fail. The gate reports only on the
            # healthy->incident edge, so this report is the only one the incident
            # will get: a save that raised used to skip the classification, the
            # alert and the forensic DOWN, and the next tick had nothing to redo.
            self.last_classification = report["classification"]
            try:
                report_path = save_report(report, self.config["reports_dir"])["markdown_path"]
            except Exception as exc:  # noqa: BLE001 - a lost file must not cost the alert
                report_path = None
                self.last_tick_error = f"report not saved: {type(exc).__name__}"
            # None rather than the previous path: that file describes an earlier
            # incident, and the window shows this path beside this classification.
            self.last_report_path = report_path
            # Redact on the way out for the same reason escalation does: Slack
            # and email are off-machine, and the on-disk report is not.
            #
            # Redaction happens here, on the run loop, and only the finished
            # string crosses to the worker. The alternative -- handing the
            # report over and redacting there -- would put the one step that
            # must not be skipped on the far side of a thread boundary.
            text = redact(
                format_notification(report, report_path),
                self.config["sensitive_strings"],
            )
            self._send_notification(text)
            self._record_incident_forensics(report)
            # An incident may have run the failover ladder step, so the
            # indicator is stale.
            self._refresh_failover_menu()
        elif self.failover is not None and self.capabilities.network_order_write:
            # Never in a build that cannot write the service order: a failback is
            # a write, and the read ahead of it would be wasted.
            #
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
        if not self.peer_network.alive():
            # No listener to hear the pongs, so a verdict computed later would
            # read every peer as silent. peer_tick rebuilds the network.
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
        if not self._log_view_enabled():
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
        if not self.capabilities.unified_log:
            return self._log_unavailable_text() + "\n"
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

    def _log_view_enabled(self) -> bool:
        """The config switch, and whether this build may read the log at all.

        Both, every time: the config value can say True in a build whose sandbox
        refuses `log show`, and that refusal is not a network fault to report.
        """
        return bool(self.config["log_view_enabled"]) and self.capabilities.unified_log

    def _log_unavailable_text(self) -> str:
        return distribution.unavailable("unified_log", "reading the system log")

    def _log_level_title(self) -> str:
        return "Errors only" if self.log_errors_only else "All levels"

    def _log_read_refused_reason(self) -> str:
        """Why `_start_log_read` declined, in words, so a control never claims work
        it did not do.
        """
        if not self.capabilities.unified_log:
            return self._log_unavailable_text() + "\n"
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
        if not self.capabilities.privileged_repairs:
            # A build that may never use root has nothing to find out, and the
            # probe itself runs `sudo -n -l`.
            return
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
                    # covers, not exact-line membership: a blanket NOPASSWD: ALL
                    # permits the restart, and the window said "not granted".
                    "granted": privileges.covers(granted_commands, privileges.MDNS_HUP),
                    "file_rule_listed": privileges.own_rule_listed(granted_commands),
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
            self.privileges_file_rule_listed = result.get(
                "file_rule_listed", self.privileges_file_rule_listed
            )
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
            # The account this process runs as. getpass.getuser() reads LOGNAME
            # and USER first, so an inherited environment could name someone else
            # in a rule that grants root commands.
            outcome = privileges.grant(pwd.getpwuid(os.getuid()).pw_name, interfaces)
            granted_commands = privileges.granted_commands_now()
            self._privilege_results.put(
                {
                    "granted": privileges.covers(granted_commands, privileges.MDNS_HUP),
                    "file_rule_listed": privileges.own_rule_listed(granted_commands),
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
                    "granted": privileges.covers(granted_commands, privileges.MDNS_HUP),
                    "file_rule_listed": privileges.own_rule_listed(granted_commands),
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
        self._drain_router_results()
        self._finish_localization_if_due()
        self._refresh_mini()
        if self._peers_dirty and (
            self._peers_saved_at is None
            or time.monotonic() - self._peers_saved_at >= PEER_SAVE_MIN_INTERVAL_SECONDS
        ):
            # A peer was heard from on the listener thread. Persisting from here
            # keeps all file writing on the main thread. Throttled: every peer message
            # marks the registry dirty, and this runs every second.
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

    def _settings_restart_hint(self) -> str:
        # The store build ships no service script to restart it with.
        return STORE_RESTART_HINT if self.capabilities.is_app_store else SERVICE_RESTART_HINT

    def open_settings(self):
        if self._settings is None:
            options = {}
            if self.capabilities.is_app_store:
                # Its config sits in the sandbox container, not at ~/.config.
                options = {
                    "config_path_display": self.config_path,
                    "restart_hint": self._settings_restart_hint(),
                }
            self._settings = SettingsWindow(on_save=self._save_settings, **options)
        # The file, not the running config: restart-only keys keep their launch
        # values in self.config, and the window edits what is on disk.
        problem = None
        try:
            shown = load_config(self.config_path)
        except Exception as exc:  # noqa: BLE001 - an unreadable file must not block the window
            shown = self.config
            problem = config_error_text(exc)
        self._settings.load(shown)
        self._settings.show()
        if problem:
            self._settings.set_status(
                f"Showing the running config; the file was not read -- {problem}"
            )

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
            fresh = load_config(self.config_path)
            self._apply_live_config(fresh)
            if self._settings is not None:
                self._settings.load(fresh)
            return "Reloaded from disk."

        updates = collect(values)  # raises ValueError, which the window reports
        previous = dict(self.config)
        result = save_config(self.config_path, updates)
        self._apply_live_config(load_config(self.config_path))
        note = restart_note(updates, previous=previous, restart_hint=self._settings_restart_hint())
        if result["backup"]:
            note += f"\nPrevious config saved as {os.path.basename(result['backup'])}"
        return note

    def _apply_live_config(self, fresh: dict):
        """Fold a freshly loaded config into the running one, in place.

        In place because the ping, resolution and router-window closures hold
        this dict: rebinding self.config left them reading the launch values, so
        a saved ping_host changed nothing. Restart-only keys keep their launch
        values, so the running config matches what the running objects were
        built from.
        """
        self.config.update({k: v for k, v in fresh.items() if k not in NEEDS_RESTART})

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
                reason="ping" if ping["down"] else self.last_classification,
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
                permissions=self._permission_rows(),
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

    def _permission_rows(self) -> list:
        if not self.capabilities.privileged_repairs:
            # One row saying why, rather than the usual rows reading "not granted"
            # beside a hint to press Grant, which this build cannot honour.
            return [
                (
                    "Elevated permissions",
                    distribution.unavailable("privileged_repairs", "elevated permissions"),
                )
            ]
        return privileges.status_rows(
            granted=self.privileges_granted,
            # What the grant covers, not what the machine has.
            interfaces=self.granted_interfaces,
            primary=self.primary_dhcp_interface,
            file_rule_listed=self.privileges_file_rule_listed,
        )

    def _unavailable_text(self, feature: str, what: str) -> Optional[str]:
        """None when this build has `feature`; otherwise the text saying it does not."""
        if getattr(self.capabilities, feature):
            return None
        return distribution.unavailable(feature, what)

    def handle_dashboard_action(self, action_id: str):
        """A button was clicked. Main thread.

        Anything that shells out goes to a worker: repair_executor allows 5s per
        step and a full ladder is four of them, so running inline would freeze the
        window and all four timers for up to half a minute -- the same reason the
        ping does not run here.
        """
        gate = GATED_DASHBOARD_ACTIONS.get(action_id)
        if gate is not None:
            text = self._unavailable_text(*gate)
            if text is not None:
                # Before any branch below, so no worker starts and no window or
                # subprocess is attempted for a feature this build lacks.
                self._append_output(f"\n>>> {action_id}\n{text}\n")
                return
        if action_id == "open_router_window":
            try:
                self._open_router_window()
            except Exception as exc:  # noqa: BLE001 - a window failure must not cost the click
                self._append_output(f"Router console failed: {type(exc).__name__}\n")
            return
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
        # Per step, never around a loop: tick() waits for this lock on the run
        # loop during an incident, so holding it across a whole ladder would
        # freeze the window and every timer for all of it.
        with self.state_machine.lock:
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
        # The configured classifications, not ladder_for's default: that default
        # adds the failover step to every network ladder, so a manual diagnosis
        # attempted a failover the configuration had not put on the ladder.
        steps = ladder_for(classification, self.state_machine.failover_classifications)
        if not steps:
            lines.append(
                "No ladder for this classification -- nothing is broken, or "
                "`domains` is empty so DNS could not be judged."
            )
            return lines
        for step in steps:
            # Per step, for the reason given in _single_step. The classification
            # goes with it: without one the failover step assumes "network",
            # and a DNS fault on a DNS-only trigger list read as "not a trigger".
            with self.state_machine.lock:
                outcome = self.state_machine.repair_executor(step, classification.value)
            lines.append(f"[{step.kind}] {step.name}")
            lines.append(f"    why: {step.reason}")
            lines.append(f"    result: {outcome}")
            events.append({"detail": step.name, "reason": step.reason, "result": outcome})
        return lines

    # --- notifications -----------------------------------------------------

    def _send_notification(self, text: str):
        """Hand the notification to a worker and return immediately.

        Slack and email are network I/O, and this is called from the poll
        timer's callback -- the run loop that also draws the window and drives
        the 5s heartbeat. Two channels at `notify_timeout_seconds` each is a
        10-second freeze at the exact moment the network is known to be broken,
        which is when the heartbeat and the Dock tile matter most.

        Not a queue-and-drain like the troubleshooting steps: nothing on the
        main thread needs the outcome in order to draw anything, so the result
        is published straight onto the attribute the console's `:status` and the
        tests read. `notifier` returns a list of per-channel results and does not
        raise -- a delivery failure is recorded and swallowed inside it, because
        a Slack outage must not stop the report being saved.
        """

        def deliver():
            try:
                self.last_notification_results = self.notifier(text)
            except Exception as exc:  # noqa: BLE001 - belt and braces; notifier swallows
                self.last_notification_results = [
                    {"channel": "unknown", "ok": False, "error": type(exc).__name__}
                ]

        try:
            # Kept on the instance like `_ping_thread` and `_resolution_thread`,
            # so a caller that needs the send to have finished -- the suite --
            # can join it instead of sleeping and hoping.
            self._notification_thread = threading.Thread(
                target=deliver, name="notification", daemon=True
            )
            self._notification_thread.start()
        except RuntimeError:
            # Thread creation can fail under resource pressure. Sending inline is
            # worse than a lost notification only if it hangs, and the notifier
            # is timeout-bounded, so this degrades rather than drops.
            deliver()

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

    def _menu_layout(self) -> list:
        """The status-item menu for this build.

        An item for a feature this build lacks is left out rather than greyed
        out. Each such item is built here with an explicit callback, not with
        `@rumps.clicked`: that decorator registers on the class, and `App.run`
        adds every path it names that the menu lacks. A decorated "Open console"
        would come back the moment the store build ran, whatever this list says.
        """
        caps = self.capabilities
        items: list = [
            # Readouts first: they carry no callback, so they read as a status
            # header rather than as choices.
            *self.failover_rows,
            None,
            # The dashboard stays the first thing that can be clicked -- the status
            # item is easy to miss on a notched menu bar, which is why it leads.
            "Open dashboard",
        ]
        if caps.shell_console:
            # The failover line's own "Open console…" item is gone: this line's
            # console is the arbitrary-shell one, reachable from here and from the
            # dashboard button, and both go through the single controller.
            items.append(rumps.MenuItem("Open console", callback=self.open_console))
        # With an explicit callback: a bare title that no `@rumps.clicked` names
        # is drawn greyed out, and this one was, in both builds.
        items += [
            "Toggle mini window",
            rumps.MenuItem("Open last report", callback=self.open_last_report),
            None,
        ]
        if caps.router:
            items.append(self._router_menu())
        if caps.launch_agent_login_item:
            items.append(rumps.MenuItem("Start at Login", callback=self.toggle_login))
        items += ["Test network alert", self._credentials_menu()]
        if caps.requires_ai_consent:
            items += [
                rumps.MenuItem(CONSENT_ITEM, callback=self.allow_claude_diagnosis),
                rumps.MenuItem(WITHDRAW_CONSENT_ITEM, callback=self.withdraw_claude_permission),
            ]
        if caps.is_app_store:
            items.append(rumps.MenuItem(PRIVACY_POLICY_ITEM, callback=self.open_privacy_policy))
        items.append(None)
        if caps.network_order_write:
            # Below the everyday items, and behind a separator, because these two
            # rewrite the system's network service order.
            items += [
                rumps.MenuItem("Switch to backup now", callback=self.switch_to_backup),
                rumps.MenuItem("Switch back to preferred now", callback=self.switch_to_preferred),
            ]
        # Kept in every build: listing the service order is a read, and the
        # sandbox allows it.
        items.append(rumps.MenuItem("Refresh network status", callback=self.refresh_failover))
        return items

    def _router_menu(self) -> rumps.MenuItem:
        router_menu = rumps.MenuItem("Router")
        router_menu.update(
            [
                rumps.MenuItem("Management Console", callback=self.open_router_window),
                rumps.MenuItem("Configure...", callback=self.configure_router),
                rumps.MenuItem("Start", callback=self.start_router),
                rumps.MenuItem("Stop", callback=self.stop_router),
                rumps.MenuItem("List Interfaces", callback=self.list_interfaces),
                rumps.MenuItem("Troubleshoot", callback=self.troubleshoot_router),
            ]
        )
        return router_menu

    def _credentials_menu(self) -> rumps.MenuItem:
        credentials_menu = rumps.MenuItem(CREDENTIALS_MENU)
        items: list = [
            rumps.MenuItem(title, callback=lambda _sender, name=name: self.set_credential(name))
            for title, name, _message in CREDENTIAL_ITEMS
        ]
        items += [None, rumps.MenuItem(REMOVE_CREDENTIALS_ITEM, callback=self.remove_credentials)]
        credentials_menu.update(items)
        return credentials_menu

    # --- credentials ---------------------------------------------------------

    def set_credential(self, name: str) -> str:
        """Ask for one credential, save it to the Keychain, and apply it now.

        The value goes from the dialog to CredentialStore.set and nowhere else.
        What is shown afterwards is the store's outcome text, which names the
        credential and never contains the value.
        """
        title, message = next(
            (title, message) for title, item_name, message in CREDENTIAL_ITEMS if item_name == name
        )
        try:
            value = self.secret_prompt(title.rstrip("…"), f"{message}\n\n{CREDENTIAL_STORAGE_NOTE}")
        except Exception as exc:  # noqa: BLE001 - a dialog failure must not cost the menu
            outcome = f"failed: the dialog could not be shown ({type(exc).__name__})"
            self._notify(CREDENTIALS_MENU, outcome)
            return outcome
        if value is None:
            # Cancelled: nothing to save and nothing to announce.
            return "cancelled: nothing was changed"
        try:
            outcome = self.credentials.set(name, value)
        except Exception as exc:  # noqa: BLE001 - class name only, never the message
            outcome = f"failed: the Keychain write raised {type(exc).__name__}"
        if outcome.startswith("ok:"):
            problem = self._apply_credentials()
            if problem is not None:
                outcome += f"; not applied to the running app ({problem}), restart to use it"
            elif self._credential_source(name) == "environment":
                # Saved, but not what the app reads: the environment wins.
                outcome += (
                    f"; not in use, because {name} is also set in the environment, "
                    "which takes precedence"
                )
            else:
                outcome += "; in use now"
        self._notify(CREDENTIALS_MENU, outcome)
        return outcome

    def remove_credentials(self, _sender=None) -> str:
        """Delete all three of this app's Keychain items, after asking."""
        try:
            confirmed = self.choice_prompt(
                "Remove saved credentials?",
                "This deletes the Anthropic API key, Slack webhook URL and SMTP password that "
                "this app saved in your Keychain. Values set as environment variables are "
                "not affected.",
                "Remove",
                "Cancel",
            )
        except Exception as exc:  # noqa: BLE001 - a dialog failure must not cost the menu
            outcome = f"failed: the dialog could not be shown ({type(exc).__name__})"
            self._notify(CREDENTIALS_MENU, outcome)
            return outcome
        if not confirmed:
            return "cancelled: nothing was changed"
        outcomes = []
        for name in credentials.NAMES:
            try:
                outcomes.append(self.credentials.delete(name))
            except Exception as exc:  # noqa: BLE001 - one failure must not skip the others
                outcomes.append(f"failed: removing {name} raised {type(exc).__name__}")
        problem = self._apply_credentials()
        if problem is not None:
            outcomes.append(f"not applied to the running app ({problem}), restart to use it")
        still_set = [n for n in credentials.NAMES if self._credential_source(n) == "environment"]
        if still_set:
            outcomes.append(
                f"still set in the environment, and still in use: {', '.join(still_set)}"
            )
        outcome = "\n".join(outcomes)
        self._notify(CREDENTIALS_MENU, outcome)
        return outcome

    def _credential_source(self, name: str) -> Optional[str]:
        try:
            return self.credentials.source(name)
        except Exception:  # noqa: BLE001 - only decides whether to add a note
            return None

    def _apply_credentials(self) -> Optional[str]:
        """Rebuild what reads credentials, in place. None, or the failure's class name.

        Both are attribute rebinds. A notification already being delivered, or an
        escalation already under way, finishes with what it started with; the
        next one uses the new value.
        """
        try:
            self.notifier = build_notifier(self.config, env=self.credentials.as_env())
            self.state_machine.escalator = build_escalator(
                self.capabilities, self.credentials, self.consent
            )
        except Exception as exc:  # noqa: BLE001 - the Keychain change already happened
            return type(exc).__name__
        return None

    # --- Claude permission (store build) -------------------------------------

    def _refresh_consent_menu(self):
        if self.consent is None:
            return
        self.menu[CONSENT_ITEM].state = self.consent.granted()

    def allow_claude_diagnosis(self, _sender=None) -> str:
        """Show what would be sent, and record the answer.

        "Don't Allow" withdraws an earlier grant. Someone who opens this dialog,
        reads the list and declines has answered the question, and a grant left in
        place would keep sending incident data they just refused.
        """
        if self.consent is None:
            return "disabled: this build does not ask; setting ANTHROPIC_API_KEY is the opt-in"
        try:
            allowed = self.choice_prompt(
                "Allow Claude diagnosis?", ai_consent.DISCLOSURE, "Allow", "Don't Allow"
            )
        except Exception as exc:  # noqa: BLE001 - no dialog means no answer, so no change
            outcome = f"failed: the dialog could not be shown ({type(exc).__name__})"
            self._notify("Claude diagnosis", outcome)
            return outcome
        if allowed:
            outcome = self.consent.grant()
        elif self.consent.granted():
            outcome = self.consent.revoke()
        else:
            return "cancelled: nothing was changed"
        self._refresh_consent_menu()
        self._notify("Claude diagnosis", outcome)
        return outcome

    def withdraw_claude_permission(self, _sender=None) -> str:
        if self.consent is None:
            return "disabled: this build does not ask; unset ANTHROPIC_API_KEY to opt out"
        outcome = self.consent.revoke()
        self._refresh_consent_menu()
        self._notify("Claude diagnosis", outcome)
        return outcome

    def open_privacy_policy(self, _sender=None) -> str:
        url = self.privacy_policy_url_fn()
        if not url:
            outcome = (
                "No privacy policy URL is bundled with this copy of the app "
                f"({PRIVACY_POLICY_URL_KEY} is not set in its Info.plist)."
            )
            self._notify(PRIVACY_POLICY_ITEM, outcome)
            return outcome
        try:
            opened = bool(self.url_opener(url))
        except Exception:  # noqa: BLE001 - report it, never crash the menu
            opened = False
        if not opened:
            outcome = f"failed: could not open {url}"
            self._notify(PRIVACY_POLICY_ITEM, outcome)
            return outcome
        return f"ok: opened {url}"

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

    def open_console(self, _sender=None):
        """Open the console, building it on first use.

        Takes `_sender=None` so the dashboard button can call this directly:
        both surfaces land on the one controller held at `self.console`, which
        is what keeps them the same console rather than two with separate
        working directories and separate history.

        Guarded, an idea carried over from the failover line's console: building
        an AppKit window can fail, and a failure to open the console must cost
        the console and nothing else. rumps 0.4.0 catches an exception in
        MenuItem.callback_, so the timers would survive one, but the click would
        do nothing visible and a half-built controller would be kept. `console_window`
        itself imports AppKit inside its methods rather than at module scope, so
        the import at the top of this file is safe; it is `show()` that can raise.
        """
        text = self._unavailable_text("shell_console", "the console")
        if text is not None:
            self._notify("Console", text)
            return
        try:
            if self.console is None:
                self.console = ConsoleWindowController(status=self.status_snapshot)
            self.console.show()
        except Exception as exc:  # noqa: BLE001 - a failed window must say so
            # Cleared so a later attempt rebuilds rather than reusing a
            # half-constructed controller.
            self.console = None
            rumps.notification(
                "Net/DNS Monitor",
                "Console",
                f"Could not open the console window ({type(exc).__name__}). "
                "`python3 -m netdnsmonitor.cli console` is the terminal equivalent.",
            )

    @rumps.clicked("Toggle mini window")
    def toggle_mini_window_clicked(self, _sender):
        self.toggle_mini_window()

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
        if not self.capabilities.network_order_write and lines and lines[0].startswith("Active: "):
            # "failover is automatic" would be false here: nothing can switch.
            lines[0] = lines[0].split(" — ")[0] + " — read-only in this build"
        # strict=False: the padded list is longer than the rows on purpose.
        for row, text in zip(
            self.failover_rows, lines + [""] * len(self.failover_rows), strict=False
        ):
            # An empty title would leave a clickable-looking blank row.
            row.title = text or " "

    def _manual_switch(self, target: str, label: str):
        text = self._unavailable_text("network_order_write", f"switching to the {label} network")
        if text is not None:
            # Ahead of the configuration check: no config can make this work here.
            self._notify("Network failover", text)
            return
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
        text = failover_status_text(self.failover)
        unavailable = self._unavailable_text("network_order_write", "switching networks")
        if self.failover is not None and unavailable is not None:
            text = f"{text} {unavailable}"
        rumps.notification("Net/DNS Monitor", "Network failover", text)

    def open_last_report(self, _sender=None) -> str:
        """Through `url_opener`, as the privacy policy is: see
        open_url_with_workspace for why not `webbrowser`. Reached from the menu
        and from the dashboard's "Open last incident report".
        """
        path = self.last_report_path
        if not path:
            outcome = "No report has been generated yet."
            self._notify("Last report", outcome)
            return outcome
        detail = ""
        try:
            # as_uri() percent-encodes: the default reports_dir sits under
            # "Application Support", and a raw space makes an invalid file URL.
            opened = bool(self.url_opener(pathlib.Path(path).as_uri()))
        except Exception as exc:  # noqa: BLE001 - class name only, never raised into the menu
            opened = False
            detail = f" ({type(exc).__name__})"
        if not opened:
            outcome = f"failed: could not open {path}{detail}"
            self._notify("Last report", outcome)
            return outcome
        return f"ok: opened {path}"

    @rumps.clicked("Test network alert")
    def test_network_alert(self, _sender):
        """Fire the alert on demand.

        Whether macOS actually draws a notification banner depends on
        notification authorisation for this bundle, which the process cannot
        observe from the inside. This makes that answerable in one click instead
        of by waiting for a real outage.
        """
        alert.network_failed(self.config["ping_host"], error="test alert, not a real outage")

    # --- router ------------------------------------------------------------

    def _notify(self, subtitle: str, message: str):
        """A notification that cannot raise into a menu callback."""
        try:
            rumps.notification("Net/DNS Monitor", subtitle, message)
        except Exception:  # noqa: BLE001 - a lost banner must not cost the click
            traceback.print_exc()

    def _router_unavailable(self) -> bool:
        """True, after announcing it, in a build without the router.

        The store build's menu has no Router submenu, so this only matters to a
        caller that reaches these handlers some other way.
        """
        text = self._unavailable_text("router", "the router")
        if text is None:
            return False
        self._notify("Router", text)
        return True

    def _open_router_window(self):
        """Raises on failure; each caller reports it where its user is looking."""
        if self._router_unavailable():
            return
        try:
            if self.router_window is None:
                # A getter and the path, not a copy of the dict: the window writes
                # its own keys through save_config, and reads the live config.
                # The key through the credential store: an app started by
                # LaunchServices has no shell environment, so a Keychain key is
                # the only one it can have.
                self.router_window = RouterWindowController(
                    config_getter=lambda: self.config,
                    config_path=self.config_path,
                    app=self,
                    api_key_getter=lambda: self.credentials.get("ANTHROPIC_API_KEY"),
                )
            self.router_window.show()
        except Exception:
            # Cleared so a later attempt rebuilds rather than reusing a
            # half-constructed controller.
            self.router_window = None
            raise

    def open_router_window(self, _sender=None):
        try:
            self._open_router_window()
        except Exception as exc:  # noqa: BLE001 - a failed window must say so
            self._notify(
                "Router console",
                f"Could not open the router console window ({type(exc).__name__}).",
            )

    def configure_router(self, _sender=None):
        """Open the config file this app actually loaded, creating it if absent.

        `open -t` on a missing file exits non-zero and shows nothing, and the
        path used to be hardcoded rather than the one passed to the app.
        """
        if self._router_unavailable():
            return
        path = self.config_path
        try:
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if not os.path.exists(path):
                with open(path, "a", encoding="utf-8"):
                    pass
            result = self.router_run_fn([OPEN_BIN, "-t", path], check=False, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            self._notify("Router", f"Could not open {path} ({type(exc).__name__}).")
            return
        code = getattr(result, "returncode", 0)
        if code != 0:
            self._notify("Router", f"Could not open {path} (open exited {code}).")

    def _router_or_notify(self):
        if self._router_unavailable():
            return None
        if self.router is None:
            self._notify("Router", "Router disabled (set router_enabled)")
        return self.router

    def _start_router_worker(
        self,
        slot: str,
        label: str,
        work: Callable[[], object],
        reveal: bool = False,
    ) -> bool:
        """Run `work` on a worker and queue its text for the UI tick to show.

        Two slots, so a diagnostics read is not refused while the admin dialog
        for Start waits on a password -- and two Starts never stack. `reveal`
        opens the dashboard for output too long for a notification.
        """
        running = getattr(self, slot)
        if running is not None and running.is_alive():
            self._notify("Router", f"{label}: the previous router action is still running.")
            return False

        def runner():
            try:
                outcome = work()
            except Exception as exc:  # noqa: BLE001 - a worker must not die silently
                outcome = f"failed: {type(exc).__name__}"
            self._router_results.put((label, str(outcome), reveal))

        thread = threading.Thread(target=runner, name=f"router{slot}", daemon=True)
        try:
            thread.start()
        except RuntimeError as exc:
            self._notify(
                "Router", f"{label}: failed: could not start a worker ({type(exc).__name__})"
            )
            return False
        setattr(self, slot, thread)
        return True

    def _drain_router_results(self):
        """Main thread: print each outcome to the results pane and announce it.

        The pane, rather than rumps.alert, because an alert is modal: it holds
        the run loop, and with it every monitoring timer, until someone clicks OK.
        """
        while True:
            try:
                label, text, reveal = self._router_results.get_nowait()
            except queue.Empty:
                return
            if reveal:
                try:
                    self.open_dashboard()
                except Exception:  # noqa: BLE001 - the notification still reports it
                    traceback.print_exc()
            self._append_output(f"\n>>> {label}\n{text}\n")
            first = text.strip().splitlines()[0] if text.strip() else "(no output)"
            self._notify("Router", f"{label}: {first[:200]}")

    def start_router(self, _sender=None):
        router = self._router_or_notify()
        if router is not None:
            self._start_router_worker("_router_thread", "Start router", router.start)

    def stop_router(self, _sender=None):
        router = self._router_or_notify()
        if router is not None:
            self._start_router_worker("_router_thread", "Stop router", router.stop)

    def _router_interfaces(self) -> tuple:
        router = self.router
        if router is not None:
            return router.wan_if, router.lan_if
        return self.config["wan_interface"], self.config["lan_interface"]

    def list_interfaces(self, _sender=None):
        if self._router_unavailable():
            return
        run_fn = self.router_run_fn

        def work() -> str:
            names = get_interfaces(run_fn)
            if not names:
                return "Could not list network interfaces."
            return "\n".join(names)

        self._start_router_worker("_router_info_thread", "Network interfaces", work, reveal=True)

    def troubleshoot_router(self, _sender=None):
        if self._router_unavailable():
            return
        run_fn = self.router_run_fn
        wan, lan = self._router_interfaces()

        def work() -> str:
            lines = collect_diagnostics(run_fn, wan, lan)
            lines.append("\n" + router_nat_text(run_fn))
            return "\n".join(lines)

        self._start_router_worker("_router_info_thread", "Router diagnostics", work, reveal=True)

    # --- login item ----------------------------------------------------------

    def toggle_login(self, sender):
        """Install or remove this item's LaunchAgent, then show what is on disk.

        The checkmark is set from the files after the write, never flipped
        before it: a write that failed used to leave the item checked with no
        agent installed. The service script's agent is reported but not
        removed here -- it carries the supervision flag, and
        `net-dns-monitor-service uninstall` is what takes it out.
        """
        text = self._unavailable_text("launch_agent_login_item", "Start at Login")
        if text is not None:
            # The reason already names the replacement: System Settings' Login Items.
            self._notify("Start at Login", text)
            return
        own = login_agent_path(LOGIN_AGENT_LABEL)
        service = login_agent_path(SERVICE_AGENT_LABEL)
        try:
            if login_item_installed():
                if os.path.exists(own):
                    os.remove(own)
                if os.path.exists(service):
                    self._notify(
                        "Start at Login",
                        "Still on: net-dns-monitor-service installed its own login agent. "
                        "Run `net-dns-monitor-service uninstall` to remove it.",
                    )
            else:
                frozen = bool(getattr(sys, "frozen", False))
                executable = _bundle_executable() if frozen else sys.executable
                source_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                plist = login_agent_plist(frozen, executable, source_root)
                os.makedirs(os.path.dirname(own), exist_ok=True)
                staged = own + ".tmp"
                try:
                    with open(staged, "wb") as f:
                        plistlib.dump(plist, f)
                    os.replace(staged, own)
                finally:
                    if os.path.exists(staged):
                        os.remove(staged)
        except OSError as exc:
            self._notify("Start at Login", f"Not changed ({type(exc).__name__}).")
        sender.state = login_item_installed()


STARTUP_FAILED_TITLE = "Net-DNS-Monitor could not start"


def show_startup_alert(title: str, message: str) -> None:
    """Modal, which is acceptable only here: no timer has started, so there is
    no monitoring for it to hold up. rumps.App.run activates the shared
    application before any alert of its own; this runs before run(), so it
    does the same.
    """
    from AppKit import NSApplication

    NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
    rumps.alert(title=title, message=message)


def main(
    app_factory: Optional[Callable[..., rumps.App]] = None,
    startup_alert: Callable[[str, str], object] = show_startup_alert,
    config_path: str = DEFAULT_CONFIG_PATH,
) -> None:
    factory = NetDnsMonitorApp if app_factory is None else app_factory
    try:
        app = factory(config_path=config_path)
    except (ConfigError, ValueError, yaml.YAMLError) as exc:
        # Started from Finder, the Dock or a LaunchAgent, a traceback on stderr
        # reaches nobody: the app never appears, and Settings, which could fix
        # the file, never opens. config_error_text keeps a YAML message, which
        # quotes the file, out of both.
        problem = config_error_text(exc)
        print(f"{STARTUP_FAILED_TITLE}: {problem}", file=sys.stderr)
        print(f"Config file: {config_path}", file=sys.stderr)
        try:
            startup_alert(STARTUP_FAILED_TITLE, f"{problem}\n\nConfig file: {config_path}")
        except Exception:  # noqa: BLE001 - stderr already has it; still exit 2
            traceback.print_exc()
        sys.exit(2)
    app.run()


if __name__ == "__main__":
    main()
