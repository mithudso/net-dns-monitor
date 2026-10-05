"""Edit every configurable option in a window, instead of in a text editor.

**Saving rewrites the live config, and that loses its comments.** The repo's
tracked default `config.yaml` carries ~100 lines of them, and they are not
decoration -- the note explaining why `failover_probe_timeout_seconds` has to
grow with the target list is the kind of thing someone needs to read again a
year later. YAML round-tripping with comments intact needs ruamel.yaml, a
dependency this project does not have and would have to freeze into the bundle.

So instead:

* Every save first copies the current file, byte for byte, to
  `config.yaml.bak-<epoch>` (with `-1`, `-2`, ... appended if that name is
  taken). A single fixed `.bak` would be overwritten by the second save with the
  already-stripped version, and the only commented copy would be gone -- exactly
  when someone is clicking Save repeatedly. A bare one-second timestamp fails the
  same way for two saves inside one second.
* The written file carries a header pointing back at the default `config.yaml`
  that ships with the app, which still has every explanation. That is a
  *different* file from the one being overwritten: this window writes the
  per-machine copy at `~/.config/net-dns-monitor/config.yaml`, which install.sh
  first copied from it. The header names the backup it took, and says nothing
  about a backup when none could be taken.
* The window says so before you click, not after.
* Nothing is written unless the whole resulting config passes the same checks
  `load_config` applies. A file it rejects would leave the app unable to start.

**Most changes need a restart**, because they are read once in `App.__init__` --
timer intervals, alert thresholds, the peer windows. The window says which, since
otherwise someone changes a threshold, sees no difference, and reasonably
concludes the setting does not work.
"""

import os
import shutil
import time
import traceback
from typing import Callable, Optional

import yaml

from netdnsmonitor.config import (
    DEFAULT_CONFIG,
    PATH_KEYS,
    ConfigError,
    min_learn_interval,
    normalize_config,
    target_problem,
    validate_config,
)

# (key, label, kind). Grouped in display order. `kind` drives parsing, and a
# wrong kind is the difference between 5 and "5" reaching bind() or a timer.
GROUPS = [
    (
        "Ping heartbeat",
        [
            ("ping_host_v6", "IPv6 host to ping first (blank = off)", "str"),
            ("ping_host", "Host to ping", "str"),
            ("ping_fallback_host", "Fallback host to ping (blank = off)", "str"),
            ("ping_interval_seconds", "Ping every (seconds)", "int"),
            ("ping_timeout_seconds", "Ping timeout (seconds)", "float"),
            ("ping_failure_threshold", "Alert after N failed pings", "int"),
            ("ping_alert_repeat_seconds", "Re-alert every (0 = never)", "int"),
            ("ping_loss_window", "Loss averaged over N pings", "int"),
        ],
    ),
    (
        "Incident detection",
        [
            ("external_targets", "Internet targets (IP:port, comma separated)", "targets"),
            ("internal_targets", "LAN targets (IP:port, comma separated)", "targets"),
            ("poll_interval_seconds", "Probe every (seconds)", "int"),
            ("failure_threshold", "Incident after N failures", "int"),
            ("success_threshold", "Clear after N successes", "int"),
            ("domains", "Domains checked for DNS (comma separated)", "list"),
            ("log_lookback", "Log lookback window", "str"),
            ("sensitive_strings", "Redact from escalations (comma separated)", "list"),
        ],
    ),
    (
        "Resolution monitor",
        [
            ("resolution_interval_seconds", "Batch every (seconds)", "int"),
            ("resolution_stall_seconds", "Counts as a stall at (seconds)", "float"),
            ("resolution_batch_deadline_seconds", "Batch deadline (seconds)", "int"),
            ("resolution_timeout_seconds", "Per-lookup timeout (advisory)", "float"),
            ("resolution_max_workers", "Parallel lookups", "int"),
        ],
    ),
    (
        "Windows and graphs",
        [
            ("open_dashboard_at_launch", "Open dashboard at launch", "bool"),
            ("auto_open_console", "Open console at launch", "bool"),
            ("ui_refresh_seconds", "Window refresh (seconds)", "int"),
            ("dock_refresh_seconds", "Dock tile refresh (seconds)", "int"),
            ("history_max_samples", "Graph history samples", "int"),
        ],
    ),
    (
        "LAN peer discovery",
        [
            ("peer_discovery_enabled", "Enabled (broadcasts hostname + health)", "bool"),
            ("peer_port", "UDP port", "int"),
            ("peer_announce_seconds", "Announce every (seconds)", "int"),
            ("peer_current_seconds", "Counts as current for (seconds)", "int"),
            ("peer_recent_seconds", "Counts as recent for (seconds)", "int"),
            ("peer_probe_wait_seconds", "Wait for peer replies (seconds)", "int"),
        ],
    ),
    (
        "System log viewer",
        [
            ("log_view_enabled", "Enabled", "bool"),
            ("log_view_errors_only", "Start with errors only", "bool"),
            ("log_view_backfill_window", "Backfill window at launch", "str"),
            ("log_view_poll_window", "Poll window", "str"),
            ("log_view_poll_seconds", "Poll every (seconds)", "int"),
            ("log_view_timeout_seconds", "Read timeout (seconds)", "int"),
            ("log_view_max_entries", "Entries held in memory", "int"),
            ("log_view_row_limit", "Rows drawn in the pane", "int"),
            ("log_view_announce_limit", "New errors announced per poll", "int"),
            ("log_view_noise_patterns", "Drop entries containing (comma separated)", "list"),
        ],
    ),
    (
        # Service names are free text on purpose: they must match
        # `networksetup -listallnetworkservices` exactly, and a dropdown built
        # from a cached list would go stale the moment an adapter is unplugged.
        "Network failover",
        [
            ("failover_enabled", "Fail over automatically", "bool"),
            ("failover_preferred_service", "Preferred service", "str"),
            ("failover_backup_service", "Backup service", "str"),
            ("failover_backup_services", "Additional backups (comma separated)", "list"),
            ("failover_trigger_classifications", "Trigger on (comma separated)", "list"),
            ("failover_failback_threshold", "Healthy ticks before failback", "int"),
            ("failover_cooldown_seconds", "Cooldown between switches (seconds)", "int"),
            ("failover_max_switches_per_hour", "Maximum switches per hour", "int"),
            (
                # "targets", not "list": these are host/port pairs and need the
                # same parser `external_targets` uses. As a plain list the window
                # would save ["192.168.68.1:53"] -- strings, not pairs -- and the
                # prober would silently probe nothing.
                "failover_probe_targets",
                "Reachability probe targets (IP:port, comma separated)",
                "targets",
            ),
            ("failover_probe_timeout_seconds", "Reachability probe budget (0 = default)", "float"),
            ("failover_speedtest_host", "Throughput probe host", "str"),
            ("failover_speedtest_path", "Throughput probe path", "str"),
            ("failover_speedtest_port", "Throughput probe port", "int"),
            ("failover_speedtest_timeout_seconds", "Throughput probe timeout (seconds)", "float"),
            ("failover_speedtest_max_bytes", "Throughput probe max bytes", "int"),
        ],
    ),
    (
        "Domain learning",
        [
            # "float", not "int": the default is 2.0, and int(float("0.5")) is 0 --
            # a timeout that makes every connect fail at once.
            ("probe_timeout_seconds", "Probe timeout (seconds)", "float"),
            ("control_domain", "Control domain (known-good name)", "str"),
            ("learn_domains_from_logs", "Learn domains from the log", "bool"),
            ("max_learned_domains", "Maximum learned domains", "int"),
            ("domain_learn_interval_seconds", "Learn every (seconds)", "int"),
        ],
    ),
    (
        # The two secrets are deliberately absent: the Slack webhook URL comes
        # from SLACK_WEBHOOK_URL and the SMTP password from SMTP_PASSWORD, so a
        # config file that gets shared or synced carries no credential. Putting
        # either in this window would write it straight into config.yaml.
        "Notifications",
        [
            ("slack_enabled", "Send to Slack", "bool"),
            ("email_enabled", "Send email", "bool"),
            ("email_recipients", "Email recipients (comma separated)", "list"),
            ("email_from", "From address", "str"),
            ("smtp_host", "SMTP host", "str"),
            ("smtp_port", "SMTP port", "int"),
            ("smtp_username", "SMTP username", "str"),
            ("smtp_starttls", "Use STARTTLS", "bool"),
            ("notify_timeout_seconds", "Send timeout (seconds)", "int"),
        ],
    ),
    (
        "Files and folders",
        [
            ("reports_dir", "Incident reports", "str"),
            ("learned_domains_path", "Learned domains", "str"),
            ("failover_state_path", "Failover state", "str"),
            ("resolution_log_path", "Resolution log", "str"),
            ("forensic_log_path", "Forensic journal", "str"),
            ("forensic_episodes_dir", "Forensic episodes", "str"),
            ("peer_record_path", "Peer record", "str"),
            ("history_path", "Graph history", "str"),
        ],
    ),
    (
        # The in-app router conflicts with the standalone router/ stack: both
        # rewrite pf NAT rules and run DHCP on the LAN interface.
        "Router (not with the router/ stack)",
        [
            ("router_enabled", "Enable Router menu (bootpd; admin)", "bool"),
            ("wan_interface", "Upstream interface (e.g. en3)", "str"),
            ("lan_interface", "LAN interface (e.g. en0)", "str"),
            ("lan_ip", "LAN address", "str"),
            ("lan_netmask", "LAN netmask", "str"),
            ("dhcp_start", "DHCP range start", "str"),
            ("dhcp_end", "DHCP range end", "str"),
        ],
    ),
]

# Read once in App.__init__, so editing them changes nothing until a restart.
NEEDS_RESTART = {
    "external_targets",
    "internal_targets",
    "reports_dir",
    "resolution_log_path",
    "forensic_log_path",
    "forensic_episodes_dir",
    "peer_record_path",
    "history_path",
    "ping_interval_seconds",
    "ping_failure_threshold",
    "ping_alert_repeat_seconds",
    "ping_loss_window",
    "poll_interval_seconds",
    "failure_threshold",
    "success_threshold",
    "domains",
    "log_lookback",
    "sensitive_strings",
    "resolution_interval_seconds",
    "ui_refresh_seconds",
    "history_max_samples",
    # Turning discovery off at runtime only makes peer_tick return early. The
    # socket and its reader keep answering PROBE with this machine's hostname and
    # health until a restart closes them.
    "peer_discovery_enabled",
    "peer_port",
    "peer_announce_seconds",
    "peer_current_seconds",
    "peer_recent_seconds",
    # The log viewer's timer, buffer, reader and starting filter are all built
    # once in App.__init__. The window's own controls change the live filter; the
    # config values behind them do not take effect until a restart.
    "log_view_enabled",
    "log_view_errors_only",
    "log_view_backfill_window",
    "log_view_poll_seconds",
    "log_view_timeout_seconds",
    "log_view_max_entries",
    # The prober, the learner and its store are built once in build_state_machine,
    # and the notifier once in App.__init__ -- editing any of these changes
    # nothing until a restart.
    "probe_timeout_seconds",
    "control_domain",
    "learn_domains_from_logs",
    "learned_domains_path",
    "max_learned_domains",
    "domain_learn_interval_seconds",
    "slack_enabled",
    "email_enabled",
    "email_recipients",
    "email_from",
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_starttls",
    "notify_timeout_seconds",
    # NetworkFailover and its store are built once in App.__init__ too.
    "failover_enabled",
    "failover_preferred_service",
    "failover_backup_service",
    "failover_backup_services",
    "failover_trigger_classifications",
    "failover_failback_threshold",
    "failover_cooldown_seconds",
    "failover_max_switches_per_hour",
    "failover_state_path",
    "failover_probe_targets",
    "failover_probe_timeout_seconds",
    "failover_speedtest_host",
    "failover_speedtest_path",
    "failover_speedtest_port",
    "failover_speedtest_timeout_seconds",
    "failover_speedtest_max_bytes",
    # The Router is built once in App.__init__ but never started there: only
    # Router > Start or the router window starts it. That object is built from
    # these keys at launch, so a change here needs a restart to reach it.
    "router_enabled",
    "wan_interface",
    "lan_interface",
    "lan_ip",
    "lan_netmask",
    "dhcp_start",
    "dhcp_end",
}

FIELDS = [(key, label, kind) for _group, fields in GROUPS for key, label, kind in fields]
LABELS = {key: label for key, label, _kind in FIELDS}

HEADER = """# Written by Net-DNS-Monitor's settings window.
#
# Comments from a hand-edited config are NOT preserved by that window. The
# tracked default config.yaml in the Net-DNS-Monitor repository -- the file
# install.sh copies into place on first install -- still explains every key below.
"""

# Appended only when a backup was actually written, so the file never claims a
# copy that does not exist.
BACKUP_NOTE = """#
# The previous version of this file was saved alongside it as {name}.
"""


def format_field(kind: str, value) -> str:
    """Config value -> text for the field."""
    if kind == "bool":
        return "yes" if value else "no"
    if kind == "list":
        return ", ".join(str(v) for v in (value or []))
    if kind == "targets":
        # An entry that is not a pair is shown as written, not unpacked. An older
        # window saved ["192.168.68.1:53"] as plain strings, and unpacking one
        # raised inside open_settings, so the Settings window never opened.
        parts = []
        for target in value or []:
            if isinstance(target, (list, tuple)) and len(target) == 2:
                parts.append(f"{target[0]}:{target[1]}")
            else:
                parts.append(str(target))
        return ", ".join(parts)
    if value is None:
        return ""
    return str(value)


def parse_field(kind: str, text: str, label: str = ""):
    """Text from the field -> a typed config value.

    Raises ValueError naming the field. A silently wrong type here is worse than
    an error: `peer_port` as the string "45737" reaches `bind()` and raises
    TypeError deep in a worker, and `ping_interval_seconds` as a string makes a
    timer that never fires.
    """
    text = (text or "").strip()
    name = label or kind
    if kind == "bool":
        if text.lower() in ("yes", "true", "1", "on"):
            return True
        if text.lower() in ("no", "false", "0", "off"):
            return False
        raise ValueError(f"{name}: expected yes or no, got {text!r}")
    if kind == "list":
        return [part.strip() for part in text.split(",") if part.strip()]
    if kind == "targets":
        # app.py does `tuple(t)` on each entry and the prober unpacks host, port,
        # so a malformed entry has to be rejected here rather than raising inside
        # a probe on a background timer.
        # rpartition, so an IPv6 address keeps its own colons: fe80::1%en0:53.
        targets = []
        for part in (p.strip() for p in text.split(",")):
            if not part:
                continue
            host, _, port = part.rpartition(":")
            host, port = host.strip(), port.strip()
            if host.startswith("[") and host.endswith("]"):
                host = host[1:-1]
            if not host or not (port.isascii() and port.isdigit()):
                raise ValueError(f"{name}: expected IP:port entries, got {part!r}")
            target = [host, int(port)]
            problem = target_problem(target)
            if problem is not None:
                raise ValueError(f"{name}: {problem} (in {part!r})")
            targets.append(target)
        return targets
    if kind == "int":
        try:
            as_float = float(text)
            # "5.9" used to become 5 silently. A fraction is a typo or a
            # misunderstanding of the unit; saving a different number than the
            # one typed hides it.
            if as_float != int(as_float):
                raise ValueError(text)
            value = int(as_float)
        except (ValueError, OverflowError):
            # OverflowError is not hypothetical: float("inf") parses fine and
            # int() then refuses it, and that exception is not a ValueError -- so
            # it escaped past the window's handler into an AppKit callback, where
            # the click simply appeared to do nothing.
            raise ValueError(f"{name}: expected a whole number, got {text!r}") from None
        # Zero stays legal: it means "never" or "use the default" for several
        # keys. Below zero reaches rumps.Timer as an interval.
        if value < 0:
            raise ValueError(f"{name}: expected a whole number of 0 or more, got {text!r}")
        return value
    if kind == "float":
        try:
            value = float(text)
        except ValueError:
            raise ValueError(f"{name}: expected a number, got {text!r}") from None
        # inf/nan parse as floats and would reach a timer interval or a timeout.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"{name}: expected a finite number, got {text!r}")
        if value < 0:
            raise ValueError(f"{name}: expected a number of 0 or more, got {text!r}")
        return value
    return text


# Keys whose consumers treat 0 as "off by accident": a zero threshold or window
# would divide, never fire, or fire on nothing. Zero stays legal elsewhere.
MIN_ONE = frozenset(
    {"failure_threshold", "success_threshold", "ping_failure_threshold", "ping_loss_window"}
)


def collect(values: dict, current_config: Optional[dict] = None) -> dict:
    """Parse a {key: text} mapping into typed config values.

    Every field is parsed before anything is written, so one bad value means
    nothing is saved rather than half a config being applied.
    """
    parsed = {}
    for key, label, kind in FIELDS:
        if key in values:
            parsed[key] = parse_field(kind, values[key], label)
            if key in MIN_ONE and parsed[key] < 1:
                raise ValueError(
                    f"{label}: expected a whole number of 1 or more, got {values[key]!r}"
                )
    if "domain_learn_interval_seconds" in parsed:
        # load_config raises a too-short interval to 2 x poll without a word, so
        # the file would keep a number the app never uses. Refuse it here, judged
        # against the poll in the same submission, else the running config's.
        poll = parsed.get("poll_interval_seconds")
        if poll is None:
            poll = (current_config or {}).get(
                "poll_interval_seconds", DEFAULT_CONFIG["poll_interval_seconds"]
            )
        floor = min_learn_interval(poll)
        if parsed["domain_learn_interval_seconds"] < floor:
            raise ValueError(
                f"{LABELS.get('domain_learn_interval_seconds', 'domain_learn_interval_seconds')}: "
                f"must be at least {floor:g} seconds (twice the poll interval)"
            )
    # The checks load_config applies, on the fields that were sent. A value it
    # would refuse has to be refused here, before a file the app cannot start
    # from is written.
    try:
        validate_config(parsed)
    except ConfigError as exc:
        raise ValueError(f"{LABELS.get(exc.key, exc.key)}: {exc}") from None
    return parsed


def backup_path(
    path: str,
    clock: Callable[[], float] = time.time,
    exists: Callable[[str], bool] = os.path.exists,
) -> str:
    """`<path>.bak-<epoch>`, with -1, -2, ... appended until the name is free.

    The epoch has one-second resolution. Without the suffix, two saves inside
    one second pick the same name, and the second backup -- already stripped of
    comments -- replaces the only commented copy.
    """
    base = f"{path}.bak-{int(clock())}"
    candidate, n = base, 1
    while exists(candidate):
        candidate = f"{base}-{n}"
        n += 1
    return candidate


def _collapse_home(value):
    """/Users/<name>/x -> ~/x. load_config expands `~` on every read, so the file
    only needs the portable form. An absolute home path pins the file to one
    account, and under the App Store sandbox `~` resolves inside the app's
    container, so a saved absolute path would point outside it.
    """
    home = os.path.expanduser("~")
    if not isinstance(value, str) or home in ("", "~", os.sep):
        return value
    if value == home:
        return "~"
    if value.startswith(home + os.sep):
        return "~" + value[len(home) :]
    return value


def save_config(
    path: str,
    updates: dict,
    existing: Optional[dict] = None,
    clock: Callable[[], float] = time.time,
    writer: Optional[Callable[[str, str], None]] = None,
) -> dict:
    """Write the config, backing up whatever was there first.

    Returns {"path", "backup"} where backup is None if there was nothing to back
    up. The merge is onto the file's own contents rather than onto the running
    config, so a key the window does not expose is preserved rather than being
    silently reset to its default.

    Raises ValueError (a config.ConfigError naming the key), before anything is
    written, if load_config would refuse the merged result.
    """
    if writer is None:
        from netdnsmonitor.report_storage import _atomic_write

        writer = _atomic_write

    # A symlinked config.yaml (a dotfiles checkout, say) is written through to its
    # target. os.replace on the link path swaps the link for a regular file, and
    # the target silently stops receiving changes.
    real = os.path.realpath(path)

    on_disk = {}
    if existing is not None:
        on_disk = dict(existing)
    elif os.path.isfile(real):
        try:
            with open(real, encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                on_disk = loaded
        except (OSError, UnicodeError, yaml.YAMLError):
            # An unreadable or malformed file must not block saving a good one --
            # that is the situation someone opens this window to get out of.
            # UnicodeError specifically: a config that is not valid UTF-8 raises
            # UnicodeDecodeError, which is not an OSError, and it escaped.
            on_disk = {}

    merged = {**on_disk, **updates}
    candidate = {**DEFAULT_CONFIG, **merged}
    normalize_config(candidate)
    validate_config(candidate)
    for key in PATH_KEYS:
        if key in merged:
            merged[key] = _collapse_home(merged[key])

    backup = None
    if os.path.isfile(real):
        backup = backup_path(real, clock)
        try:
            with open(real, "rb") as f:
                raw = f.read()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                # Not UTF-8, so the text writer cannot take it. Copy the bytes:
                # skipping the backup here would overwrite the only copy of a
                # file nobody has been able to read back.
                shutil.copyfile(real, backup)
            else:
                writer(backup, text)
        except OSError:
            # Failing to back up must not stop the save -- but it must be
            # reported as "no backup" rather than claimed.
            backup = None

    header = HEADER
    if backup is not None:
        header += BACKUP_NOTE.format(name=os.path.basename(backup))
    body = yaml.safe_dump(merged, default_flow_style=False, sort_keys=True, allow_unicode=True)
    os.makedirs(os.path.dirname(real) or ".", exist_ok=True)
    writer(real, header + "\n" + body)
    return {"path": path, "backup": backup}


def _same(before, after) -> bool:
    # A null string setting is shown as a blank field, which parses back as "".
    # That round trip is not a change.
    return before == after or (before in (None, "") and after in (None, ""))


# How each build restarts. The store build ships no service script, so naming
# it there sends someone after a command that does not exist.
SERVICE_RESTART_HINT = "Run: net-dns-monitor-service restart"
STORE_RESTART_HINT = "Quit and reopen Net-DNS-Monitor."

# Where the direct build keeps its config. The store build's is inside its
# sandbox container, so the app passes the real path there instead.
DEFAULT_CONFIG_PATH_DISPLAY = "~/.config/net-dns-monitor/config.yaml"


def restart_note(
    updates: dict,
    previous: Optional[dict] = None,
    restart_hint: str = SERVICE_RESTART_HINT,
    changed: Optional[set] = None,
) -> str:
    """Which of these need a restart, in words for the window.

    `changed` is an alternative to `previous`: the set of keys whose text differs
    from what the window loaded.

    The window sends every field, so `updates` alone names every restart-only key
    whether or not it changed. Pass `previous` (the config as loaded before the
    save) to name only the keys whose value actually changed.
    """
    keys = list(updates)
    if previous is not None:
        keys = [key for key in keys if not _same(previous.get(key), updates[key])]
    if changed is not None:
        keys = [key for key in keys if key in changed]
    pending = sorted(key for key in keys if key in NEEDS_RESTART)
    if not pending:
        return "Saved. These take effect immediately."
    return (
        "Saved. These need a restart to take effect "
        f"({len(pending)}): {', '.join(pending)}.\n"
        f"{restart_hint}"
    )


def settings_notice(
    config_path_display: str = DEFAULT_CONFIG_PATH_DISPLAY,
    restart_hint: str = SERVICE_RESTART_HINT,
) -> str:
    """The warning above the fields. The path gets a line of its own: a sandbox
    container path is longer than the label is wide.
    """
    name = os.path.basename(config_path_display) or "config.yaml"
    return (
        "Saving rewrites this file and does not keep its comments:\n"
        f"{config_path_display}\n"
        f"The previous file is backed up as {name}.bak-<timestamp>.\n"
        f"Most changes need a restart. {restart_hint}"
    )


# --- the window ------------------------------------------------------------

WINDOW_WIDTH = 560
ROW_HEIGHT = 26
LABEL_WIDTH = 300
FIELD_WIDTH = 210
GROUP_GAP = 24
# Room for the notice's path line to wrap once: a sandbox container path runs
# past the width of the window.
NOTICE_HEIGHT = 70
CHROME_HEIGHT = 76 + NOTICE_HEIGHT


class SettingsWindow:
    """A field per option, in a scrolling list. Retained by App, like the others."""

    def __init__(
        self,
        on_save: Callable[[dict], str],
        config_path_display: Optional[str] = None,
        restart_hint: Optional[str] = None,
        hidden_keys: frozenset = frozenset(),
    ):
        import AppKit

        from netdnsmonitor.dashboard import _label, _make_button_target

        self.on_save = on_save
        self.fields = {}
        # Features the current build cannot run are not offered. A hidden key
        # has no field, so collect never sees it and save never writes it.
        self.hidden_keys = frozenset(hidden_keys)
        visible_groups = [
            (g, [f for f in fields if f[0] not in self.hidden_keys]) for g, fields in GROUPS
        ]
        visible_groups = [(g, fields) for g, fields in visible_groups if fields]
        # Field text as of the last load(), so a save can say which keys changed.
        self._loaded: dict[str, str] = {}
        self._target = _make_button_target(self._handle)

        rows = sum(len(fields) for _g, fields in visible_groups)
        content_height = rows * ROW_HEIGHT + len(visible_groups) * GROUP_GAP + 20
        visible_height = min(620, content_height)

        self.window = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            AppKit.NSMakeRect(0, 0, WINDOW_WIDTH, visible_height + CHROME_HEIGHT),
            AppKit.NSWindowStyleMaskTitled
            | AppKit.NSWindowStyleMaskClosable
            | AppKit.NSWindowStyleMaskResizable,
            AppKit.NSBackingStoreBuffered,
            False,
        )
        self.window.setTitle_("Net-DNS-Monitor Settings")
        self.window.setReleasedWhenClosed_(False)
        self.window.center()
        outer = self.window.contentView()

        # The warning goes above the fields, not in a dialog after saving: by then
        # the comments are already gone.
        self.notice = _label(
            AppKit,
            AppKit.NSMakeRect(16, visible_height + 62, WINDOW_WIDTH - 32, NOTICE_HEIGHT),
            settings_notice(
                config_path_display or DEFAULT_CONFIG_PATH_DISPLAY,
                restart_hint or SERVICE_RESTART_HINT,
            ),
            9.5,
        )
        outer.addSubview_(self.notice)

        scroll = AppKit.NSScrollView.alloc().initWithFrame_(
            AppKit.NSMakeRect(16, 52, WINDOW_WIDTH - 32, visible_height)
        )
        scroll.setHasVerticalScroller_(True)
        scroll.setBorderType_(AppKit.NSBezelBorder)
        document = AppKit.NSView.alloc().initWithFrame_(
            AppKit.NSMakeRect(0, 0, WINDOW_WIDTH - 52, content_height)
        )

        y = content_height - 10
        for group, fields in visible_groups:
            y -= GROUP_GAP
            document.addSubview_(
                _label(AppKit, AppKit.NSMakeRect(8, y, LABEL_WIDTH, 18), group.upper(), 10.0)
            )
            for key, label, _kind in fields:
                y -= ROW_HEIGHT
                suffix = "  (restart)" if key in NEEDS_RESTART else ""
                document.addSubview_(
                    _label(
                        AppKit,
                        AppKit.NSMakeRect(8, y + 3, LABEL_WIDTH, 18),
                        label + suffix,
                        10.5,
                    )
                )
                field = AppKit.NSTextField.alloc().initWithFrame_(
                    AppKit.NSMakeRect(LABEL_WIDTH + 12, y, FIELD_WIDTH, 21)
                )
                field.setFont_(
                    AppKit.NSFont.monospacedSystemFontOfSize_weight_(
                        10.5, AppKit.NSFontWeightRegular
                    )
                )
                document.addSubview_(field)
                self.fields[key] = field

        scroll.setDocumentView_(document)
        outer.addSubview_(scroll)

        for index, (title, action, key) in enumerate(
            [("Save", "save", "s"), ("Reload", "reload", "r")]
        ):
            button = AppKit.NSButton.alloc().initWithFrame_(
                AppKit.NSMakeRect(WINDOW_WIDTH - 32 - (index + 1) * 104, 14, 96, 28)
            )
            button.setTitle_(title)
            button.setBezelStyle_(AppKit.NSBezelStyleRounded)
            button.setTarget_(self._target)
            button.setAction_("invoke:")
            button.setIdentifier_(action)
            button.setKeyEquivalent_(key if action == "save" else "")
            outer.addSubview_(button)

        self.status = _label(AppKit, AppKit.NSMakeRect(16, 16, 260, 30), "", 9.5)
        outer.addSubview_(self.status)

    def _handle(self, sender):
        action = str(sender.identifier() or "")
        if action == "save":
            try:
                message = self.on_save({key: f.stringValue() for key, f in self.fields.items()})
            except ValueError as exc:
                # A parse error names the offending field. Reported in the window
                # rather than raised into an AppKit callback, where nobody sees it.
                self.status.setStringValue_(f"Not saved -- {exc}")
                return
            except Exception as exc:  # noqa: BLE001 - never raise into AppKit
                # Anything else -- a full disk, a read-only config directory. The
                # narrow ValueError catch let those escape into the ObjC callback,
                # where the click looked like it did nothing at all.
                traceback.print_exc()
                self.status.setStringValue_(f"Not saved -- {type(exc).__name__}: {exc}")
                return
            self.status.setStringValue_(message)
        elif action == "reload":
            # load_config raises on a malformed or refused file (YAMLError,
            # ValueError, UnicodeDecodeError). The status used to say "Reloaded
            # from disk." first and let that escape into the AppKit callback, so
            # the window claimed a reload that had not happened.
            try:
                message = self.on_save(None)
            except Exception as exc:  # noqa: BLE001 - never raise into AppKit
                traceback.print_exc()
                self.status.setStringValue_(f"Not reloaded -- {type(exc).__name__}: {exc}")
                return
            self.status.setStringValue_(
                message if isinstance(message, str) and message else "Reloaded from disk."
            )

    def load(self, config: dict):
        for key, _label, kind in FIELDS:
            field = self.fields.get(key)
            if field is not None:
                text = format_field(kind, config.get(key))
                field.setStringValue_(text)
                self._loaded[key] = text

    def changed_keys(self, values: dict) -> set:
        """Keys whose text differs from what load() put in the field."""
        return {key for key, text in values.items() if self._loaded.get(key) != text}

    def show(self):
        import AppKit

        self.window.makeKeyAndOrderFront_(None)
        AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    def set_status(self, text: str):
        self.status.setStringValue_(text)
