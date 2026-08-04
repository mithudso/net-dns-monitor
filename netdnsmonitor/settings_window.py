"""Edit every configurable option in a window, instead of in a text editor.

**Saving rewrites the live config, and that loses its comments.** The repo's
tracked default `config.yaml` carries ~100 lines of them, and they are not
decoration -- the note explaining that an empty `domains` list latches a
permanent false incident is the kind of thing someone needs to read again a year
later. YAML round-tripping with comments intact needs ruamel.yaml, a dependency
this project does not have and would have to freeze into the bundle.

So instead:

* Every save first copies the current file to `config.yaml.bak-<epoch>`. The
  timestamp is the important part. A single fixed `.bak` would be overwritten by
  the second save with the already-stripped version, and the only commented copy
  would be gone -- exactly when someone is clicking Save repeatedly.
* The written file carries a header pointing back at the repo's own tracked
  `config.yaml`, which still has every explanation. That is a *different* file
  from the one being overwritten: this window writes the per-machine copy at
  `~/.config/net-dns-monitor/config.yaml`. Since both are now called config.yaml,
  the header names each by full path rather than by filename alone.
* The window says so before you click, not after.

**Most changes need a restart**, because they are read once in `App.__init__` --
timer intervals, alert thresholds, the peer windows. The window says which, since
otherwise someone changes a threshold, sees no difference, and reasonably
concludes the setting does not work.
"""

import os
import time
import traceback
from typing import Callable, Optional

import yaml

# (key, label, kind). Grouped in display order. `kind` drives parsing, and a
# wrong kind is the difference between 5 and "5" reaching bind() or a timer.
GROUPS = [
    (
        "Ping heartbeat",
        [
            ("ping_host", "Host to ping", "str"),
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
            ("external_targets", "Internet targets (host:port, comma separated)", "targets"),
            ("internal_targets", "LAN targets (host:port, comma separated)", "targets"),
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
        "Files and folders",
        [
            ("reports_dir", "Incident reports", "str"),
            ("resolution_log_path", "Resolution log", "str"),
            ("forensic_log_path", "Forensic journal", "str"),
            ("forensic_episodes_dir", "Forensic episodes", "str"),
            ("peer_record_path", "Peer record", "str"),
            ("history_path", "Graph history", "str"),
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
}

FIELDS = [(key, label, kind) for _group, fields in GROUPS for key, label, kind in fields]

HEADER = """# Written by Net-DNS-Monitor's settings window.
#
# Comments from a hand-edited config are NOT preserved by that window. The repo's
# tracked default config.yaml still carries the full explanation of every key
# below, including the warning about leaving `domains` empty.
#
# The previous version of this file was saved alongside it as
# config.yaml.bak-<timestamp>.
"""


def format_field(kind: str, value) -> str:
    """Config value -> text for the field."""
    if kind == "bool":
        return "yes" if value else "no"
    if kind == "list":
        return ", ".join(str(v) for v in (value or []))
    if kind == "targets":
        return ", ".join(f"{host}:{port}" for host, port in (value or []))
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
        targets = []
        for part in (p.strip() for p in text.split(",")):
            if not part:
                continue
            host, _, port = part.rpartition(":")
            if not host or not port.strip().isdigit():
                raise ValueError(f"{name}: expected host:port entries, got {part!r}")
            targets.append([host.strip(), int(port)])
        return targets
    if kind == "int":
        try:
            return int(float(text))
        except (ValueError, OverflowError):
            # OverflowError is not hypothetical: float("inf") parses fine and
            # int() then refuses it, and that exception is not a ValueError -- so
            # it escaped past the window's handler into an AppKit callback, where
            # the click simply appeared to do nothing.
            raise ValueError(f"{name}: expected a whole number, got {text!r}") from None
    if kind == "float":
        try:
            value = float(text)
        except ValueError:
            raise ValueError(f"{name}: expected a number, got {text!r}") from None
        # inf/nan parse as floats and would reach a timer interval or a timeout.
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError(f"{name}: expected a finite number, got {text!r}")
        return value
    return text


def collect(values: dict) -> dict:
    """Parse a {key: text} mapping into typed config values.

    Every field is parsed before anything is written, so one bad value means
    nothing is saved rather than half a config being applied.
    """
    parsed = {}
    for key, label, kind in FIELDS:
        if key in values:
            parsed[key] = parse_field(kind, values[key], label)
    return parsed


def backup_path(path: str, clock: Callable[[], float] = time.time) -> str:
    return f"{path}.bak-{int(clock())}"


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
    """
    if writer is None:
        from netdnsmonitor.report_storage import _atomic_write

        writer = _atomic_write

    on_disk = {}
    if existing is not None:
        on_disk = dict(existing)
    elif os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                on_disk = loaded
        except (OSError, UnicodeError, yaml.YAMLError):
            # An unreadable or malformed file must not block saving a good one --
            # that is the situation someone opens this window to get out of.
            # UnicodeError specifically: a config that is not valid UTF-8 raises
            # UnicodeDecodeError, which is not an OSError, and it escaped.
            on_disk = {}

    backup = None
    if os.path.isfile(path):
        backup = backup_path(path, clock)
        try:
            with open(path, encoding="utf-8") as f:
                writer(backup, f.read())
        except (OSError, UnicodeError):
            # Same reason as above. Failing to back up must not stop the save --
            # but it must be reported as "no backup" rather than claimed.
            backup = None

    merged = {**on_disk, **updates}
    body = yaml.safe_dump(merged, default_flow_style=False, sort_keys=True, allow_unicode=True)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    writer(path, HEADER + "\n" + body)
    return {"path": path, "backup": backup}


def restart_note(updates: dict) -> str:
    """Which of these need a restart, in words for the window."""
    pending = sorted(key for key in updates if key in NEEDS_RESTART)
    if not pending:
        return "Saved. These take effect immediately."
    return (
        "Saved. These need a restart to take effect "
        f"({len(pending)}): {', '.join(pending)}.\n"
        "Run: net-dns-monitor-service restart"
    )


# --- the window ------------------------------------------------------------

WINDOW_WIDTH = 560
ROW_HEIGHT = 26
LABEL_WIDTH = 300
FIELD_WIDTH = 210
GROUP_GAP = 24
CHROME_HEIGHT = 132


class SettingsWindow:
    """A field per option, in a scrolling list. Retained by App, like the others."""

    def __init__(self, on_save: Callable[[dict], str]):
        import AppKit

        from netdnsmonitor.dashboard import _label, _make_button_target

        self.on_save = on_save
        self.fields = {}
        self._target = _make_button_target(self._handle)

        rows = sum(len(fields) for _g, fields in GROUPS)
        content_height = rows * ROW_HEIGHT + len(GROUPS) * GROUP_GAP + 20
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
            AppKit.NSMakeRect(16, visible_height + 62, WINDOW_WIDTH - 32, 56),
            "Saving rewrites ~/.config/net-dns-monitor/config.yaml and does not keep its\n"
            "comments. The previous file is backed up as config.yaml.bak-<timestamp>.\n"
            "Most changes need: net-dns-monitor-service restart",
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
        for group, fields in GROUPS:
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
            self.status.setStringValue_("Reloaded from disk.")
            self.on_save(None)

    def load(self, config: dict):
        for key, _label, kind in FIELDS:
            field = self.fields.get(key)
            if field is not None:
                field.setStringValue_(format_field(kind, config.get(key)))

    def show(self):
        import AppKit

        self.window.makeKeyAndOrderFront_(None)
        AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

    def set_status(self, text: str):
        self.status.setStringValue_(text)
