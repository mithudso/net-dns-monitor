"""The Router Management Console window.

Everything that decides something lives in the plain functions at the top of
this file, which the offline suite covers; the controller below them only reads
widgets and draws text. AppKit, PyObjC and `anthropic` are imported lazily so
the module imports on a machine with no GUI session and costs nothing at app
start.

Every subprocess, the Anthropic client, and the hop back to the main thread
are injected. Anything slow runs on a worker thread: a blocking wait on the
main thread freezes the window, the menu bar, and the rumps timers doing the
actual monitoring.
"""

import ipaddress
import os
import re
import subprocess
import threading
from collections.abc import Mapping
from typing import Callable, Optional

import yaml

from netdnsmonitor.router import DEFAULTS

RunFn = Callable[..., object]

STYLE_MASK = 1 | 2 | 4 | 8
RESIZE_BOTH = 18

COMMAND_TIMEOUT_SECONDS = 5.0
# `ping -c 4` takes about four seconds when every reply arrives and longer when
# they do not; this bounds the worst case without cutting off a normal run.
PING_TIMEOUT_SECONDS = 20.0
AI_MAX_TOKENS = 1000

ROUTER_KEYS = tuple(DEFAULTS)
# Config key -> Router attribute. Router validates these when it starts, so
# writing them here cannot put an unchecked value into the root script.
_ROUTER_ATTRS = {
    "wan_interface": "wan_if",
    "lan_interface": "lan_if",
    "lan_ip": "lan_ip",
    "lan_netmask": "lan_netmask",
    "dhcp_start": "dhcp_start",
    "dhcp_end": "dhcp_end",
}

_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?"
)
# Client MAC addresses appear in `netstat -rn` link-layer rows. Judging a router
# config does not need them, so they never leave the machine.
_MAC_RE = re.compile(r"\b[0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5}\b")


# --- pure helpers ----------------------------------------------------------


def _capture(run_fn: RunFn, argv: list, timeout: float = COMMAND_TIMEOUT_SECONDS):
    """(stdout, None) on success, or (None, reason). Never raises."""
    try:
        result = run_fn(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        return None, type(exc).__name__
    if getattr(result, "returncode", 1) != 0:
        return None, f"exit {getattr(result, 'returncode', '?')}"
    return getattr(result, "stdout", "") or "", None


def parse_interfaces(output: str) -> list:
    interfaces = []
    current_name = None
    for line in output.splitlines():
        if line.startswith("Hardware Port:"):
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and current_name:
            device = line.split(":", 1)[1].strip()
            interfaces.append(f"{current_name} ({device})")
            current_name = None
    return interfaces


def get_interfaces(run_fn: RunFn = subprocess.run) -> list:
    """Interface titles like "Wi-Fi (en0)", or [] if they could not be listed."""
    out, _error = _capture(run_fn, ["networksetup", "-listallhardwareports"])
    return parse_interfaces(out) if out is not None else []


def device_from_title(title) -> Optional[str]:
    """`None` when nothing is selected. Guessing "en0" here once meant an empty
    popup could start a router on an interface nobody chose.
    """
    if not title or "(" not in title:
        return None
    return str(title).rsplit("(", 1)[-1].strip(")") or None


def router_updates(values: Mapping) -> dict:
    """Only the router's own keys, so a save cannot rewrite anything else."""
    return {key: values[key] for key in ROUTER_KEYS if key in values}


def ping_target(text) -> Optional[str]:
    """The target if it is an IPv4 address or a hostname, else None.

    The text is passed to `ping` as an argument, so a leading `-` would be read
    as an option.
    """
    candidate = (text or "").strip()
    if not candidate:
        return None
    try:
        return str(ipaddress.IPv4Address(candidate))
    except ValueError:
        pass
    if _HOSTNAME_RE.fullmatch(candidate):
        return candidate
    return None


def bootpd_status(run_fn: RunFn = subprocess.run) -> str:
    """bootpd is socket-activated: launchd holds UDP 67 while the job is loaded
    and bootpd itself only runs when a request arrives, so `bootpd` in `ps` says
    nothing about whether the port is taken.
    """
    try:
        result = run_fn(
            ["/bin/launchctl", "print", "system/com.apple.bootpd"],
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        return f"bootpd job: not checked ({type(exc).__name__})"
    if getattr(result, "returncode", 1) == 0:
        return "bootpd job loaded (UDP 67 held)"
    return "bootpd job not loaded"


def collect_diagnostics(run_fn: RunFn, wan: Optional[str], lan: Optional[str]) -> list:
    lines = ["--- Diagnostics & Routing Status ---"]
    routes, error = _capture(run_fn, ["netstat", "-rn", "-f", "inet"])
    lines.append(
        "\nRouting Table:\n" + routes
        if routes is not None
        else f"\nRouting table: not checked ({error})"
    )
    fwd, error = _capture(run_fn, ["sysctl", "net.inet.ip.forwarding"])
    lines.append(
        "\n" + fwd.strip() if fwd is not None else f"\nIP forwarding: not checked ({error})"
    )
    lines.append(bootpd_status(run_fn))
    if wan is not None and wan == lan:
        lines.append("\n!!! OBVIOUS CONFLICT: WAN and LAN are set to the same interface !!!")
    return lines


def build_ai_prompt(values: Mapping, routes: str, forwarding: str) -> str:
    return (
        "Analyze this macOS router/Internet Sharing config:\n"
        f"WAN: {values.get('wan_interface')}\nLAN: {values.get('lan_interface')}\n"
        f"LAN IP: {values.get('lan_ip')}\nNetmask: {values.get('lan_netmask')}\n"
        f"DHCP: {values.get('dhcp_start')}-{values.get('dhcp_end')}\n"
        f"\nRouting table:\n{routes}\n\nIP Forwarding: {forwarding}\n"
        "Is this config logically sound? Provide brief feedback and subnet/route suggestions."
    )


def redact_prompt(prompt: str, sensitive_strings) -> str:
    from netdnsmonitor.escalation import redact

    return redact(_MAC_RE.sub("[MAC]", prompt), list(sensitive_strings or []))


def ai_config_check(
    values: Mapping,
    run_fn: RunFn,
    sensitive_strings,
    api_key: Optional[str],
    client_factory: Optional[Callable[[], object]] = None,
) -> str:
    """Run the check and return the text to show. Never raises."""
    if not api_key:
        return "skipped: ANTHROPIC_API_KEY not set"
    from netdnsmonitor.anthropic_escalator import (
        DEFAULT_MODEL,
        DEFAULT_TIMEOUT_SECONDS,
        default_client,
    )

    routes, error = _capture(run_fn, ["netstat", "-rn", "-f", "inet"])
    if routes is None:
        routes = f"(not available: {error})"
    fwd, error = _capture(run_fn, ["sysctl", "net.inet.ip.forwarding"])
    fwd = fwd.strip() if fwd is not None else f"(not available: {error})"
    prompt = redact_prompt(build_ai_prompt(values, routes, fwd), sensitive_strings)
    try:
        client = (client_factory or default_client)()
        response = client.messages.create(
            model=DEFAULT_MODEL,
            max_tokens=AI_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        text = response.content[0].text
    except Exception as exc:  # noqa: BLE001 - shown in the window, never raised into it
        # The class name only: an authentication error's message can carry
        # request details, and this text is drawn on screen.
        return f"\nAI Check Failed: {type(exc).__name__}"
    return "\n[AI Analysis]\n" + text


# --- AppKit shell ----------------------------------------------------------

_ROUTER_TARGET_CLASS = None


def _router_target_class():
    global _ROUTER_TARGET_CLASS
    if _ROUTER_TARGET_CLASS is None:
        import objc
        from Foundation import NSObject

        class _RouterTarget(NSObject):
            def initWithController_(self, ctrl):
                self = objc.super(_RouterTarget, self).init()
                if self is None:
                    return None
                self._controller = ctrl
                return self

            def onStart_(self, sender):
                self._controller.on_start()

            def onStop_(self, sender):
                self._controller.on_stop()

            def onPing_(self, sender):
                self._controller.on_ping()

            def onRefresh_(self, sender):
                self._controller.on_refresh()

            def onAiCheck_(self, sender):
                self._controller.on_ai_check()

            def onSaveConfig_(self, sender):
                self._controller.on_save_config()

        _ROUTER_TARGET_CLASS = _RouterTarget
    return _ROUTER_TARGET_CLASS


def make_label(x, y, w, h, text):
    import AppKit
    from Foundation import NSMakeRect

    lbl = AppKit.NSTextField.alloc().initWithFrame_(NSMakeRect(x, y, w, h))
    lbl.setStringValue_(text)
    lbl.setBezeled_(False)
    lbl.setDrawsBackground_(False)
    lbl.setEditable_(False)
    lbl.setSelectable_(False)
    return lbl


def make_textfield(x, y, w, h, text):
    import AppKit
    from Foundation import NSMakeRect

    tf = AppKit.NSTextField.alloc().initWithFrame_(NSMakeRect(x, y, w, h))
    tf.setStringValue_(text)
    return tf


def _default_post(fn, *args):
    from PyObjCTools.AppHelper import callAfter

    callAfter(fn, *args)


def _default_spawn(fn):
    threading.Thread(target=fn, daemon=True).start()


class RouterWindowController:
    def __init__(
        self,
        config_getter: Optional[Callable[[], Mapping]] = None,
        config_path: Optional[str] = None,
        app=None,
        run_fn: RunFn = subprocess.run,
        client_factory: Optional[Callable[[], object]] = None,
        post: Optional[Callable[..., None]] = None,
        spawn: Optional[Callable[[Callable[[], None]], None]] = None,
        environ: Optional[Mapping] = None,
        config: Optional[Mapping] = None,
    ):
        # `config` is the old keyword: a dict captured once. A getter sees the
        # app's current config instead of whatever it was when the window opened.
        if config_getter is None:
            captured = config if config is not None else {}

            def config_getter():
                return captured

        if config_path is None and app is not None:
            config_path = getattr(app, "config_path", None)
        self.config_getter = config_getter
        self.config_path = config_path
        self.app = app
        self.run_fn = run_fn
        self.client_factory = client_factory
        self.post = post or _default_post
        self.spawn = spawn or _default_spawn
        self.environ = environ if environ is not None else os.environ
        self.window = None
        self.text_view = None
        self.interfaces: list = []
        self._busy = False

    # --- config ------------------------------------------------------------

    def _config(self) -> Mapping:
        try:
            current = self.config_getter()
        except Exception:  # noqa: BLE001 - a broken getter must not break the window
            return {}
        return current if isinstance(current, Mapping) else {}

    def _default(self, key):
        return self._config().get(key, DEFAULTS[key])

    # --- window ------------------------------------------------------------

    def show(self):
        import AppKit

        if self.window is None:
            self.interfaces = get_interfaces(self.run_fn)
            self._target = _router_target_class().alloc().initWithController_(self)
            self._build_window()
            if not self.interfaces:
                self.append_log("Could not list network interfaces.")
        self.window.makeKeyAndOrderFront_(None)
        AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.on_refresh()

    def _button(self, content, frame, title, action):
        import AppKit
        from Foundation import NSMakeRect

        btn = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(*frame))
        btn.setTitle_(title)
        btn.setTarget_(self._target)
        btn.setAction_(action)
        btn.setBezelStyle_(1)  # NSRoundedBezelStyle
        content.addSubview_(btn)
        return btn

    def _build_window(self):
        import AppKit
        from AppKit import NSBackingStoreBuffered, NSFont
        from Foundation import NSMakeRect

        self.window = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 800, 600), STYLE_MASK, NSBackingStoreBuffered, False
        )
        self.window.setTitle_("Router Management Console")
        self.window.setReleasedWhenClosed_(False)
        self.window.center()
        content = self.window.contentView()

        y = 550
        content.addSubview_(make_label(10, y, 100, 24, "WAN Interface:"))
        self.wan_popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(120, y, 250, 24), False
        )
        self.wan_popup.addItemsWithTitles_(self.interfaces)
        self._select_interface(self.wan_popup, self._default("wan_interface"))
        content.addSubview_(self.wan_popup)

        content.addSubview_(make_label(400, y, 100, 24, "LAN Interface:"))
        self.lan_popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(500, y, 250, 24), False
        )
        self.lan_popup.addItemsWithTitles_(self.interfaces)
        self._select_interface(self.lan_popup, self._default("lan_interface"))
        content.addSubview_(self.lan_popup)

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "LAN IP:"))
        self.lan_ip = make_textfield(120, y, 150, 24, str(self._default("lan_ip")))
        content.addSubview_(self.lan_ip)

        content.addSubview_(make_label(290, y, 80, 24, "Netmask:"))
        self.lan_nm = make_textfield(370, y, 150, 24, str(self._default("lan_netmask")))
        content.addSubview_(self.lan_nm)

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "DHCP Start:"))
        self.dhcp_s = make_textfield(120, y, 150, 24, str(self._default("dhcp_start")))
        content.addSubview_(self.dhcp_s)

        content.addSubview_(make_label(290, y, 80, 24, "DHCP End:"))
        self.dhcp_e = make_textfield(370, y, 150, 24, str(self._default("dhcp_end")))
        content.addSubview_(self.dhcp_e)

        y -= 40
        self._button(content, (10, y, 120, 24), "Save Config", "onSaveConfig:")
        self._button(content, (140, y, 120, 24), "Start Router", "onStart:")
        self._button(content, (270, y, 120, 24), "Stop Router", "onStop:")
        self._button(content, (400, y, 150, 24), "Refresh Diagnostics", "onRefresh:")
        self._button(content, (560, y, 150, 24), "AI Config Check", "onAiCheck:")

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "Ping Target:"))
        self.ping_field = make_textfield(120, y, 200, 24, "8.8.8.8")
        content.addSubview_(self.ping_field)
        self._button(content, (330, y, 100, 24), "Ping", "onPing:")

        y -= 20
        scroll = AppKit.NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 10, 780, y))
        scroll.setHasVerticalScroller_(True)
        scroll.setAutoresizingMask_(RESIZE_BOTH)
        self.text_view = AppKit.NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 780, y))
        self.text_view.setEditable_(False)
        self.text_view.setRichText_(False)
        self.text_view.setFont_(NSFont.userFixedPitchFontOfSize_(12))
        self.text_view.setBackgroundColor_(AppKit.NSColor.blackColor())
        self.text_view.setTextColor_(AppKit.NSColor.whiteColor())
        scroll.setDocumentView_(self.text_view)
        content.addSubview_(scroll)

    def _select_interface(self, popup, device):
        for i, item in enumerate(self.interfaces):
            if f"({device})" in item:
                popup.selectItemAtIndex_(i)
                break

    def _form_values(self) -> dict:
        return {
            "wan_interface": device_from_title(self.wan_popup.titleOfSelectedItem()),
            "lan_interface": device_from_title(self.lan_popup.titleOfSelectedItem()),
            "lan_ip": str(self.lan_ip.stringValue()).strip(),
            "lan_netmask": str(self.lan_nm.stringValue()).strip(),
            "dhcp_start": str(self.dhcp_s.stringValue()).strip(),
            "dhcp_end": str(self.dhcp_e.stringValue()).strip(),
        }

    def append_log(self, text):
        if self.text_view is None:
            print(text)  # headless fallback, used by the tests
            return
        from Foundation import NSMakeRange

        current = self.text_view.string() or ""
        self.text_view.setString_(current + text + "\n")
        self.text_view.scrollRangeToVisible_(NSMakeRange(len(self.text_view.string()), 0))

    def _clear_log(self):
        if self.text_view is not None:
            self.text_view.setString_("")

    def _in_background(self, work: Callable[[], Optional[str]]) -> bool:
        """Run `work` off the main thread and post the text it returns."""

        def runner():
            try:
                result = work()
            except Exception as exc:  # noqa: BLE001 - a worker must not die silently
                result = f"failed: {type(exc).__name__}"
            if result:
                self.post(self.append_log, result)

        try:
            self.spawn(runner)
        except RuntimeError as exc:
            self.append_log(f"failed: could not start a worker ({type(exc).__name__})")
            return False
        return True

    # --- actions -----------------------------------------------------------

    def on_save_config(self, values: Optional[Mapping] = None) -> bool:
        values = dict(values) if values is not None else self._form_values()
        if not values.get("wan_interface") or not values.get("lan_interface"):
            self.append_log("not saved: select both a WAN and a LAN interface")
            return False
        updates = router_updates(values)

        router = getattr(self.app, "router", None)
        if router is not None:
            for key, attr in _ROUTER_ATTRS.items():
                if key in updates:
                    setattr(router, attr, updates[key])

        if not self.config_path:
            self.append_log("not saved: no config file path")
            return False
        from netdnsmonitor.settings_window import save_config

        try:
            result = save_config(self.config_path, updates)
        except (OSError, ValueError, yaml.YAMLError) as exc:
            self.append_log(f"Error saving config: {type(exc).__name__}")
            return False
        current = self._config()
        if isinstance(current, dict):
            current.update(updates)
        backup = result.get("backup") if isinstance(result, Mapping) else None
        suffix = f" (previous file backed up to {backup})" if backup else ""
        self.append_log(f"Configuration saved to {self.config_path}{suffix}.")
        return True

    def _router_action(self, label: str, action: Callable[[], object]) -> None:
        if self._busy:
            self.append_log("(the previous router action is still running)")
            return
        self._busy = True

        def work():
            try:
                outcome = action()
            finally:
                self._busy = False
            return f"{label}: {outcome}"

        if not self._in_background(work):
            # The worker's `finally` never ran, so the flag is cleared here or
            # every later click is refused as "still running".
            self._busy = False

    def on_start(self, values: Optional[Mapping] = None):
        values = dict(values) if values is not None else self._form_values()
        self.append_log("Starting router...")
        if values.get("wan_interface") and values.get("wan_interface") == values.get(
            "lan_interface"
        ):
            self.append_log("refused: WAN and LAN are the same interface")
            return
        router = getattr(self.app, "router", None)
        if router is None:
            self.append_log("Router module not loaded.")
            return
        self.on_save_config(values)
        self._router_action("Start router", router.start)

    def on_stop(self):
        self.append_log("Stopping router...")
        router = getattr(self.app, "router", None)
        if router is None:
            self.append_log("Router module not loaded.")
            return
        self._router_action("Stop router", router.stop)

    def on_ping(self, text: Optional[str] = None):
        raw = text if text is not None else str(self.ping_field.stringValue())
        target = ping_target(raw)
        if target is None:
            self.append_log(f"\nrefused: {raw!r} is not an IPv4 address or hostname")
            return
        self.append_log(f"\nPinging {target}...")
        run_fn = self.run_fn

        def work():
            try:
                result = run_fn(
                    ["ping", "-c", "4", target],
                    capture_output=True,
                    text=True,
                    timeout=PING_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
                return f"Ping failed: {type(exc).__name__}"
            output = (getattr(result, "stdout", "") or "") + (getattr(result, "stderr", "") or "")
            if getattr(result, "returncode", 1) == 0:
                return output
            return f"Ping failed:\n{output}"

        self._in_background(work)

    def on_refresh(self, values: Optional[Mapping] = None):
        values = dict(values) if values is not None else self._form_values()
        self._clear_log()
        run_fn = self.run_fn
        wan, lan = values.get("wan_interface"), values.get("lan_interface")
        self._in_background(lambda: "\n".join(collect_diagnostics(run_fn, wan, lan)))

    def on_ai_check(self, values: Optional[Mapping] = None):
        values = dict(values) if values is not None else self._form_values()
        self.append_log("\nAnalyzing config with Anthropic AI...")
        sensitive = self._config().get("sensitive_strings", [])
        api_key = self.environ.get("ANTHROPIC_API_KEY")
        run_fn, factory = self.run_fn, self.client_factory
        self._in_background(
            lambda: ai_config_check(values, run_fn, sensitive, api_key, client_factory=factory)
        )
