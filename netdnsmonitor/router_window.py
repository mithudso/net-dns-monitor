import subprocess
import threading
import traceback
import anthropic
from typing import Optional

try:
    import objc
    import AppKit
    from Foundation import NSObject, NSMakeRect, NSBackingStoreBuffered, NSAttributedString, NSMakeRange, NSFont
except ImportError:
    pass  # Not on macOS or no PyObjC

STYLE_MASK = 1 | 2 | 4 | 8
RESIZE_BOTH = 18

_ROUTER_TARGET_CLASS = None

def _router_target_class():
    global _ROUTER_TARGET_CLASS
    if _ROUTER_TARGET_CLASS is None:
        class _RouterTarget(NSObject):
            def initWithController_(self, ctrl):
                self = objc.super(_RouterTarget, self).init()
                if self is None: return None
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

def get_interfaces():
    out = subprocess.check_output(["networksetup", "-listallhardwareports"], text=True)
    interfaces = []
    current_name = None
    for line in out.splitlines():
        if line.startswith("Hardware Port:"):
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("Device:") and current_name:
            device = line.split(":", 1)[1].strip()
            interfaces.append(f"{current_name} ({device})")
            current_name = None
    return interfaces

def make_label(x, y, w, h, text):
    lbl = AppKit.NSTextField.alloc().initWithFrame_(NSMakeRect(x, y, w, h))
    lbl.setStringValue_(text)
    lbl.setBezeled_(False)
    lbl.setDrawsBackground_(False)
    lbl.setEditable_(False)
    lbl.setSelectable_(False)
    return lbl

def make_textfield(x, y, w, h, text):
    tf = AppKit.NSTextField.alloc().initWithFrame_(NSMakeRect(x, y, w, h))
    tf.setStringValue_(text)
    return tf

class RouterWindowController:
    def __init__(self, config: dict, app):
        self.config = config
        self.app = app
        self.window = None
        self.interfaces = get_interfaces()

    def show(self):
        if self.window is None:
            self._target = _router_target_class().alloc().initWithController_(self)
            self._build_window()
        self.window.makeKeyAndOrderFront_(None)
        AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
        self.on_refresh()

    def _build_window(self):
        self.window = AppKit.NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 800, 600), STYLE_MASK, NSBackingStoreBuffered, False
        )
        self.window.setTitle_("Router Management Console")
        self.window.setReleasedWhenClosed_(False)
        self.window.center()
        content = self.window.contentView()

        y = 550
        content.addSubview_(make_label(10, y, 100, 24, "WAN Interface:"))
        self.wan_popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(120, y, 250, 24), False)
        self.wan_popup.addItemsWithTitles_(self.interfaces)
        self._select_interface(self.wan_popup, self.config.get("wan_interface", "en0"))
        content.addSubview_(self.wan_popup)

        content.addSubview_(make_label(400, y, 100, 24, "LAN Interface:"))
        self.lan_popup = AppKit.NSPopUpButton.alloc().initWithFrame_pullsDown_(NSMakeRect(500, y, 250, 24), False)
        self.lan_popup.addItemsWithTitles_(self.interfaces)
        self._select_interface(self.lan_popup, self.config.get("lan_interface", "en1"))
        content.addSubview_(self.lan_popup)

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "LAN IP:"))
        self.lan_ip = make_textfield(120, y, 150, 24, self.config.get("lan_ip", "192.168.10.1"))
        content.addSubview_(self.lan_ip)

        content.addSubview_(make_label(290, y, 80, 24, "Netmask:"))
        self.lan_nm = make_textfield(370, y, 150, 24, self.config.get("lan_netmask", "255.255.255.0"))
        content.addSubview_(self.lan_nm)

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "DHCP Start:"))
        self.dhcp_s = make_textfield(120, y, 150, 24, self.config.get("dhcp_start", "192.168.10.100"))
        content.addSubview_(self.dhcp_s)

        content.addSubview_(make_label(290, y, 80, 24, "DHCP End:"))
        self.dhcp_e = make_textfield(370, y, 150, 24, self.config.get("dhcp_end", "192.168.10.200"))
        content.addSubview_(self.dhcp_e)

        y -= 40
        btn_save = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(10, y, 120, 24))
        btn_save.setTitle_("Save Config")
        btn_save.setTarget_(self._target)
        btn_save.setAction_("onSaveConfig:")
        btn_save.setBezelStyle_(1) # NSRoundedBezelStyle
        content.addSubview_(btn_save)

        btn_start = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(140, y, 120, 24))
        btn_start.setTitle_("Start Router")
        btn_start.setTarget_(self._target)
        btn_start.setAction_("onStart:")
        btn_start.setBezelStyle_(1)
        content.addSubview_(btn_start)

        btn_stop = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(270, y, 120, 24))
        btn_stop.setTitle_("Stop Router")
        btn_stop.setTarget_(self._target)
        btn_stop.setAction_("onStop:")
        btn_stop.setBezelStyle_(1)
        content.addSubview_(btn_stop)

        btn_ref = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(400, y, 150, 24))
        btn_ref.setTitle_("Refresh Diagnostics")
        btn_ref.setTarget_(self._target)
        btn_ref.setAction_("onRefresh:")
        btn_ref.setBezelStyle_(1)
        content.addSubview_(btn_ref)

        btn_ai = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(560, y, 150, 24))
        btn_ai.setTitle_("AI Config Check")
        btn_ai.setTarget_(self._target)
        btn_ai.setAction_("onAiCheck:")
        btn_ai.setBezelStyle_(1)
        content.addSubview_(btn_ai)

        y -= 40
        content.addSubview_(make_label(10, y, 100, 24, "Ping Target:"))
        self.ping_target = make_textfield(120, y, 200, 24, "8.8.8.8")
        content.addSubview_(self.ping_target)

        btn_ping = AppKit.NSButton.alloc().initWithFrame_(NSMakeRect(330, y, 100, 24))
        btn_ping.setTitle_("Ping")
        btn_ping.setTarget_(self._target)
        btn_ping.setAction_("onPing:")
        btn_ping.setBezelStyle_(1)
        content.addSubview_(btn_ping)

        y -= 20
        # Text view for output
        scroll = AppKit.NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 10, 780, y))
        scroll.setHasVerticalScroller_(True)
        scroll.setAutoresizingMask_(RESIZE_BOTH)
        self.text_view = AppKit.NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 780, y))
        self.text_view.setEditable_(False)
        self.text_view.setFont_(NSFont.userFixedPitchFontOfSize_(12))
        scroll.setDocumentView_(self.text_view)
        content.addSubview_(scroll)

    def _select_interface(self, popup, device):
        for i, item in enumerate(self.interfaces):
            if f"({device})" in item:
                popup.selectItemAtIndex_(i)
                break

    def _get_device(self, popup):
        title = popup.titleOfSelectedItem()
        if not title: return "en0"
        return title.split("(")[-1].strip(")")

    def append_log(self, text):
        storage = self.text_view.textStorage()
        storage.appendAttributedString_(NSAttributedString.alloc().initWithString_(text + "\n"))
        self.text_view.scrollRangeToVisible_(NSMakeRange(storage.length(), 0))

    def on_save_config(self):
        self.config["wan_interface"] = self._get_device(self.wan_popup)
        self.config["lan_interface"] = self._get_device(self.lan_popup)
        self.config["lan_ip"] = self.lan_ip.stringValue()
        self.config["lan_netmask"] = self.lan_nm.stringValue()
        self.config["dhcp_start"] = self.dhcp_s.stringValue()
        self.config["dhcp_end"] = self.dhcp_e.stringValue()
        
        # update router object if exists
        if self.app.router:
            self.app.router.wan_if = self.config["wan_interface"]
            self.app.router.lan_if = self.config["lan_interface"]
            self.app.router.lan_ip = self.config["lan_ip"]
            self.app.router.lan_netmask = self.config["lan_netmask"]
            self.app.router.dhcp_start = self.config["dhcp_start"]
            self.app.router.dhcp_end = self.config["dhcp_end"]
            
        import yaml
        config_path = os.path.expanduser("~/.config/net-dns-monitor/config.yaml")
        try:
            with open(config_path, "r") as f:
                data = yaml.safe_load(f) or {}
            data.update(self.config)
            with open(config_path, "w") as f:
                yaml.dump(data, f)
            self.append_log("Configuration saved to config.yaml.")
        except Exception as e:
            self.append_log(f"Error saving config: {e}")

    def on_start(self):
        self.append_log("Starting router...")
        if self.app.router:
            self.on_save_config()
            self.app.router.start()
            self.append_log("Router started via osascript.")
        else:
            self.append_log("Router module not loaded.")

    def on_stop(self):
        self.append_log("Stopping router...")
        if self.app.router:
            self.app.router.stop()
            self.append_log("Router stopped via osascript.")

    def on_ping(self):
        target = self.ping_target.stringValue()
        self.append_log(f"\\nPinging {target}...")
        def run():
            try:
                res = subprocess.check_output(["ping", "-c", "4", target], text=True, stderr=subprocess.STDOUT)
                AppKit.performSelectorOnMainThread_withObject_waitUntilDone_(
                    self.append_log, res, False
                )
            except subprocess.CalledProcessError as e:
                AppKit.performSelectorOnMainThread_withObject_waitUntilDone_(
                    self.append_log, f"Ping failed:\\n{e.output}", False
                )
        threading.Thread(target=run, daemon=True).start()

    def on_refresh(self):
        self.text_view.setString_("")
        self.append_log("--- Diagnostics & Routing Status ---")
        try:
            routes = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
            self.append_log("\\nRouting Table:\\n" + routes)
            
            fwd = subprocess.check_output(["sysctl", "net.inet.ip.forwarding"], text=True).strip()
            self.append_log("\\n" + fwd)
            
            ps = subprocess.check_output(["ps", "aux"], text=True)
            self.append_log(f"DHCP/bootpd running: {'bootpd' in ps}")
            
            if self._get_device(self.wan_popup) == self._get_device(self.lan_popup):
                self.append_log("\\n!!! OBVIOUS CONFLICT: WAN and LAN are set to the same interface !!!")
                
        except Exception as e:
            self.append_log(f"Error running diagnostics: {e}")

    def on_ai_check(self):
        self.append_log("\\nAnalyzing config with Anthropic AI...")
        wan = self._get_device(self.wan_popup)
        lan = self._get_device(self.lan_popup)
        ip = self.lan_ip.stringValue()
        nm = self.lan_nm.stringValue()
        start = self.dhcp_s.stringValue()
        end = self.dhcp_e.stringValue()

        def run():
            try:
                routes = subprocess.check_output(["netstat", "-rn", "-f", "inet"], text=True)
                fwd = subprocess.check_output(["sysctl", "net.inet.ip.forwarding"], text=True).strip()
                prompt = (
                    f"Analyze this macOS router/Internet Sharing config:\\n"
                    f"WAN: {wan}\\nLAN: {lan}\\nLAN IP: {ip}\\nNetmask: {nm}\\nDHCP: {start}-{end}\\n"
                    f"\\nRouting table:\\n{routes}\\n\\nIP Forwarding: {fwd}\\n"
                    f"Is this config logically sound? Provide brief feedback and subnet/route suggestions."
                )
                client = anthropic.Anthropic()
                res = client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=1000,
                    messages=[{"role": "user", "content": prompt}]
                )
                txt = res.content[0].text
                AppKit.performSelectorOnMainThread_withObject_waitUntilDone_(
                    self.append_log, "\\n[AI Analysis]\\n" + txt, False
                )
            except Exception as e:
                AppKit.performSelectorOnMainThread_withObject_waitUntilDone_(
                    self.append_log, f"\\nAI Check Failed: {e}", False
                )
        threading.Thread(target=run, daemon=True).start()
