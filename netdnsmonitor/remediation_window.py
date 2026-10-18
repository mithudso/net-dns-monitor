"""The remediation-script editor as a macOS window: a small Python IDE.

PyObjC/AppKit, no new dependency. **This file is a shell**: what a script may be
named, what Save refuses, what a test run prints and which tokens are coloured is
all in `remediation_editor.py`, which the offline suite covers. Anything decided
here is decided somewhere untestable, so keep it that way.

Layout: a script picker and the buttons on top; the editor in the middle; the
script's description or the last run's output below. Colour is applied from
`highlight_spans`, recomputed as the text changes.

A test run executes the script for real -- a repair really flushes the cache -- so
a script of KIND "repair" asks first. The run happens on a worker thread, because
a script may take its full timeout and a blocked main thread freezes the menu bar
and the rumps timer doing the monitoring.
"""

import contextlib
import threading
import traceback
from typing import Callable, Optional

from netdnsmonitor import ui_style
from netdnsmonitor.remediation_editor import (
    KIND_BUILTIN_NAME,
    KIND_COMMENT,
    KIND_KEYWORD,
    KIND_NUMBER,
    KIND_STRING,
    EditorSession,
    highlight_spans,
)
from netdnsmonitor.ui_catalog import CONTROL_TIPS

# titled | closable | miniaturizable | resizable (numeric for the reason in console_window).
STYLE_MASK = 1 | 2 | 4 | 8
RESIZE_BOTH = 2 | 16
PINNED_TOP = 8
RESIZE_WIDTH_PINNED_BOTTOM = 2 | 32

# RGB, picked to read on both the light and dark appearance.
_COLOURS = {
    KIND_KEYWORD: (0.78, 0.25, 0.55),
    KIND_STRING: (0.77, 0.34, 0.21),
    KIND_COMMENT: (0.42, 0.55, 0.40),
    KIND_NUMBER: (0.25, 0.45, 0.85),
    KIND_BUILTIN_NAME: (0.35, 0.55, 0.75),
}

_TARGET_CLASS = None


def _dispatch(controller, name, *args):
    """Call a controller method from an ObjC action.

    A module-level function, not a method on the NSObject subclass: PyObjC reads
    every method there as an Objective-C selector and rejects one whose argument
    count does not match its name. An exception out of an ObjC action is reported
    nowhere a person looks, so it is printed instead.
    """
    try:
        getattr(controller, name)(*args)
    except Exception:  # noqa: BLE001 - an ObjC action must not raise
        traceback.print_exc()


def _make_target(controller):
    """An ObjC object to receive the buttons' actions and the text view's delegate.

    Built lazily so importing this module needs no GUI session, which is what lets
    the offline suite import it.
    """
    global _TARGET_CLASS
    if _TARGET_CLASS is not None:
        return _TARGET_CLASS.alloc().initWithController_(controller)

    import objc
    from Foundation import NSObject

    class _EditorTarget(NSObject):
        def initWithController_(self, ctrl):
            self = objc.super(_EditorTarget, self).init()
            if self is None:
                return None
            self._controller = ctrl
            return self

        def pick_(self, sender):
            _dispatch(self._controller, "pick", int(sender.indexOfSelectedItem()))

        def save_(self, sender):
            _dispatch(self._controller, "save")

        def check_(self, sender):
            _dispatch(self._controller, "check")

        def run_(self, sender):
            _dispatch(self._controller, "run")

        def remove_(self, sender):
            _dispatch(self._controller, "remove")

        def new_(self, sender):
            _dispatch(self._controller, "new")

        def textDidChange_(self, notification):
            _dispatch(self._controller, "text_changed")

    _TARGET_CLASS = _EditorTarget
    return _EditorTarget.alloc().initWithController_(controller)


class RemediationWindowController:
    """Holds the window. Constructed lazily; `show()` builds it on first use."""

    def __init__(
        self,
        session: EditorSession,
        on_main: Optional[Callable[[Callable[[], None]], None]] = None,
    ):
        self.session = session
        self._on_main_hook = on_main
        self.window = None
        self.popup = None
        self.editor = None
        self.output = None
        self.status = None
        self.remove_button = None
        self._target = None
        self._names: list[str] = []
        self.current: Optional[str] = None
        self._loaded_text = ""
        self._busy = False

    # --- helpers ---------------------------------------------------------

    def _on_main(self, fn: Callable[[], None]) -> None:
        if self._on_main_hook is not None:
            self._on_main_hook(fn)
            return
        from Foundation import NSOperationQueue

        NSOperationQueue.mainQueue().addOperationWithBlock_(fn)

    def _set_output(self, text: str) -> None:
        if self.output is not None:
            self.output.setString_(text)

    def _set_status(self, text: str) -> None:
        if self.status is not None:
            self.status.setStringValue_(text)

    def _editor_text(self) -> str:
        return str(self.editor.string()) if self.editor is not None else ""

    def _set_editor_text(self, text: str) -> None:
        self.editor.setString_(text)
        self._loaded_text = text
        self._recolour()
        self._update_title()

    def _update_title(self) -> None:
        if self.window is None:
            return
        dirty = self.current is not None and self._editor_text() != self._loaded_text
        name = f" - {self.current}" if self.current else ""
        self.window.setTitle_(f"Remediation scripts{name}{' (edited)' if dirty else ''}")

    def _recolour(self) -> None:
        """Re-apply token colours. Attribute-only edits: the text is untouched."""
        from AppKit import NSColor, NSForegroundColorAttributeName
        from Foundation import NSMakeRange

        storage = self.editor.textStorage()
        text = str(storage.string())
        storage.beginEditing()
        try:
            whole = NSMakeRange(0, storage.length())
            storage.addAttribute_value_range_(
                NSForegroundColorAttributeName, NSColor.textColor(), whole
            )
            for start, length, kind in highlight_spans(text):
                if start + length > storage.length():
                    continue
                r, g, b = _COLOURS[kind]
                storage.addAttribute_value_range_(
                    NSForegroundColorAttributeName,
                    NSColor.colorWithSRGBRed_green_blue_alpha_(r, g, b, 1.0),
                    NSMakeRange(start, length),
                )
        finally:
            storage.endEditing()

    def _reload_popup(self, select: Optional[str] = None) -> None:
        rows = self.session.rows()
        self._names = [row.name for row in rows]
        self.popup.removeAllItems()
        self.popup.addItemsWithTitles_([row.label for row in rows])
        for item, row in zip(self.popup.itemArray(), rows, strict=True):
            ui_style.tip(item, row.tip)
        if select in self._names:
            self.popup.selectItemAtIndex_(self._names.index(select))

    # --- actions (called by the target) ----------------------------------

    def open_script(self, name: str) -> None:
        self.current = name
        self._set_editor_text(self.session.load(name))
        self._set_output(self.session.description(name))
        verb = self.session.remove_verb(name) if self.session.can_remove(name) else "Reset"
        self.remove_button.setTitle_(f"{verb}...")
        self.remove_button.setEnabled_(self.session.can_remove(name))
        self._set_status("")

    def pick(self, index: int) -> None:
        if 0 <= index < len(self._names):
            self.open_script(self._names[index])

    def text_changed(self) -> None:
        self._recolour()
        self._update_title()

    def check(self) -> None:
        if self.current is None:
            return
        problems = self.session.check(self.current, self._editor_text())
        if problems:
            self._set_output("problems:\n  " + "\n  ".join(problems))
            self._set_status("check failed")
        else:
            self._set_output("no problems: the script compiles and its metadata is valid")
            self._set_status("check passed")

    def save(self) -> None:
        if self.current is None:
            return
        ok, message = self.session.save(self.current, self._editor_text())
        self._set_output(message)
        self._set_status("saved" if ok else "not saved")
        if ok:
            self._reload_popup(self.current)
            self.open_script(self.current)
            self._set_output(message)
            self._set_status("saved")

    def _confirm(self, title: str, detail: str, button: str) -> bool:
        from AppKit import NSAlert

        alert = NSAlert.alloc().init()
        alert.setMessageText_(title)
        alert.setInformativeText_(detail)
        alert.addButtonWithTitle_(button)
        alert.addButtonWithTitle_("Cancel")
        return int(alert.runModal()) == 1000  # NSAlertFirstButtonReturn

    def remove(self) -> None:
        if self.current is None or not self.session.can_remove(self.current):
            return
        verb = self.session.remove_verb(self.current)
        detail = (
            "This discards your changes and restores the shipped script."
            if verb == "Reset"
            else "This deletes the custom script file."
        )
        if not self._confirm(f"{verb} {self.current}?", detail, verb):
            return
        message = self.session.remove(self.current)
        self._reload_popup()
        if self.current in self._names:
            self._reload_popup(self.current)
            self.open_script(self.current)
        elif self._names:
            self.popup.selectItemAtIndex_(0)
            self.open_script(self._names[0])
        self._set_output(message)

    def new(self) -> None:
        from AppKit import NSAlert, NSTextField
        from Foundation import NSMakeRect

        alert = NSAlert.alloc().init()
        alert.setMessageText_("New remediation script")
        alert.setInformativeText_(
            "Name it with lowercase letters, digits and underscores. "
            "It joins the ladder for the classifications you list in the script."
        )
        field = NSTextField.alloc().initWithFrame_(NSMakeRect(0, 0, 260, 24))
        field.setPlaceholderString_("restart_vpn_client")
        alert.setAccessoryView_(field)
        alert.addButtonWithTitle_("Create")
        alert.addButtonWithTitle_("Cancel")
        alert.window().setInitialFirstResponder_(field)
        if int(alert.runModal()) != 1000:
            return
        ok, message, text = self.session.create(str(field.stringValue()))
        if not ok:
            self._set_output(message)
            return
        self.current = str(field.stringValue()).strip()
        self._set_editor_text(text)
        # Not in the popup until saved: nothing exists on disk yet.
        self.remove_button.setEnabled_(False)
        self._set_output(message)
        self._set_status("unsaved")

    def run(self) -> None:
        if self.current is None:
            return
        if self._busy:
            self._set_status("a run is still going")
            return
        name, text = self.current, self._editor_text()
        if self.session.needs_confirmation(name) and not self._confirm(
            f"Run {name} for real?",
            "This is a repair: it changes the machine exactly as it would during an incident.",
            "Run",
        ):
            return
        self._busy = True
        self._set_output(f">>> running {name} ...")
        self._set_status("running")
        try:
            threading.Thread(target=self._run_worker, args=(name, text), daemon=True).start()
        except RuntimeError:
            # Thread creation can fail under resource pressure; the flag is only
            # cleared by the hop that never gets queued.
            self._busy = False
            self._set_status("could not start the run")

    def _run_worker(self, name: str, text: str) -> None:
        output = ""
        try:
            output = self.session.test_run(name, text)
        except Exception as exc:  # noqa: BLE001 - a worker must not die silently
            output = f"failed: the run raised {type(exc).__name__}"

        def finish() -> None:
            try:
                self._set_output(output)
                self._set_status("done")
            finally:
                self._busy = False

        try:
            self._on_main(finish)
        except Exception:  # noqa: BLE001 - the flag must not outlive a failed hop
            self._busy = False
            raise

    # --- window ----------------------------------------------------------

    def build(self) -> None:
        """Create the window and its controls without showing it.

        Split from `show` so the offline suite can build the window and walk its
        controls (every one must have a tooltip) without putting it on screen.
        """
        import AppKit
        from AppKit import (
            NSBackingStoreBuffered,
            NSButton,
            NSFont,
            NSPopUpButton,
            NSScrollView,
            NSTextField,
            NSTextView,
            NSWindow,
        )
        from Foundation import NSMakeRect

        width, height = 900, 640
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, width, height), STYLE_MASK, NSBackingStoreBuffered, False
        )
        # Released-on-close would leave `self.window` pointing at a freed object.
        self.window.setReleasedWhenClosed_(False)
        self.window.setTitle_("Remediation scripts")
        content = self.window.contentView()
        self._target = _make_target(self)  # kept: setTarget_ does not retain it

        top = height - 36
        self.popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(10, top, 330, 26), False
        )
        self.popup.setTarget_(self._target)
        self.popup.setAction_("pick:")
        ui_style.tip(self.popup, CONTROL_TIPS["pick"])
        self.popup.setAutoresizingMask_(PINNED_TOP)
        content.addSubview_(self.popup)

        def button(title, action, x, w=80, tip_key=""):
            b = NSButton.alloc().initWithFrame_(NSMakeRect(x, top, w, 26))
            b.setTitle_(title)
            ui_style.style_button(AppKit, b, prominent=action == "save:")
            ui_style.tip(b, CONTROL_TIPS[tip_key])
            b.setTarget_(self._target)
            b.setAction_(action)
            b.setAutoresizingMask_(PINNED_TOP)
            content.addSubview_(b)
            return b

        button("Save", "save:", 350, tip_key="editor_save")
        button("Check", "check:", 435, tip_key="editor_check")
        button("Run test", "run:", 520, 90, tip_key="editor_run")
        self.remove_button = button("Reset...", "remove:", 615, 90, tip_key="editor_remove")
        button("New...", "new:", 710, tip_key="editor_new")

        self.status = NSTextField.labelWithString_("")
        ui_style.tip(self.status, CONTROL_TIPS["editor_status"])
        self.status.setFrame_(NSMakeRect(800, top + 4, 90, 18))
        self.status.setAutoresizingMask_(PINNED_TOP)
        content.addSubview_(self.status)

        mono = NSFont.userFixedPitchFontOfSize_(12)

        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 190, width - 20, top - 200))
        scroll.setHasVerticalScroller_(True)
        scroll.setBorderType_(2)
        scroll.setAutoresizingMask_(RESIZE_BOTH)
        self.editor = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, width - 20, 400))
        self.editor.setFont_(mono)
        # Rich text so token colours can be attributes; every smart substitution
        # off, because a curly quote or a "--" turned into an en dash is a
        # SyntaxError in code that looks identical on screen.
        self.editor.setRichText_(True)
        self.editor.setAllowsUndo_(True)
        for setter in (
            "setAutomaticQuoteSubstitutionEnabled_",
            "setAutomaticDashSubstitutionEnabled_",
            "setAutomaticTextReplacementEnabled_",
            "setAutomaticSpellingCorrectionEnabled_",
            "setContinuousSpellCheckingEnabled_",
            "setAutomaticLinkDetectionEnabled_",
        ):
            with contextlib.suppress(Exception):
                getattr(self.editor, setter)(False)
        self.editor.setDelegate_(self._target)
        ui_style.tip(self.editor, CONTROL_TIPS["editor_text"])
        scroll.setDocumentView_(self.editor)
        content.addSubview_(scroll)

        out_scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 10, width - 20, 170))
        out_scroll.setHasVerticalScroller_(True)
        out_scroll.setBorderType_(2)
        out_scroll.setAutoresizingMask_(RESIZE_WIDTH_PINNED_BOTTOM)
        self.output = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, width - 20, 170))
        self.output.setEditable_(False)
        self.output.setRichText_(False)
        self.output.setFont_(mono)
        ui_style.tip(self.output, CONTROL_TIPS["editor_output"])
        out_scroll.setDocumentView_(self.output)
        content.addSubview_(out_scroll)

        self._reload_popup()
        self.glass_kind = ui_style.apply_window_glass(AppKit, self.window)
        self.window.center()
        if self._names:
            self.popup.selectItemAtIndex_(0)
            self.open_script(self._names[0])

    def show(self) -> None:
        from AppKit import NSApplication

        # A menu bar app is an accessory; without this the window opens looking
        # usable and ignores typing until it is clicked.
        with contextlib.suppress(Exception):
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

        if self.window is None:
            self.build()
        self.window.makeKeyAndOrderFront_(None)
