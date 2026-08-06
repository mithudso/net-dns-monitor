"""The console as a real macOS window, opened from the menu bar.

PyObjC/AppKit rather than a new dependency: rumps already pulls PyObjC in, so
this adds nothing to `requirements.txt`.

**This file is a shell and nothing else.** Every decision -- which commands
exist, whether one changes system state, what the interface table says, what
the guide says -- comes from `commands.py`, `cli.py` and `console.py`, all of
which are tested offline. The rule that makes that worth insisting on: an
AppKit window cannot be automated-tested any more than the menu bar can, so
anything decided *here* is decided somewhere untestable. If you find yourself
writing an `if` in this file, it probably belongs in `console.handle`.

Long work runs on a background thread. AppKit redraws on the main thread only,
and a benchmark takes seconds per interface -- doing that inline freezes the
window mid-diagnosis, which is the same class of bug as freezing the menu bar.
"""

import threading
from typing import Callable, Optional

from netdnsmonitor.cli import (
    build_context,
    interface_rows,
    render_catalog,
    render_failover_status,
    render_interfaces,
    render_usage_guide,
)
from netdnsmonitor.commands import CATALOG
from netdnsmonitor.console import ConsoleState, handle


def command_menu_titles() -> list[str]:
    """What the dropdown shows. Marked entries change system state, so the
    label says so before the click rather than after.
    """
    titles = []
    for command in CATALOG:
        mark = "!  " if command.mutates else "   "
        titles.append(f"{mark}{command.key} — {command.answers}")
    return titles


def _make_target(controller):
    """An ObjC object to receive the text field and popup actions.

    Cocoa targets must be real ObjC objects, so this cannot just be a Python
    callable. Built lazily inside a function so importing this module never
    requires a GUI session -- which is what lets the tested parts of this file
    be imported by the offline suite.
    """
    import objc
    from Foundation import NSObject

    class _ConsoleTarget(NSObject):
        def initWithController_(self, ctrl):
            self = objc.super(_ConsoleTarget, self).init()
            if self is None:
                return None
            self._controller = ctrl
            return self

        def submit_(self, sender):
            line = str(sender.stringValue()).strip()
            sender.setStringValue_("")
            if line:
                self._controller.submit(line)

        def pick_(self, sender):
            # Index 0 is the "Insert a diagnostic command..." placeholder.
            self._controller.insert_command(sender.indexOfSelectedItem() - 1)

    return _ConsoleTarget.alloc().initWithController_(controller)


class ConsoleWindowController:
    """Holds the window and pumps text into it. Constructed lazily so importing
    this module on a machine without a GUI session does not explode.
    """

    def __init__(self, config: dict):
        self.config = config
        self.state = ConsoleState()
        self.window = None
        self.text_view = None
        self.input_field = None
        self.command_popup = None
        self._context = None

    # --- context ---------------------------------------------------------

    def context(self):
        if self._context is None:
            self._context = build_context(self.config)
        return self._context

    def services(self):
        from netdnsmonitor.cli import list_services

        return list_services(self.context()[3])

    # --- output ----------------------------------------------------------

    def append(self, text: str) -> None:
        if not text:
            return
        if self.text_view is None:
            print(text)
            return
        from AppKit import NSAttributedString
        from Foundation import NSMakeRange

        storage = self.text_view.textStorage()
        storage.appendAttributedString_(NSAttributedString.alloc().initWithString_(text + "\n"))
        self.text_view.scrollRangeToVisible_(NSMakeRange(storage.length(), 0))

    def append_async(self, produce: Callable[[], str]) -> None:
        """Run something slow off the main thread, then post the result back.

        A benchmark is seconds per interface; on the main thread that is a
        frozen window during exactly the outage being diagnosed.
        """

        def worker():
            try:
                text = produce()
            except Exception as exc:  # noqa: BLE001 - a window must not die on a command
                text = f"failed: {type(exc).__name__}: {exc}"
            self._on_main(lambda: self.append(text))

        threading.Thread(target=worker, daemon=True).start()

    def _on_main(self, fn: Callable[[], None]) -> None:
        try:
            from Foundation import NSOperationQueue

            NSOperationQueue.mainQueue().addOperationWithBlock_(fn)
        except Exception:  # noqa: BLE001 - headless fallback
            fn()

    # --- actions ---------------------------------------------------------

    def submit(self, line: str) -> None:
        """One line of input, exactly as the terminal console handles it."""
        prober, meter, failover, run_fn = self.context()
        self.append(f"netdns> {line}")
        text, self.state = handle(line, self.state, self.services(), run_fn)

        if text == "__INTERFACES__":
            self.append_async(lambda: render_interfaces(interface_rows(run_fn, prober)))
        elif text == "__BENCH__":
            self.append("benchmarking reachable interfaces, this takes a few seconds...")
            self.append_async(
                lambda: render_interfaces(
                    interface_rows(run_fn, prober, meter, measure=True)
                )
            )
        elif text == "__STATUS__":
            self.append_async(
                lambda: render_failover_status(failover.snapshot() if failover else None)
            )
        elif text == "__SWITCH_BACKUP__":
            self.append_async(
                lambda: failover.switch_now("backup") if failover
                else "failover is not configured."
            )
        elif text == "__SWITCH_PREFERRED__":
            self.append_async(
                lambda: failover.switch_now("preferred") if failover
                else "failover is not configured."
            )
        elif text:
            self.append(text)

    def insert_command(self, index: int) -> None:
        """Dropdown pick: put the key in the input box rather than running it.

        Inserting instead of executing is deliberate. The dropdown is a
        discovery aid, and several entries change system state; a menu that
        fires on selection would run one before the user has read it.
        """
        if 0 <= index < len(CATALOG) and self.input_field is not None:
            self.input_field.setStringValue_(CATALOG[index].key)

    # --- window ----------------------------------------------------------

    def show(self) -> None:
        from AppKit import (
            NSBackingStoreBuffered,
            NSPopUpButton,
            NSScrollView,
            NSTextField,
            NSTextView,
            NSTitledWindowMask,
            NSWindow,
        )
        from Foundation import NSMakeRect

        if self.window is not None:
            self.window.makeKeyAndOrderFront_(None)
            return

        rect = NSMakeRect(0, 0, 760, 520)
        mask = NSTitledWindowMask | (1 << 1) | (1 << 2) | (1 << 3)  # close/min/resize
        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            rect, mask, NSBackingStoreBuffered, False
        )
        self.window.setTitle_("Net/DNS Console")
        content = self.window.contentView()

        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 80, 740, 430))
        scroll.setHasVerticalScroller_(True)
        self.text_view = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 740, 430))
        self.text_view.setEditable_(False)
        self.text_view.setRichText_(False)
        scroll.setDocumentView_(self.text_view)
        content.addSubview_(scroll)

        # Kept on the instance: an ObjC target is not retained by setTarget_,
        # so a local would be collected and the controls would go dead.
        self._target = _make_target(self)

        self.command_popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
            NSMakeRect(10, 44, 740, 26), False
        )
        self.command_popup.addItemsWithTitles_(
            ["Insert a diagnostic command…"] + command_menu_titles()
        )
        self.command_popup.setTarget_(self._target)
        self.command_popup.setAction_("pick:")
        content.addSubview_(self.command_popup)

        self.input_field = NSTextField.alloc().initWithFrame_(NSMakeRect(10, 10, 740, 24))
        self.input_field.setPlaceholderString_(
            "command key or number — ? guide · i interfaces · b benchmark · q close"
        )
        self.input_field.setTarget_(self._target)
        self.input_field.setAction_("submit:")
        content.addSubview_(self.input_field)

        self.window.center()
        self.window.makeKeyAndOrderFront_(None)

        self.append(render_usage_guide())
        self.append("")
        self.append(render_catalog())
        self.append("")
        self.append_async(
            lambda: render_interfaces(interface_rows(self.context()[3], self.context()[0]))
        )
