"""The console as a real macOS window, opened from the menu bar.

PyObjC/AppKit rather than a new dependency: rumps already pulls PyObjC in, so
this adds nothing to `requirements.txt`.

**This file is a shell and nothing else.** What a line of input means, which
built-ins exist, how a result is rendered, what the limits are -- all of that is
in `console.py`, which the offline suite covers. The rule worth insisting on: an
AppKit window cannot be automated-tested any more than the menu bar can, so
anything decided *here* is decided somewhere untestable. An `if` in this file
probably belongs in `console.handle`.

Every command runs on a worker thread, not just the slow ones. A console with a
fixed command set can pick which work to push off the main thread, because it
knows in advance which entries are slow; an arbitrary-command console cannot.
A blocking wait on the main thread freezes the window, the menu bar, *and* the
rumps timer doing the actual monitoring -- during the outage the console was
opened to investigate.
"""

import contextlib
import threading
import traceback
from typing import Callable, Optional

from netdnsmonitor.console import BANNER, PROMPT, ClearSignal, ConsoleState, handle, run_command

# titled | closable | miniaturizable | resizable. Spelled numerically because
# the PyObjC constant names for these moved between versions (NSTitledWindowMask
# -> NSWindowStyleMaskTitled) and the values did not.
STYLE_MASK = 1 | 2 | 4 | 8

# NSViewWidthSizable | NSViewHeightSizable, and width + a flexible top margin
# (which is what pins a control to the bottom edge on resize).
RESIZE_BOTH = 2 | 16
RESIZE_PINNED_BOTTOM = 2 | 32

BUSY_MESSAGE = "(a command is still running -- wait for it, up to the command timeout)"

# Characters kept in the transcript. The controller lives for the whole app
# session and is never rebuilt, so without a ceiling the text storage grows
# with every command until the window -- and the menu bar app behind it --
# starts paying for it on every redraw.
MAX_TRANSCRIPT_CHARS = 2_000_000

# Objective-C class names are process-global, even across Python controllers.
_CONSOLE_TARGET_CLASS = None


def _make_target(controller):
    """An ObjC object to receive the text field's action.

    Cocoa targets must be real ObjC objects, so this cannot be a plain Python
    callable. Built lazily inside a function so that importing this module never
    requires a GUI session -- which is what lets the offline suite import it.
    """
    global _CONSOLE_TARGET_CLASS
    if _CONSOLE_TARGET_CLASS is not None:
        return _CONSOLE_TARGET_CLASS.alloc().initWithController_(controller)

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
            line = str(sender.stringValue())
            sender.setStringValue_("")
            # The field is already cleared, so a raise here loses the line
            # with no trace of it -- and an exception out of an ObjC action
            # is not reported anywhere a person would look.
            try:
                self._controller.submit(line)
            except Exception:  # noqa: BLE001 - an ObjC action must not raise
                traceback.print_exc()

    _CONSOLE_TARGET_CLASS = _ConsoleTarget
    return _ConsoleTarget.alloc().initWithController_(controller)


class ConsoleWindowController:
    """Holds the window and pumps text into it. Constructed lazily so importing
    this module on a machine without a GUI session does not explode.
    """

    def __init__(
        self,
        status: Optional[Callable[[], str]] = None,
        runner: Callable[..., object] = run_command,
        on_main: Optional[Callable[[Callable[[], None]], None]] = None,
    ):
        # `runner` and `on_main` exist to be replaced in tests. Everything in
        # this class below the AppKit calls is ordinary dispatch logic, and
        # injecting those two is what keeps it inside the suite instead of
        # outside it.
        self.status = status
        self.runner = runner
        self.state = ConsoleState()
        self.window = None
        self.text_view = None
        self.input_field = None
        self._target = None
        self._on_main_hook = on_main
        self._busy = False

    # --- output ----------------------------------------------------------

    def append(self, text: str) -> None:
        if not text:
            return
        if self.text_view is None:
            print(text)  # headless fallback, used by the import-only tests
            return
        from AppKit import NSAttributedString
        from Foundation import NSMakeRange

        storage = self.text_view.textStorage()
        storage.appendAttributedString_(NSAttributedString.alloc().initWithString_(text + "\n"))
        if storage.length() > MAX_TRANSCRIPT_CHARS:
            storage.deleteCharactersInRange_(
                NSMakeRange(0, storage.length() - MAX_TRANSCRIPT_CHARS)
            )
        self.text_view.scrollRangeToVisible_(NSMakeRange(storage.length(), 0))

    def clear(self) -> None:
        if self.text_view is None:
            return
        from Foundation import NSMakeRange

        storage = self.text_view.textStorage()
        storage.deleteCharactersInRange_(NSMakeRange(0, storage.length()))

    def _on_main(self, fn: Callable[[], None]) -> None:
        if self._on_main_hook is not None:
            self._on_main_hook(fn)
            return
        try:
            from Foundation import NSOperationQueue

            NSOperationQueue.mainQueue().addOperationWithBlock_(fn)
        except Exception:  # noqa: BLE001 - a worker thread must not die here
            # Running `fn` inline would put `_finish`'s AppKit writes on this
            # worker thread. Only the headless path -- no text view, where
            # append is a print -- is safe to run inline.
            if self.text_view is None:
                fn()
            else:
                # run_line owns the busy flag and must know no hop was queued.
                raise

    # --- actions ---------------------------------------------------------

    def submit(self, line: str) -> None:
        """One line of input. Echoes immediately, then does the work off-thread.

        The echo is deliberately not deferred: on a command that takes the full
        timeout, a console that shows nothing for 20 seconds looks broken.
        """
        if not line.strip():
            return
        if self._busy:
            self.append(BUSY_MESSAGE)
            return

        self.append(f"{PROMPT}{line.strip()}")
        self._busy = True
        try:
            threading.Thread(target=self.run_line, args=(line,), daemon=True).start()
        except RuntimeError as exc:
            # Thread creation can fail under resource pressure. The flag is
            # cleared once the output is drawn, which never happens if the
            # thread never starts -- leaving the console refusing every later
            # line.
            self._busy = False
            self.append(f"failed to start command: {exc}")

    def run_line(self, line: str) -> None:
        """The worker-thread body: run the line, then hand the text back to the
        main thread to draw.
        """
        text = ""
        try:
            text, self.state = handle(line, self.state, self.runner, self.status)
        except Exception as exc:  # noqa: BLE001 - a window must not die on a command
            text = f"failed: {type(exc).__name__}: {exc}"
        try:
            self._on_main(lambda: self._finish(text))
        except Exception:  # noqa: BLE001 - the flag must not outlive a failed hop
            # The hop was never queued, so `_finish` will not clear the flag.
            self._busy = False
            raise

    def _finish(self, text: str) -> None:
        """Back on the main thread: AppKit redraws nowhere else.

        The busy flag is cleared here, after the output is drawn, not on the
        worker. Cleared on the worker, it dropped before this hop was queued:
        with the main thread busy, a second Return was accepted and its echo
        was drawn above the first command's output.
        """
        try:
            if self.state.closed:
                self.state.closed = False  # so a reopened window is not born closed
                self.close()
                return
            if isinstance(text, ClearSignal):
                self.clear()
                return
            self.append(text)
        finally:
            self._busy = False

    def close(self) -> None:
        if self.window is not None:
            self.window.close()

    # --- window ----------------------------------------------------------

    def show(self) -> None:
        from AppKit import (
            NSApplication,
            NSBackingStoreBuffered,
            NSColor,
            NSFont,
            NSScrollView,
            NSTextField,
            NSTextView,
            NSWindow,
        )
        from Foundation import NSMakeRect

        # A menu bar app runs as an accessory: ordering a window front does not
        # make the app active, and an inactive app's window takes no keystrokes.
        # Without this the console opens looking usable and silently ignores
        # typing until it is clicked.
        # Suppressed deliberately, and broadly: activation is cosmetic next to
        # showing the window at all, so nothing here may stop the window opening.
        with contextlib.suppress(Exception):
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)

        if self.window is not None:
            self.window.makeKeyAndOrderFront_(None)
            self.window.makeFirstResponder_(self.input_field)
            return

        self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
            NSMakeRect(0, 0, 820, 560), STYLE_MASK, NSBackingStoreBuffered, False
        )
        # NSWindow is released when closed by default, which would leave the
        # `self.window is not None` branch above handing back a freed object the
        # second time the console is opened.
        self.window.setReleasedWhenClosed_(False)
        self.window.setTitle_("Net/DNS Console")
        content = self.window.contentView()

        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(10, 46, 800, 504))
        scroll.setHasVerticalScroller_(True)
        scroll.setAutoresizingMask_(RESIZE_BOTH)
        self.text_view = NSTextView.alloc().initWithFrame_(NSMakeRect(0, 0, 800, 504))
        self.text_view.setEditable_(False)
        self.text_view.setRichText_(False)
        self.text_view.setFont_(NSFont.userFixedPitchFontOfSize_(12))
        # Command output is column-aligned (`netstat -rn`, `ifconfig`); a
        # proportional font turns all of it into noise.
        try:
            self.text_view.setBackgroundColor_(NSColor.textBackgroundColor())
            self.text_view.setTextColor_(NSColor.textColor())
        except Exception:  # noqa: BLE001 - system colors, not worth failing over
            pass
        scroll.setDocumentView_(self.text_view)
        content.addSubview_(scroll)

        # Kept on the instance: an ObjC target is not retained by setTarget_, so
        # a local would be collected and the field would go dead.
        self._target = _make_target(self)

        self.input_field = NSTextField.alloc().initWithFrame_(NSMakeRect(10, 10, 800, 26))
        self.input_field.setPlaceholderString_("shell command -- :help for built-ins, q to close")
        self.input_field.setFont_(NSFont.userFixedPitchFontOfSize_(12))
        self.input_field.setAutoresizingMask_(RESIZE_PINNED_BOTTOM)
        self.input_field.setTarget_(self._target)
        self.input_field.setAction_("submit:")
        content.addSubview_(self.input_field)

        positioned = False
        try:
            from AppKit import NSScreen

            screen = NSScreen.mainScreen()
            if screen is not None:
                vf = screen.visibleFrame()
                win_w = min(820.0, vf.size.width * 0.48)
                win_h = min(520.0, vf.size.height * 0.46)
                win_x = vf.origin.x + vf.size.width - win_w - 20.0
                win_y = vf.origin.y + 20.0
                self.window.setFrame_display_(NSMakeRect(win_x, win_y, win_w, win_h), True)
                positioned = True
        except Exception:  # noqa: BLE001
            pass

        if not positioned:
            self.window.center()

        self.window.makeKeyAndOrderFront_(None)
        self.window.makeFirstResponder_(self.input_field)

        self.append(BANNER)
        self.append("")
