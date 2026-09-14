"""The dialogs behind the menu's Credentials and Claude-permission items.

Both are NSAlerts run modally. That is a deliberate exception to this app's rule
against modal alerts (see alert.py and App._drain_router_results). A modal session
does not service NSDefaultRunLoopMode, which is where rumps schedules its timers,
so monitoring pauses while one of these is open. They open only when someone has
just clicked a menu item, and the answer cannot be given without them, so that
person decides how long the pause lasts.

AppKit is imported inside each function, so this module imports cleanly in the
tests and the CLI. The app takes these functions as parameters, and the suite
passes fakes, so no test opens a window.
"""

from typing import Optional

SECURE_FIELD_WIDTH = 320.0
SECURE_FIELD_HEIGHT = 24.0


def _bring_to_front() -> None:
    # The status-item menu is usually used while another app is frontmost, and a
    # modal alert from a background app opens behind that app's windows.
    import AppKit

    AppKit.NSApplication.sharedApplication().activateIgnoringOtherApps_(True)


def prompt_for_secret(title: str, message: str) -> Optional[str]:
    """Ask for one secret in a masked field.

    Returns None when the person cancels. On Save it returns the text with
    surrounding whitespace removed, which a pasted key often carries. That can be
    an empty string: the credential store then says an empty value was not saved,
    rather than the dialog closing with no outcome at all.
    """
    import AppKit

    alert = AppKit.NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(message)
    alert.addButtonWithTitle_("Save")
    alert.addButtonWithTitle_("Cancel")
    # NSSecureTextField, not NSTextField: it masks what is typed and refuses to
    # copy it out, so the value is never on screen or on the pasteboard.
    field = AppKit.NSSecureTextField.alloc().initWithFrame_(
        AppKit.NSMakeRect(0, 0, SECURE_FIELD_WIDTH, SECURE_FIELD_HEIGHT)
    )
    alert.setAccessoryView_(field)
    alert.window().setInitialFirstResponder_(field)
    _bring_to_front()
    if alert.runModal() != AppKit.NSAlertFirstButtonReturn:
        return None
    return str(field.stringValue() or "").strip()


def confirm(title: str, message: str, ok_label: str, cancel_label: str) -> bool:
    """A two-button question. True only for the first button."""
    import AppKit

    alert = AppKit.NSAlert.alloc().init()
    alert.setMessageText_(title)
    alert.setInformativeText_(message)
    alert.addButtonWithTitle_(ok_label)
    alert.addButtonWithTitle_(cancel_label)
    _bring_to_front()
    return alert.runModal() == AppKit.NSAlertFirstButtonReturn
