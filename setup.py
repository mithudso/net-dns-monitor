"""py2app build spec. A bare venv python3 shares Apple's framework Python
runtime, which re-execs itself into its own bundled Python.app the moment
rumps creates an NSApplication -- that stub's Info.plist says "Python" and
wins over any wrapper .app, no matter how the outer script is launched
(confirmed empirically: CFBundleName override, NSProcessInfo.processName,
and a hand-built wrapper .app around `exec python3 -m ...` all failed for
this specific reason). py2app embeds its own private interpreter copy that
never touches that shared re-exec path, so this is the one approach that
actually gives the frozen app its own Dock/Force-Quit/Cmd-Tab identity.

Build: python setup.py py2app
Output: dist/Net-DNS-Monitor.app
"""

from setuptools import setup

APP = ["netdnsmonitor/app.py"]
OPTIONS = {
    "argv_emulation": False,
    "plist": {
        "CFBundleName": "Net-DNS-Monitor",
        "CFBundleDisplayName": "Net-DNS-Monitor",
        "CFBundleIdentifier": "com.net-dns-monitor.app",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "LSUIElement": False,
    },
    # AppKit/Foundation/objc are the pyobjc bridge modules this whole file
    # exists to bundle correctly (dock_icon.py and app.py's display-name
    # override both need them). modulegraph's static analysis already
    # picks them up as transitive imports of rumps -- confirmed by
    # inspecting a real build -- but listing them explicitly means a
    # future refactor that changes how they're imported can't silently
    # drop them from the bundle.
    "packages": ["netdnsmonitor", "rumps", "yaml", "anthropic", "AppKit", "Foundation", "objc"],
}

setup(
    app=APP,
    name="Net-DNS-Monitor",
    options={"py2app": OPTIONS},
)
