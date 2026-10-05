"""py2app build spec. A bare venv python3 shares Apple's framework Python
runtime, which re-execs itself into its own bundled Python.app the moment
rumps creates an NSApplication -- that stub's Info.plist says "Python" and
wins over any wrapper .app, no matter how the outer script is launched
(confirmed empirically: CFBundleName override, NSProcessInfo.processName,
and a hand-built wrapper .app around `exec python3 -m ...` all failed for
this specific reason). py2app embeds its own private interpreter copy that
never touches that shared re-exec path, so this is the one approach that
actually gives the frozen app its own Dock/Force-Quit/Cmd-Tab identity.

Direct build:     python setup.py py2app
Output:           dist/Net-DNS-Monitor.app

Mac App Store build: do not run this file directly for that. Run
`scripts/appstore/build_appstore.py`, which sets the NETDNS_* variables read
below, then does the post-processing py2app cannot: rebuilding the launcher
against the current SDK, removing the stdlib string App Review rejects,
signing inside-out with entitlements, and packaging.
"""

import os

from setuptools import setup

APP = ["netdnsmonitor/app.py"]

PLIST = {
    "CFBundleName": "Net-DNS-Monitor",
    "CFBundleDisplayName": "Net-DNS-Monitor",
    "CFBundleIdentifier": "com.net-dns-monitor.app",
    "CFBundleShortVersionString": "1.0",
    "CFBundleVersion": "1",
    "LSUIElement": False,
    # macOS 15 and later gate traffic to local-network addresses behind a
    # per-app permission (Apple TN3179). This app trips it on purpose: the peer
    # announcement is a UDP broadcast and the interface probe reaches the
    # gateway. The prompt appears either way; this string is the reason the
    # user sees in it, and a store build without it is refused by
    # build_appstore.py.
    "NSLocalNetworkUsageDescription": (
        "Net-DNS-Monitor checks whether your router and other devices on your local "
        "network are reachable, and announces itself to other copies of the app on "
        "the same network."
    ),
}

OPTIONS = {
    "argv_emulation": False,
    "plist": PLIST,
    # AppKit/Foundation/objc are the pyobjc bridge modules this whole file
    # exists to bundle correctly (dock_icon.py and app.py's display-name
    # override both need them). modulegraph's static analysis already
    # picks them up as transitive imports of rumps -- confirmed by
    # inspecting a real build -- but listing them explicitly means a
    # future refactor that changes how they're imported can't silently
    # drop them from the bundle.
    "packages": ["netdnsmonitor", "rumps", "yaml", "anthropic", "AppKit", "Foundation", "objc"],
}

if os.environ.get("NETDNS_BUILD") == "appstore":
    # Every value that identifies the product in App Store Connect comes from
    # the build script's arguments. A default bundle id here would let a build
    # upload under an identifier the developer never registered. A wrong id is
    # caught by build_appstore.py's provisioning-profile check, which compares
    # the profile's application identifier with team id + bundle id before this
    # file runs; this file does not validate anything itself.
    PLIST.update(
        {
            "CFBundleIdentifier": os.environ["NETDNS_BUNDLE_ID"],
            "CFBundleShortVersionString": os.environ["NETDNS_VERSION"],
            "CFBundleVersion": os.environ["NETDNS_BUILD_NUMBER"],
            "LSApplicationCategoryType": "public.app-category.utilities",
            "NSHumanReadableCopyright": os.environ.get("NETDNS_COPYRIGHT", ""),
            # distribution.detect() also keys off the sandbox's own variable;
            # this makes the intent explicit when LaunchServices starts the app.
            "LSEnvironment": {"NETDNS_DISTRIBUTION": "appstore"},
        }
    )
    policy_url = os.environ.get("NETDNS_PRIVACY_POLICY_URL")
    if policy_url:
        # Read by the app's "Privacy Policy" menu item (Guideline 5.1.1(i)).
        PLIST["NDMPrivacyPolicyURL"] = policy_url
    # Nothing here uses xz; lzma is only reached through shutil's optional
    # import, which tolerates its absence. Bundling it drags in Homebrew's
    # liblzma, whose bottle is built for the host macOS, and
    # build_appstore.py sets LSMinimumSystemVersion from the highest minos in
    # the bundle -- so that one dylib raised the store floor to macOS 27.
    OPTIONS["excludes"] = ["lzma", "_lzma"]
    icon = os.environ.get("NETDNS_ICON")
    if icon:
        OPTIONS["iconfile"] = icon
    if os.environ.get("NETDNS_WITH_PROBE") == "1":
        # Local sandbox testing only. build_appstore.py refuses to package a
        # bundle that contains the probe.
        OPTIONS["extra_scripts"] = ["scripts/appstore/sandbox_probe.py"]

setup(
    app=APP,
    name="Net-DNS-Monitor",
    options={"py2app": OPTIONS},
)
