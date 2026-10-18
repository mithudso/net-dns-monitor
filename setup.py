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
    # per-app permission (Apple TN3179). The default configuration never
    # contacts one: heartbeat and connectivity probes go to public addresses
    # (1.1.1.1, 8.8.8.8, Cloudflare and Google IPv6) and the system resolver.
    # The prompt appears when the user turns on LAN peer discovery (a UDP
    # broadcast; off by default in the store build) or adds a local address to
    # monitor, and the direct build's failover probes a gateway the same way.
    # This string is the only reason the user sees in the prompt, so it names
    # exactly those cases (Guideline 5.1.1(ii)); a store build without it is
    # refused by build_appstore.py.
    "NSLocalNetworkUsageDescription": (
        "Net-DNS-Monitor sends a small status broadcast to other Macs on your local "
        "network, and listens for theirs, when you turn on LAN peer discovery. It also "
        "contacts local addresses you add to monitor, such as your router."
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
    # A python-build-standalone interpreter (the only kind whose Mach-O minos is
    # low enough for macOS 26; Homebrew's is 27.0) builds zlib into the
    # executable, so `zlib.__file__` does not exist and py2app 0.28.10 raises
    # AttributeError copying it. There is nothing to copy; skip exactly that file.
    import zlib

    if not getattr(zlib, "__file__", None):
        from py2app.build_app import py2app as _py2app_command

        _no_file = "<zlib is built into the interpreter>"
        zlib.__file__ = _no_file
        _copy_file = _py2app_command.copy_file

        def _copy_file_skipping_zlib(self, infile, *args, **kwargs):
            if infile == _no_file:
                return None
            return _copy_file(self, infile, *args, **kwargs)

        _py2app_command.copy_file = _copy_file_skipping_zlib
    # Nothing here uses xz; lzma is only reached through shutil's optional
    # import, which tolerates its absence. Bundling it drags in Homebrew's
    # liblzma, whose bottle is built for the host macOS, and
    # build_appstore.py sets LSMinimumSystemVersion from the highest minos in
    # the bundle -- so that one dylib raised the store floor to macOS 27.
    #
    # The rest are third-party and standard-library packages the app never
    # imports. They arrive because the build venv holds more than
    # requirements.txt (anthropic's optional `mcp` import drags in a web-server
    # stack) and because py2app follows every import under `packages`. Dropping
    # them removes about 25 MB, the oldest SDK stamps, and strings such as
    # funding links in third-party package metadata that App Review would read
    # as part of the app. Each name was checked by importing the pruned bundle
    # and building an Anthropic client (build_appstore.import_smoke_test).
    OPTIONS["excludes"] = [
        "lzma",
        "_lzma",
        "mcp",
        "uvicorn",
        "starlette",
        "sse_starlette",
        "httptools",
        "watchfiles",
        "websockets",
        "requests",
        "urllib3",
        "charset_normalizer",
        "cryptography",
        "jsonschema",
        "jsonschema_specifications",
        "referencing",
        "rpds",
        "dns",
        "email_validator",
        "pydantic_settings",
        "python_multipart",
        "dotenv",
        "tomli",
        "markdown_it",
        "mdurl",
        "httpx_sse",
        "setuptools",
        "pkg_resources",
        "_distutils_hack",
        "tkinter",
        "unittest",
        "test",
        "pydoc_data",
        "_pyrepl",
        "xmlrpc",
        "aiohttp",
        "aiosignal",
        "frozenlist",
        "multidict",
        "propcache",
        "yarl",
        "uvloop",
    ]
    # Contents/Resources/PrivacyInfo.xcprivacy; build_appstore.py refuses a
    # bundle whose copy is missing or fails its TN3181 checks (ITMS-91056).
    OPTIONS["resources"] = ["packaging/appstore/PrivacyInfo.xcprivacy"]
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
