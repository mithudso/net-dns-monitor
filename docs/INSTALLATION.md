# Installation

Choose one of three ways to run the app.

| Way | For | Guide |
|---|---|---|
| Direct build, supervised LaunchAgent | Daily use on your own Mac, with every feature | [HOWTO.md](../HOWTO.md) → Installation, then `./scripts/install.sh` |
| From source | Development | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Mac App Store build | Distribution through the store (reduced edition) | [APP_STORE_SUBMISSION.md](APP_STORE_SUBMISSION.md) |

## Prerequisites

- macOS on Apple silicon. macOS 26 or later for the store build (`LSMinimumSystemVersion` 26.0, set by `scripts/appstore/build_appstore.py`).
- Python 3.13. `scripts/install.sh` and `scripts/start.sh` refuse older versions.
- Xcode 26 or later, only for the Mac App Store build.

## Verify an install

Check that the bundle is installed and the supervising agent is loaded.
Don't run the bundle's executable directly: it starts the app.

```bash
ls -d ~/Applications/Net-DNS-Monitor.app
launchctl print "gui/$(id -u)/com.mitchhudson.net-dns-monitor" | head -5
```

From a source checkout, run a single status check. It exits 1 if the network
is unhealthy.

```bash
.venv/bin/python -m netdnsmonitor.cli status
```

## Upgrade and uninstall

```bash
NDM_SOURCE_BUNDLE=dist/Net-DNS-Monitor.app scripts/net-dns-monitor-service update
scripts/net-dns-monitor-service uninstall
```

Uninstalling leaves `~/.config/net-dns-monitor/` and
`~/Library/Application Support/net-dns-monitor/`, so reports and settings
survive. Delete them by hand if you want a clean removal. The Mac App Store
build keeps everything in `~/Library/Containers/<bundle id>/`.

## Build and service reservations

`start.sh` and `install.sh` reserve `.netdns-build.lock` in the checkout and
`startup.lock` under the user's Application Support directory. The service
wrapper reserves `service-install.lock`; the optional indexer installer reserves
its plist's `.install.lock`. A concurrent owner causes a refusal. Normal exits
remove only reservations created by that invocation. An abrupt `SIGKILL` can
leave an empty directory reservation behind.

Recovery is manual: identify the exact reported lock, inspect the owning build,
installer or service command and wait for it to finish. Remove only that empty
reservation with `rmdir` after confirming no owner remains. Do not use recursive
removal or steal an active reservation. This is separate from the persistent
advisory lock files used by journal rotation and semantic indexing; do not unlink
those inodes.

The source fingerprint `dist/.netdns-source.sha256` records the inputs to a
successful direct build. It invalidates cached bundles when source changes.
Maintenance source checks do not build, install, restart or activate the app.
The headless and fleet commands are documented in [FLEET.md](FLEET.md); they do
not replace the menubar install automatically.
