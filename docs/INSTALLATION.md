# Installation

Choose the installation path for your edition.

| Way | For | Guide |
|---|---|---|
| Direct download, Free or Premium | Build and run on your Mac with the edition selected by the package | [Net DNS Monitor](https://netdnsmonitor.com) and the package's `START-HERE.md` |
| Direct build, supervised LaunchAgent | Daily use on your own Mac, with every feature | [HOWTO.md](../HOWTO.md) → Installation, then `./scripts/install.sh` |
| From source | Development | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Mac App Store build | Distribution through the store (reduced edition) | [APP_STORE_SUBMISSION.md](APP_STORE_SUBMISSION.md) |

## Prerequisites

- macOS on Apple silicon. macOS 26 or later for the store build (`LSMinimumSystemVersion` 26.0, set by `scripts/appstore/build_appstore.py`).
- Python 3.13. `scripts/install.sh` and `scripts/start.sh` refuse older versions.
- Xcode 26 or later, only for the Mac App Store build.

## Website downloads

The website ZIPs contain complete source packages. Each runs the same setup
script on the buyer's Mac using Python 3.13 and first-run internet access.
Free records incidents and runs diagnostics. Premium can also run repairs.
Premium's elevated repairs need permissions. Automatic failover requires
configured services and is off by default.

To assemble both packages for distribution, run this from the checkout root
and specify a fresh artifact directory.

```bash
python3 scripts/build_direct_release.py /path/to/release-artifacts
```

The script reads the checked-out application sources and a public sample
configuration. Each ZIP includes setup instructions and the MIT license.
The script prints the package checksums. Keep the Premium ZIP in private
storage for delivery after checkout.

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

To move from the menu bar's **Start at Login** to the supervised service, turn
off the menu item first. If the standalone agent was loaded earlier in this
session, log out and back in before installing the supervised service. Its
installer refuses to replace the bundle or register a second job while the
standalone agent is installed or loaded.

With the supervised service installed, **Start at Login** reflects whether
supervision is enabled. A stopped supervisor leaves the box unchecked. Use
`net-dns-monitor-service start` to re-enable its startup job.

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
wrapper and the **Start at Login** writer share `service-install.lock`; the optional indexer installer reserves
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
