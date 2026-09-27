# Installation

Choose one of three ways to run the app.

| Way | For | Guide |
|---|---|---|
| Direct build, supervised LaunchAgent | Daily use on your own Mac, with every feature | [HOWTO.md](../HOWTO.md) → Installation, then `./scripts/install.sh` |
| From source | Development | [DEVELOPMENT.md](DEVELOPMENT.md) |
| Mac App Store build | Distribution through the store (reduced edition) | [APP_STORE_SUBMISSION.md](APP_STORE_SUBMISSION.md) |

## Prerequisites

- macOS on Apple silicon. The bundled Python sets the minimum OS; the Homebrew build is macOS 26.
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
