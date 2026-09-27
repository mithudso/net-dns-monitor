# Router Architecture

> **Retired 2026-09-22.** This Mac left the `192.168.4.0/24` network and is no
> longer a router. The live daemons, pf anchors, and interface config were
> snapshotted to `/Users/mitch/Archive/old-network-2026-09-22/` (see its
> `INVENTORY.md`), and are removed by that directory's `retire.sh`. This
> document and the scripts beside it are kept as the record of the stack.

## Overview
Turns macOS into a strict hardware router. Bypasses Apple's GUI Internet Sharing which hijacks ports.

## Components
1. **Dnsmasq** (`dnsmasq/dnsmasq.conf`)
   - DHCP Server (Port 67)
   - Assigns `192.168.4.x` IPs.
   - DNS proxying disabled (`port=0`).

2. **Unbound** (`unbound/unbound.conf`)
   - Direct DoT (DNS-over-TLS) Cache (Port 53)
   - Binds directly to `192.168.4.1`.
   - Answers only loopback and `192.168.4.0/24`; runs as `nobody` after binding.
   - Bypasses ISP logging, serves stale cache for speed.

3. **PF / NAT** (`router/scripts/enable_nat.sh`)
   - Replaces macOS Internet Sharing.
   - Forwards traffic from `192.168.4.0/24` to the interface that holds the default route, detected on each run (e.g. `en13`).
   - Loads its rule into the `com.apple/custom_nat` anchor, so Apple's main ruleset is left alone.

4. **LaunchDaemon** (`router/scripts/install_persistent_nat.sh`)
   - Apple resets IP forwarding on boot.
   - Installs a root-owned copy of `enable_nat.sh` at `/Library/PrivilegedHelperTools/net-dns-monitor/enable_nat.sh` and points the daemon there. The daemon runs as root, so it must never run a file in a user-writable checkout.
   - Runs at load and every 60 seconds (`StartInterval`): sets `net.inet.ip.forwarding=1`, unloads `bootpd`, and re-detects the upstream interface so NAT follows a failover.
   - Logs to `/var/log/com.custom.router.nat.out.log` and `.err.log`.
   - After editing `enable_nat.sh`, re-run the installer: the daemon runs the installed copy, not the file in the repo.

## Known Apple Conflicts
- **bootpd:** Apple's DHCP server is socket-activated. While its launchd job (`com.apple.bootpd`) is loaded, launchd holds UDP 67 and `dnsmasq` cannot bind, even when no `bootpd` process is running. `enable_nat.sh` unloads the job and moves `/etc/bootpd.plist` to `/etc/bootpd.plist.bak`.
- **bridge100:** Internet Sharing can leave a bridge that traps a physical adapter (`en15`). It is only a problem if the LAN adapter is a member; remove it with `sudo ifconfig bridge100 deletem en15`.

## The app's Router menu is a different router
The menu bar app has its own router mode (`netdnsmonitor/router.py`, the **Router** menu and the Router Management Console). It is a separate implementation, not a front end for this stack:

| | `router/` stack (this document) | App Router menu |
|---|---|---|
| DHCP | dnsmasq | Apple `bootpd` |
| LAN | `192.168.4.0/24` | `192.168.10.0/24` by default |
| NAT anchor | `com.apple/custom_nat` | `com.apple/netdnsmonitor_nat` |

The two conflict: both need UDP 67, and stopping the app's router turns IP forwarding off. The app therefore refuses to start or stop its router while `/Library/LaunchDaemons/com.custom.router.nat.plist` is installed. Which of the two is the supported router has not been decided; neither is removed.
