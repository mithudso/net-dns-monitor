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
   - Bypasses ISP logging, serves stale cache for speed.

3. **PF / NAT** (`router/scripts/enable_nat.sh`)
   - Replaces macOS Internet Sharing.
   - Forwards traffic from `192.168.4.0/24` to the active internet interface (e.g. `en13`).

4. **LaunchDaemon** (`router/scripts/install_persistent_nat.sh`)
   - Apple resets IP forwarding on boot.
   - Daemon injects `net.inet.ip.forwarding=1` and kills zombie `bootpd` on every boot.

## Known Apple Conflicts
- **bootpd:** Apple's DHCP server auto-starts if `/etc/bootpd.plist` exists, hogging port 67 and crashing `dnsmasq`. Script nukes this plist.
- **bridge100:** Apple leaves zombie bridges that trap physical adapters (`en15`). Require manual deletion: `sudo ifconfig bridge100 deletem en15`.
