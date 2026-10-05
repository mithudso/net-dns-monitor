#!/usr/bin/env bash
# RETIRED 2026-09-22 (see router/docs/ROUTER.md): the LAN moved to 192.168.1.0/24, whose
# gateway (192.168.1.254) already serves DHCP. Re-running this stack would put a second DHCP
# server on the network. Set NDM_ROUTER_FORCE=1 only to deliberately rebuild the old subnet.
if [[ "${NDM_ROUTER_FORCE:-0}" != "1" ]]; then
    echo "router stack retired 2026-09-22; refusing to run (set NDM_ROUTER_FORCE=1 to override)" >&2
    exit 1
fi
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "=> Unloading launchd bootps socket (Frees Port 67)..."
launchctl unload -w /System/Library/LaunchDaemons/bootps.plist 2>/dev/null || true
# This script re-runs every 60s. An unconditional mv would overwrite the .bak
# with whatever bootpd.plist exists by then (the app router writes one), losing
# the original configuration for good.
if [[ ! -e /etc/bootpd.plist.bak ]]; then
    mv /etc/bootpd.plist /etc/bootpd.plist.bak 2>/dev/null || true
fi
killall bootpd 2>/dev/null || true

echo "=> Enabling IP Forwarding..."
sysctl -w net.inet.ip.forwarding=1

# Upstream interface is DETECTED, not hardcoded. It was pinned to en13, which
# is correct only while the USB LAN adapter is the default route -- fail over
# to Wi-Fi and NAT keeps pointing at a dead interface, silently, with pf
# reporting a perfectly healthy rule that matches nothing.
#
# RunAtLoad can fire before the network is up, so wait for a default route
# rather than racing it and exiting.
WAN=""
for _ in $(seq 1 30); do
    # `|| true`: with no default route `route` exits 1, and under pipefail that
    # kills the script on the first pass instead of letting it wait for one.
    WAN="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)"
    [[ -n "$WAN" ]] && break
    sleep 2
done

if [[ -z "$WAN" ]]; then
    echo "ERROR: no default route after 60s — cannot determine the upstream" >&2
    echo "       interface. NAT NOT configured (forwarding left enabled)." >&2
    exit 1
fi

echo "=> Configuring NAT from 192.168.4.x out through ${WAN}..."
printf 'nat on %s from 192.168.4.0/24 to any -> (%s)\n' "$WAN" "$WAN" \
    | pfctl -a com.apple/custom_nat -f -

echo "=> Enabling PF Firewall..."
pfctl -e 2>/dev/null || true

echo "=> Checking status..."
pfctl -s info | grep "Status: Enabled"
pfctl -a com.apple/custom_nat -s nat

echo "✅ NAT configured."
