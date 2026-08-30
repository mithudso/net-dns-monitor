#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

echo "=> Unloading launchd bootps socket (Frees Port 67)..."
launchctl unload -w /System/Library/LaunchDaemons/bootps.plist 2>/dev/null || true
mv /etc/bootpd.plist /etc/bootpd.plist.bak 2>/dev/null || true
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
    WAN="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')"
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
