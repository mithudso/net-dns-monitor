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

echo "=> Configuring NAT from 192.168.4.x out through en13..."
echo "nat on en13 from 192.168.4.0/24 to any -> (en13)" | pfctl -a com.apple/custom_nat -f -

echo "=> Enabling PF Firewall..."
pfctl -e 2>/dev/null || true

echo "=> Checking status..."
pfctl -s info | grep "Status: Enabled"
pfctl -a com.apple/custom_nat -s nat

echo "✅ NAT configured."
