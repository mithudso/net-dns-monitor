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

PLIST_PATH="/Library/LaunchDaemons/com.custom.router.nat.plist"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/enable_nat.sh"

if [[ ! -x "$SCRIPT_PATH" ]]; then
    echo "enable_nat.sh not found (or not executable) at $SCRIPT_PATH" >&2
    exit 1
fi

echo "=> Creating persistent NAT LaunchDaemon..."
cat <<EOF > /tmp/com.custom.router.nat.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.custom.router.nat</string>
    <key>ProgramArguments</key>
    <array>
        <string>${SCRIPT_PATH}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
EOF

if [[ -f "$PLIST_PATH" ]]; then
    echo "=> Existing LaunchDaemon found, unloading before replace..."
    launchctl unload -w "$PLIST_PATH" 2>/dev/null || true
fi

mv /tmp/com.custom.router.nat.plist $PLIST_PATH
chown root:wheel $PLIST_PATH
chmod 644 $PLIST_PATH

echo "=> Loading LaunchDaemon..."
launchctl load -w $PLIST_PATH

echo "✅ IP Forwarding and NAT will now persist across reboots."
