#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

PLIST_PATH="/Library/LaunchDaemons/com.custom.router.nat.plist"
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/enable_nat.sh"
# The daemon runs as root at every boot, so it must not execute a file in a
# user-writable checkout: whoever can edit the repo would own root on boot.
INSTALLED_SCRIPT="/usr/local/libexec/netdns-enable_nat.sh"

if [[ ! -x "$SCRIPT_PATH" ]]; then
    echo "enable_nat.sh not found (or not executable) at $SCRIPT_PATH" >&2
    exit 1
fi

echo "=> Installing NAT script to ${INSTALLED_SCRIPT}..."
install -d -o root -g wheel -m 0755 "$(dirname "$INSTALLED_SCRIPT")"
install -o root -g wheel -m 0755 "$SCRIPT_PATH" "$INSTALLED_SCRIPT"

echo "=> Creating persistent NAT LaunchDaemon..."
TMP="$(mktemp)"
cat <<EOF > "$TMP"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.custom.router.nat</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALLED_SCRIPT}</string>
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

install -o root -g wheel -m 0644 "$TMP" "$PLIST_PATH"
rm -f "$TMP"

echo "=> Loading LaunchDaemon..."
launchctl load -w "$PLIST_PATH"

echo "✅ IP Forwarding and NAT will now persist across reboots."
