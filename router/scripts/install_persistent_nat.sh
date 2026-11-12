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

# Both the app's router (netdnsmonitor/router.py) and this stack want UDP 67 and
# net.inet.ip.forwarding; Router.start refuses while this daemon's plist exists
# and this is the matching refusal in the other direction.
if /sbin/pfctl -a com.apple/netdnsmonitor_nat -s nat 2>/dev/null | /usr/bin/grep -q 'nat on'; then
    echo "Refusing: the app's router has NAT rules in com.apple/netdnsmonitor_nat. Stop it from the menu bar (Router -> Stop) first." >&2
    exit 1
fi
if /bin/launchctl print system/com.apple.bootpd >/dev/null 2>&1; then
    echo "Refusing: the system bootpd job is loaded, so another DHCP server (the app's router, or Internet Sharing) is live. Stop it first." >&2
    exit 1
fi

PLIST_PATH="/Library/LaunchDaemons/com.custom.router.nat.plist"
SOURCE_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/enable_nat.sh"

# The daemon runs as root, so the script it runs must be one only root can
# change. Pointing ProgramArguments at the checkout meant any process running as
# the user who owns the checkout could edit enable_nat.sh and have it run as root.
HELPER_DIR="/Library/PrivilegedHelperTools/net-dns-monitor"
HELPER_PATH="${HELPER_DIR}/enable_nat.sh"

if [[ ! -f "$SOURCE_PATH" ]]; then
    echo "enable_nat.sh not found at $SOURCE_PATH" >&2
    exit 1
fi

if [[ -L "$HELPER_DIR" || -L "$HELPER_PATH" ]]; then
    echo "Refusing: $HELPER_DIR or $HELPER_PATH is a symlink" >&2
    exit 1
fi

TMP_PLIST=""
HELPER_TMP=""
OLD_PLIST_BACKUP=""
OLD_HELPER_BACKUP=""
ROLLBACK_ARMED=0
HELPER_CHANGED=0
PLIST_CHANGED=0

# Recovery covers both installation artifacts. Retain a backup whose restore
# fails so an I/O failure does not also destroy the operator's recovery copy.
cleanup() {
    local rc=$? restore_failed=0
    /bin/rm -f "$TMP_PLIST" "$HELPER_TMP"
    if [[ $rc -ne 0 && $ROLLBACK_ARMED -eq 1 ]]; then
        echo "ERROR: install failed; restoring the previous helper and daemon" >&2
        if [[ $PLIST_CHANGED -eq 1 ]]; then
            launchctl unload -w "$PLIST_PATH" 2>/dev/null || true
        fi
        if [[ $HELPER_CHANGED -eq 1 ]]; then
            if [[ -n "$OLD_HELPER_BACKUP" ]]; then
                /bin/mv -f "$OLD_HELPER_BACKUP" "$HELPER_PATH" || restore_failed=1
            else
                /bin/rm -f "$HELPER_PATH" || restore_failed=1
            fi
        fi
        if [[ -n "$OLD_PLIST_BACKUP" ]]; then
            if /bin/mv -f "$OLD_PLIST_BACKUP" "$PLIST_PATH"; then
                if [[ $restore_failed -eq 0 ]]; then
                    launchctl load -w "$PLIST_PATH" || restore_failed=1
                fi
            else
                restore_failed=1
            fi
        elif [[ $PLIST_CHANGED -eq 1 ]]; then
            /bin/rm -f "$PLIST_PATH" || restore_failed=1
        fi
    fi
    if [[ $restore_failed -eq 1 ]]; then
        echo "ERROR: rollback incomplete; inspect $PLIST_PATH and $HELPER_PATH. Recovery backups: $OLD_PLIST_BACKUP $OLD_HELPER_BACKUP" >&2
    else
        [[ -z "$OLD_PLIST_BACKUP" ]] || /bin/rm -f "$OLD_PLIST_BACKUP"
        [[ -z "$OLD_HELPER_BACKUP" ]] || /bin/rm -f "$OLD_HELPER_BACKUP"
    fi
    return $rc
}
trap cleanup EXIT

echo "=> Installing a root-owned copy of enable_nat.sh at $HELPER_PATH..."
/usr/bin/install -d -o root -g wheel -m 755 "$HELPER_DIR"
/usr/sbin/chown root:wheel "$HELPER_DIR"
/bin/chmod 755 "$HELPER_DIR"
# Staged next to the target and renamed into place: launchd re-runs the helper
# every 60s, and an in-place install could be read half written.
HELPER_TMP="$(/usr/bin/mktemp "$HELPER_DIR/.enable_nat.XXXXXX")"
/usr/bin/install -o root -g wheel -m 755 "$SOURCE_PATH" "$HELPER_TMP"

echo "=> Creating persistent NAT LaunchDaemon..."
# Staged inside /Library/LaunchDaemons (root-only), not /tmp: a predictable
# /tmp name can be pre-created or swapped by another user before the mv.
TMP_PLIST="$(/usr/bin/mktemp /Library/LaunchDaemons/.com.custom.router.nat.XXXXXX)"

# StartInterval re-runs enable_nat.sh every 60s. It re-detects the upstream
# interface on each run, so NAT follows a failover to another interface within
# a minute instead of staying on the interface that was up at boot.
cat <<EOF > "$TMP_PLIST"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.custom.router.nat</string>
    <key>ProgramArguments</key>
    <array>
        <string>${HELPER_PATH}</string>
    </array>
    <!-- This installer only runs after the operator explicitly overrides retirement. -->
    <key>EnvironmentVariables</key>
    <dict>
        <key>NDM_ROUTER_FORCE</key>
        <string>1</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>StartInterval</key>
    <integer>60</integer>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/var/log/com.custom.router.nat.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/com.custom.router.nat.err.log</string>
</dict>
</plist>
EOF

/bin/chmod 644 "$TMP_PLIST"
/usr/sbin/chown root:wheel "$TMP_PLIST"
/usr/bin/plutil -lint "$TMP_PLIST"

if [[ -f "$PLIST_PATH" ]]; then
    echo "=> Existing LaunchDaemon found, unloading before replace..."
    OLD_PLIST_BACKUP="$(/usr/bin/mktemp /Library/LaunchDaemons/.com.custom.router.nat.old.XXXXXX)"
    /bin/cp -p "$PLIST_PATH" "$OLD_PLIST_BACKUP"
fi
if [[ -f "$HELPER_PATH" ]]; then
    OLD_HELPER_BACKUP="$(/usr/bin/mktemp "$HELPER_DIR/.enable_nat.old.XXXXXX")"
    /bin/cp -p "$HELPER_PATH" "$OLD_HELPER_BACKUP"
fi
ROLLBACK_ARMED=1
if [[ -f "$PLIST_PATH" ]]; then
    launchctl unload -w "$PLIST_PATH" 2>/dev/null || true
fi
HELPER_CHANGED=1
/bin/mv -f "$HELPER_TMP" "$HELPER_PATH"
HELPER_TMP=""
PLIST_CHANGED=1

/bin/mv -f "$TMP_PLIST" "$PLIST_PATH"
TMP_PLIST=""

echo "=> Loading LaunchDaemon..."
launchctl load -w "$PLIST_PATH"
ROLLBACK_ARMED=0

echo "✅ IP Forwarding and NAT will now persist across reboots."
