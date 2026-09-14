#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

UNBOUND_SRC="$SCRIPT_DIR/unbound.conf"
DNSMASQ_SRC="$BASE_DIR/dnsmasq/dnsmasq.conf"

echo "=> Installing Unbound & Dnsmasq..."
brew install unbound dnsmasq

PREFIX="$(brew --prefix)"
UNBOUND_CONF_DIR="$PREFIX/etc/unbound"
DNSMASQ_CONF_DIR="$PREFIX/etc"

# Validate the files in the repo BEFORE copying them. Validating after the copy
# meant a broken config had already replaced the working one when the check
# failed, and the next service restart would take DNS and DHCP down with it.
echo "=> Validating configurations..."
unbound-checkconf "$UNBOUND_SRC"
dnsmasq --test -C "$DNSMASQ_SRC"

echo "=> Deploying configurations (existing files are backed up)..."
STAMP="$(date +%Y%m%d-%H%M%S)"
backup() {
    if [[ -f "$1" ]]; then
        cp -p "$1" "$1.bak.$STAMP"
        echo "   backed up $1 -> $1.bak.$STAMP"
    fi
}

mkdir -p "$UNBOUND_CONF_DIR"
backup "$UNBOUND_CONF_DIR/unbound.conf"
cp "$UNBOUND_SRC" "$UNBOUND_CONF_DIR/unbound.conf"

backup "$DNSMASQ_CONF_DIR/dnsmasq.conf"
cp "$DNSMASQ_SRC" "$DNSMASQ_CONF_DIR/dnsmasq.conf"

echo "=> Clearing old PF NAT rules..."
sudo pfctl -a com.apple/unbound_dns -F all 2>/dev/null || true

echo "=> Starting Services..."
sudo brew services restart unbound
sudo brew services restart dnsmasq

# `brew services restart` can report success before dnsmasq has bound its
# socket, and does not notice if dnsmasq then exits -- for example because
# bootpd's launchd job already holds UDP 67.
# Captured into a variable rather than piped into `grep -q`: under pipefail, grep
# exiting early can make lsof fail with SIGPIPE and turn a match into a failure.
echo "=> Verifying dnsmasq holds DHCP (UDP 67)..."
BOUND=""
for _ in 1 2 3 4 5; do
    LSOF_OUT="$(sudo lsof -nP -iUDP:67 2>/dev/null || true)"
    if grep -q dnsmasq <<<"$LSOF_OUT"; then
        BOUND=1
        break
    fi
    sleep 1
done
if [[ -z "$BOUND" ]]; then
    echo "ERROR: dnsmasq is not bound to UDP 67. DHCP is NOT being served." >&2
    echo "       Check: sudo lsof -nP -iUDP:67   and   router/scripts/test_router.sh" >&2
    exit 1
fi

echo "============================================="
echo "✅ ARCHITECTURE DEPLOYED"
echo "- Dnsmasq: Listening on 192.168.4.1:67 (DHCP Server Only)"
echo "- Unbound: Listening on 192.168.4.1:53 (Direct DoT & Caching DNS)"
echo "Clients plugging into AX88179B will automatically receive a 192.168.4.x IP and DNS server."
