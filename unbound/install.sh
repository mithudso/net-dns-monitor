#!/usr/bin/env bash
# RETIRED 2026-09-22 (see router/docs/ROUTER.md): the LAN moved to 192.168.1.0/24, whose
# gateway (192.168.1.254) already serves DHCP. Re-running this stack would put a second DHCP
# server on the network. Set NDM_ROUTER_FORCE=1 only to deliberately rebuild the old subnet.
if [[ "${NDM_ROUTER_FORCE:-0}" != "1" ]]; then
    echo "router stack retired 2026-09-22; refusing to run (set NDM_ROUTER_FORCE=1 to override)" >&2
    exit 1
fi
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"

echo "=> Installing Unbound & Dnsmasq..."
brew install unbound dnsmasq

echo "=> Deploying configurations..."
# Unbound
UNBOUND_CONF_DIR="$(brew --prefix)/etc/unbound"
mkdir -p "$UNBOUND_CONF_DIR"
cp "$SCRIPT_DIR/unbound.conf" "$UNBOUND_CONF_DIR/unbound.conf"

# Dnsmasq
DNSMASQ_CONF_DIR="$(brew --prefix)/etc"
cp "$BASE_DIR/dnsmasq/dnsmasq.conf" "$DNSMASQ_CONF_DIR/dnsmasq.conf"

echo "=> Validating configurations..."
unbound-checkconf "$UNBOUND_CONF_DIR/unbound.conf"
dnsmasq --test

echo "=> Clearing old PF NAT rules..."
sudo pfctl -a com.apple/unbound_dns -F all 2>/dev/null || true

echo "=> Starting Services..."
sudo brew services restart unbound
sudo brew services restart dnsmasq

echo "============================================="
echo "✅ ARCHITECTURE DEPLOYED"
echo "- Dnsmasq: Listening on 192.168.4.1:67 (DHCP Server Only)"
echo "- Unbound: Listening on 192.168.4.1:53 (Direct DoT & Caching DNS)"
echo "Clients plugging into AX88179B will automatically receive a 192.168.4.x IP and DNS server."
