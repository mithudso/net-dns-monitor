#!/usr/bin/env bash
# RETIRED 2026-09-22 (see router/docs/ROUTER.md): the LAN moved to 192.168.1.0/24, whose
# gateway (192.168.1.254) already serves DHCP. Re-running this stack would put a second DHCP
# server on the network. Set NDM_ROUTER_FORCE=1 only to deliberately rebuild the old subnet.
if [[ "${NDM_ROUTER_FORCE:-0}" != "1" ]]; then
    echo "router stack retired 2026-09-22; refusing to run (set NDM_ROUTER_FORCE=1 to override)" >&2
    exit 1
fi
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

# `cp` onto a symlink writes through it. Where a deployed config is a link into
# a checkout, a run from another tree rewrote that checkout's tracked file, and
# a run from the same checkout failed on "are identical" after the backup.
# Both destinations are checked before either file is replaced.
refuse_foreign_link() {
    local src="$1" dst="$2"
    if [[ -L "$dst" ]] && ! [[ "$src" -ef "$dst" ]]; then
        echo "ERROR: $dst is a symlink to $(readlink "$dst")." >&2
        echo "       Copying onto it would overwrite that file. No configuration was changed." >&2
        echo "       Remove the link or point it at $src, then re-run." >&2
        exit 1
    fi
}

deploy() {
    local src="$1" dst="$2"
    if [[ "$src" -ef "$dst" ]]; then
        echo "   $dst already resolves to $src; not copied"
        return 0
    fi
    backup "$dst"
    cp "$src" "$dst"
}

refuse_foreign_link "$UNBOUND_SRC" "$UNBOUND_CONF_DIR/unbound.conf"
refuse_foreign_link "$DNSMASQ_SRC" "$DNSMASQ_CONF_DIR/dnsmasq.conf"

mkdir -p "$UNBOUND_CONF_DIR"
deploy "$UNBOUND_SRC" "$UNBOUND_CONF_DIR/unbound.conf"
deploy "$DNSMASQ_SRC" "$DNSMASQ_CONF_DIR/dnsmasq.conf"

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

# Same reason as the dnsmasq check: `brew services restart unbound` does not
# notice an unbound that exited after starting, or lost the port to another
# resolver, so the banner below would claim DNS is served when it is not.
echo "=> Verifying unbound holds DNS (port 53)..."
DNS_BOUND=""
for _ in 1 2 3 4 5; do
    LSOF_DNS="$(sudo lsof -nP -iUDP:53 2>/dev/null || true)"
    if grep -q unbound <<<"$LSOF_DNS"; then
        DNS_BOUND=1
        break
    fi
    sleep 1
done
if [[ -z "$DNS_BOUND" ]]; then
    echo "ERROR: unbound is not bound to port 53. DNS is NOT being served by it." >&2
    echo "       Check: sudo lsof -nP -iUDP:53   and   router/scripts/test_router.sh" >&2
    exit 1
fi

echo "============================================="
echo "✅ ARCHITECTURE DEPLOYED"
echo "- Dnsmasq: Listening on 192.168.4.1:67 (DHCP Server Only)"
echo "- Unbound: Listening on 192.168.4.1:53 (Direct DoT & Caching DNS)"
echo "Clients plugging into AX88179B will automatically receive a 192.168.4.x IP and DNS server."
