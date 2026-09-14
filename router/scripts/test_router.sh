#!/usr/bin/env bash
# Router & DNS Cache Diagnostic Suite

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

echo "========================================="
echo "  ROUTER & DNS DIAGNOSTIC SUITE"
echo "========================================="

# Homebrew lives in /opt/homebrew on Apple silicon and /usr/local on Intel.
# `brew` may not be on PATH (for example under sudo), so fall back rather than fail.
PREFIX="$(brew --prefix 2>/dev/null || true)"
if [ -z "$PREFIX" ]; then
    PREFIX=/opt/homebrew
    warn "brew --prefix unavailable; assuming $PREFIX"
fi

# 1. IP Forwarding
if [ "$(sysctl -n net.inet.ip.forwarding)" -eq 1 ]; then
    pass "IP Forwarding is ENABLED (net.inet.ip.forwarding=1)"
else
    fail "IP Forwarding is DISABLED. Clients will not have internet."
fi

# 2. Apple Internet Sharing (Conflict Check)
if defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT 2>/dev/null | grep -q 'Enabled = 1'; then
    warn "Apple Internet Sharing is ENABLED. This may hijack port 53 via mDNSResponder."
else
    pass "Apple Internet Sharing is DISABLED (No conflicts)"
fi

# 2b. Zombie DHCP (bootpd) Conflict Check
# bootpd is socket-activated: while its launchd job is loaded, launchd itself
# holds UDP 67 and no bootpd process exists until a request arrives. `pgrep`
# therefore passed this check while dnsmasq could not bind the port.
if launchctl print system/com.apple.bootpd >/dev/null 2>&1; then
    fail "bootpd launchd job is loaded: launchd holds UDP 67, so dnsmasq cannot bind it."
else
    pass "bootpd launchd job not loaded (UDP 67 not held by launchd)"
fi

# 2c. Zombie Bridge Check
# bridge100 existing is not by itself a fault: it only swallows traffic when the
# LAN adapter is one of its members, which this check does not inspect.
if ifconfig bridge100 >/dev/null 2>&1; then
    warn "bridge100 exists. If the LAN adapter is a member it will swallow its traffic (ifconfig bridge100)."
else
    pass "No zombie bridge100 detected"
fi

# 3. Packet Filter (PF) NAT Rules
# `sudo -n` fails instead of prompting. A failed sudo is "not checked", not
# "PF disabled" -- reporting it as disabled sends someone after the wrong fault.
if PF_INFO="$(sudo -n pfctl -s info 2>/dev/null)"; then
    if grep -q "Status: Enabled" <<<"$PF_INFO"; then
        pass "PF Firewall is ENABLED"
    else
        fail "PF Firewall is DISABLED. NAT will not work."
    fi
else
    warn "PF status not checked (needs root: rerun with sudo)"
fi

if PF_NAT="$(sudo -n pfctl -a com.apple/custom_nat -s nat 2>/dev/null)"; then
    if grep -q "nat on" <<<"$PF_NAT"; then
        pass "Custom NAT rules found in com.apple/custom_nat"
    else
        fail "Custom NAT rules NOT found. Run the pfctl NAT injection command."
    fi
else
    warn "NAT anchor not checked (needs root: rerun with sudo)"
fi

# 4. Unbound Backend (192.168.4.1:53)
# A nonzero checker exit is not by itself a syntax error: exit 127 means the
# checker is not installed (or not on PATH, for example under sudo), and a missing
# config file fails too. Both are ruled out first so neither reads as bad syntax.
if ! command -v unbound-checkconf >/dev/null 2>&1; then
    warn "unbound-checkconf not installed or not on PATH: Unbound config not checked"
elif [ ! -f "$PREFIX/etc/unbound/unbound.conf" ]; then
    fail "Unbound config not found at $PREFIX/etc/unbound/unbound.conf"
elif unbound-checkconf "$PREFIX/etc/unbound/unbound.conf" >/dev/null 2>&1; then
    pass "Unbound configuration syntax is VALID"
else
    fail "Unbound configuration has SYNTAX ERRORS"
fi

# Test resolution via Unbound directly. `dig +short` prints ";; connection timed
# out" on stdout when nothing answers, so non-empty output alone is not an answer.
if UNBOUND_TEST="$(dig @192.168.4.1 google.com +short +time=2 +tries=1)" \
    && [ -n "$UNBOUND_TEST" ] && ! grep -q '^;' <<<"$UNBOUND_TEST"; then
    pass "Unbound DNS (192.168.4.1:53) answered a query"
else
    fail "Unbound DNS (192.168.4.1:53) FAILED to resolve query. Check logs or upstream TLS."
fi

# 5. Dnsmasq DHCP (192.168.4.1:67)
# Same split as the Unbound check above.
if ! command -v dnsmasq >/dev/null 2>&1; then
    warn "dnsmasq not installed or not on PATH: Dnsmasq config not checked"
elif [ ! -f "$PREFIX/etc/dnsmasq.conf" ]; then
    fail "Dnsmasq config not found at $PREFIX/etc/dnsmasq.conf"
elif dnsmasq --test -C "$PREFIX/etc/dnsmasq.conf" >/dev/null 2>&1; then
    pass "Dnsmasq configuration syntax is VALID"
else
    fail "Dnsmasq configuration has SYNTAX ERRORS"
fi

# 6. DHCP Configuration Check
if grep -q "dhcp-range=192.168.4.50" "$PREFIX/etc/dnsmasq.conf"; then
    pass "DHCP Range configured for 192.168.4.x subnet"
else
    fail "DHCP Range missing or misconfigured in dnsmasq.conf"
fi

echo "========================================="
echo "Diagnostics complete."
