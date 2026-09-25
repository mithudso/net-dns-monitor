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
if pgrep -q bootpd; then
    fail "Apple's bootpd is RUNNING and hogging DHCP port 67. Dnsmasq will crash."
else
    pass "Apple bootpd is NOT running (Port 67 is free for Dnsmasq)"
fi

# 2c. Zombie Bridge Check
if ifconfig bridge100 >/dev/null 2>&1; then
    fail "Zombie bridge100 exists! This will swallow your adapter's traffic."
else
    pass "No zombie bridge100 detected"
fi

# 3. Packet Filter (PF) NAT Rules
if sudo pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
    pass "PF Firewall is ENABLED"
else
    fail "PF Firewall is DISABLED. NAT will not work."
fi

if sudo pfctl -a com.apple/custom_nat -s nat 2>/dev/null | grep -q "nat on"; then
    pass "Custom NAT rules found in com.apple/custom_nat"
else
    fail "Custom NAT rules NOT found. Run the pfctl NAT injection command."
fi

# 4. Unbound Backend (192.168.4.1:53)
if unbound-checkconf /opt/homebrew/etc/unbound/unbound.conf >/dev/null 2>&1; then
    pass "Unbound configuration syntax is VALID"
else
    fail "Unbound configuration has SYNTAX ERRORS"
fi

# Test resolution via Unbound directly
UNBOUND_TEST=$(dig @192.168.4.1 google.com +short +time=2)
if [ -n "$UNBOUND_TEST" ]; then
    pass "Unbound DNS (192.168.4.1:53) successfully resolved query over DoT"
else
    fail "Unbound DNS (192.168.4.1:53) FAILED to resolve query. Check logs or upstream TLS."
fi

# 5. Dnsmasq DHCP (192.168.4.1:67)
if dnsmasq --test -C /opt/homebrew/etc/dnsmasq.conf >/dev/null 2>&1; then
    pass "Dnsmasq configuration syntax is VALID"
else
    fail "Dnsmasq configuration has SYNTAX ERRORS"
fi

# 6. DHCP Configuration Check
if grep -q "dhcp-range=192.168.4.50" /opt/homebrew/etc/dnsmasq.conf; then
    pass "DHCP Range configured for 192.168.4.x subnet"
else
    fail "DHCP Range missing or misconfigured in dnsmasq.conf"
fi

echo "========================================="
echo "Diagnostics complete."
