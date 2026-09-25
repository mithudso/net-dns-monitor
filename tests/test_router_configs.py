"""Static checks on the router/ stack's dnsmasq and unbound configs.

Moved from router/tests/test_configs.py, which pytest never collected
(`testpaths = tests`). Only non-comment lines are parsed: a substring match on
the raw file passed as long as a comment mentioned the setting.
"""

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DNSMASQ = ROOT / "dnsmasq" / "dnsmasq.conf"
UNBOUND = ROOT / "unbound" / "unbound.conf"


def _lines(path):
    for raw in path.read_text(encoding="utf-8").splitlines():
        # `#` starts a comment only at a token boundary: `1.1.1.1@853#name` is
        # unbound's syntax for a TLS auth name, not a comment.
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()
        if line:
            yield line


def dnsmasq_settings():
    settings = {}
    for line in _lines(DNSMASQ):
        key, _, value = line.partition("=")
        settings.setdefault(key.strip(), []).append(value.strip())
    return settings


def unbound_settings():
    settings = {}
    for line in _lines(UNBOUND):
        key, _, value = line.partition(":")
        settings.setdefault(key.strip(), []).append(value.strip())
    return settings


def test_dnsmasq_serves_dhcp_only_on_the_router_address():
    s = dnsmasq_settings()
    assert s["port"] == ["0"], "dnsmasq must yield DNS (port 53) to unbound"
    assert s["listen-address"] == ["192.168.4.1"]
    assert "bind-interfaces" in s


def test_dnsmasq_dhcp_range_is_inside_the_router_lan():
    lan = ipaddress.IPv4Network("192.168.4.0/24")
    (dhcp_range,) = dnsmasq_settings()["dhcp-range"]
    start, end, _lease = dhcp_range.split(",")
    assert start == "192.168.4.50"
    assert ipaddress.IPv4Address(start) in lan
    assert ipaddress.IPv4Address(end) in lan
    assert ipaddress.IPv4Address(start) < ipaddress.IPv4Address(end)


def test_dnsmasq_hands_out_the_router_as_gateway_and_dns():
    options = dnsmasq_settings()["dhcp-option"]
    assert "option:router,192.168.4.1" in options
    assert "option:dns-server,192.168.4.1" in options


def test_unbound_listens_on_the_router_address_port_53():
    s = unbound_settings()
    assert s["interface"] == ["192.168.4.1"]
    assert s["port"] == ["53"]


def test_unbound_answers_only_loopback_and_the_router_lan():
    acl = {tuple(value.split()) for value in unbound_settings()["access-control"]}
    assert acl == {("127.0.0.0/8", "allow"), ("192.168.4.0/24", "allow")}


def test_unbound_does_not_run_as_root():
    (username,) = unbound_settings()["username"]
    assert username.strip('"') not in ("", "root")


def test_unbound_forwards_over_tls_with_a_cert_bundle():
    s = unbound_settings()
    assert s["forward-tls-upstream"] == ["yes"]
    assert s["tls-cert-bundle"] and s["tls-cert-bundle"][0].strip('"')
    assert all("@853#" in addr for addr in s["forward-addr"])
