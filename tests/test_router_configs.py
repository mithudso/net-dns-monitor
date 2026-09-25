"""The dnsmasq + unbound stack's config files, checked as whole lines.

Anchored regexes on purpose: `'port: 53' in content` is also true of
`port: 5353`, and `'port=0' in content` is true of a commented-out
`#port=0`, so the substring checks this replaced passed on the wrong file.
"""

import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    path = os.path.join(BASE_DIR, *parts)
    assert os.path.exists(path), path
    with open(path, encoding="utf-8") as f:
        return f.read()


def has_line(pattern, content):
    return re.search(pattern, content, re.M) is not None


def test_dnsmasq_yields_dns_to_unbound_with_port_zero():
    content = read("dnsmasq", "dnsmasq.conf")
    assert has_line(r"^\s*port=0\s*$", content)


def test_dnsmasq_serves_dhcp_on_the_lan_subnet():
    content = read("dnsmasq", "dnsmasq.conf")
    assert has_line(r"^\s*dhcp-range=192\.168\.4\.50,", content)
    assert has_line(r"^\s*listen-address=192\.168\.4\.1\s*$", content)


def test_unbound_binds_port_53_on_the_lan_ip():
    content = read("unbound", "unbound.conf")
    assert has_line(r"^\s*interface:\s*192\.168\.4\.1\s*$", content)
    assert has_line(r"^\s*port:\s*53\s*$", content)


def test_unbound_carries_a_tls_bundle_for_dot():
    content = read("unbound", "unbound.conf")
    assert has_line(r"^\s*tls-cert-bundle:", content)


def test_anchored_port_check_rejects_a_lookalike():
    assert not has_line(r"^\s*port:\s*53\s*$", "    port: 5353\n")
    assert not has_line(r"^\s*port=0\s*$", "#port=0\n")
