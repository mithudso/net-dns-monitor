#!/usr/bin/env python3
import os
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))


class TestRouterConfigs(unittest.TestCase):
    def test_dnsmasq_config(self):
        conf_path = os.path.join(BASE_DIR, "dnsmasq", "dnsmasq.conf")
        self.assertTrue(os.path.exists(conf_path))
        with open(conf_path) as f:
            content = f.read()
        self.assertIn("port=0", content, "Dnsmasq MUST have port=0 to yield DNS to unbound.")
        self.assertIn("dhcp-range=192.168.4.50", content, "DHCP range missing.")
        self.assertIn("listen-address=192.168.4.1", content, "Listen address missing.")

    def test_unbound_config(self):
        conf_path = os.path.join(BASE_DIR, "unbound", "unbound.conf")
        self.assertTrue(os.path.exists(conf_path))
        with open(conf_path) as f:
            content = f.read()
        self.assertIn("interface: 192.168.4.1", content, "Unbound must listen on 192.168.4.1.")
        self.assertIn("port: 53", content, "Unbound must bind to port 53 natively.")
        self.assertIn("tls-cert-bundle", content, "TLS bundle required for DoT.")


if __name__ == "__main__":
    unittest.main()
