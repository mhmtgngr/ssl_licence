"""Tests for SSL port configuration."""

import unittest

from config.settings import SSL_PORTS, DEFAULT_SSL_PORT


class TestSSLPorts(unittest.TestCase):

    def test_ssl_ports_contains_443(self):
        self.assertIn(443, SSL_PORTS)
        self.assertEqual(SSL_PORTS[443], "HTTPS")

    def test_ssl_ports_contains_common_ports(self):
        expected = {8443, 465, 993, 995, 636, 853, 990, 6443}
        self.assertTrue(expected.issubset(set(SSL_PORTS.keys())))

    def test_ssl_ports_all_int_keys(self):
        for port in SSL_PORTS:
            self.assertIsInstance(port, int)
            self.assertGreater(port, 0)
            self.assertLessEqual(port, 65535)

    def test_ssl_ports_all_string_values(self):
        for desc in SSL_PORTS.values():
            self.assertIsInstance(desc, str)
            self.assertTrue(len(desc) > 0)

    def test_default_ssl_port(self):
        self.assertEqual(DEFAULT_SSL_PORT, 443)

    def test_ssl_ports_has_email_ports(self):
        self.assertIn(465, SSL_PORTS)  # SMTPS
        self.assertIn(993, SSL_PORTS)  # IMAPS
        self.assertIn(995, SSL_PORTS)  # POP3S

    def test_ssl_ports_has_alt_https(self):
        self.assertIn(8443, SSL_PORTS)

    def test_ssl_ports_has_ldaps(self):
        self.assertIn(636, SSL_PORTS)

    def test_ssl_ports_has_kubernetes(self):
        self.assertIn(6443, SSL_PORTS)


if __name__ == "__main__":
    unittest.main()
