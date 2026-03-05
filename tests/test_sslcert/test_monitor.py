"""Tests for the SSL certificate monitor."""

import datetime
import unittest
from unittest.mock import patch, MagicMock

from sslcert.monitor import CertificateMonitor, CertStatus, extract_ca_name


class TestCertificateMonitor(unittest.TestCase):

    def test_default_port_is_443(self):
        self.assertEqual(CertificateMonitor.DEFAULT_PORT, 443)

    def test_check_remote_accepts_custom_port(self):
        monitor = CertificateMonitor()
        # Unreachable host on port 8443 should return None, not raise
        result = monitor.check_remote("nonexistent.invalid.test", port=8443, timeout=2)
        self.assertIsNone(result)

    def test_check_multiple_passes_port(self):
        monitor = CertificateMonitor()
        results = monitor.check_multiple(
            ["nonexistent.invalid.test"], port=8443
        )
        self.assertEqual(results, [])

    def test_classify_cert_type_single(self):
        result = CertificateMonitor._classify_cert_type(["example.com"])
        self.assertEqual(result, "single")

    def test_classify_cert_type_wildcard(self):
        result = CertificateMonitor._classify_cert_type(["*.example.com", "example.com"])
        self.assertEqual(result, "wildcard")

    def test_classify_cert_type_san(self):
        result = CertificateMonitor._classify_cert_type(["a.com", "b.com"])
        self.assertEqual(result, "san")

    def test_classify_cert_type_empty(self):
        result = CertificateMonitor._classify_cert_type([])
        self.assertEqual(result, "single")


class TestExtractCaName(unittest.TestCase):

    def test_known_ca(self):
        self.assertEqual(extract_ca_name("O=Let's Encrypt"), "Let's Encrypt")

    def test_unknown_ca_returns_org(self):
        self.assertEqual(extract_ca_name("O=My Custom CA"), "My Custom CA")

    def test_empty_issuer(self):
        self.assertEqual(extract_ca_name(""), "")


class TestCertStatus(unittest.TestCase):

    def test_post_init_auto_ca_name(self):
        status = CertStatus(
            domain="test.com",
            issuer="O=DigiCert Inc",
            subject="CN=test.com",
            not_before=datetime.datetime.now(datetime.timezone.utc),
            not_after=datetime.datetime.now(datetime.timezone.utc),
            days_remaining=30,
            is_expired=False,
            serial_number="ABC123",
        )
        self.assertEqual(status.ca_name, "DigiCert")

    def test_san_domains_default(self):
        status = CertStatus(
            domain="test.com",
            issuer="",
            subject="",
            not_before=datetime.datetime.now(datetime.timezone.utc),
            not_after=datetime.datetime.now(datetime.timezone.utc),
            days_remaining=30,
            is_expired=False,
            serial_number="",
        )
        self.assertEqual(status.san_domains, [])


if __name__ == "__main__":
    unittest.main()
