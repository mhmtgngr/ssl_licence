"""Tests for SSL certificate management."""

import unittest
from unittest.mock import patch, MagicMock
from sslcert.certificate import CertificateManager, CertificateInfo


class TestCertificateInfo(unittest.TestCase):
    """Test CertificateInfo dataclass."""

    def test_default_values(self):
        info = CertificateInfo(
            common_name="example.com",
            organization="Test Org",
        )
        self.assertEqual(info.common_name, "example.com")
        self.assertEqual(info.organization, "Test Org")
        self.assertEqual(info.country, "US")
        self.assertEqual(info.valid_days, 365)
        self.assertEqual(info.san_domains, [])

    def test_custom_values(self):
        info = CertificateInfo(
            common_name="test.com",
            organization="My Org",
            country="TR",
            state="Istanbul",
            valid_days=730,
            san_domains=["*.test.com", "api.test.com"],
        )
        self.assertEqual(info.country, "TR")
        self.assertEqual(info.valid_days, 730)
        self.assertEqual(len(info.san_domains), 2)


class TestCertificateManager(unittest.TestCase):
    """Test CertificateManager methods."""

    def test_build_subject_basic(self):
        info = CertificateInfo(
            common_name="example.com",
            organization="Test",
        )
        subject = CertificateManager._build_subject(info)
        self.assertIn("/CN=example.com", subject)
        self.assertIn("/O=Test", subject)

    def test_build_subject_full(self):
        info = CertificateInfo(
            common_name="example.com",
            organization="Test",
            country="US",
            state="CA",
            locality="SF",
            org_unit="Dev",
            email="admin@example.com",
        )
        subject = CertificateManager._build_subject(info)
        self.assertIn("/CN=example.com", subject)
        self.assertIn("/C=US", subject)
        self.assertIn("/ST=CA", subject)
        self.assertIn("/L=SF", subject)

    def test_build_san_config(self):
        domains = ["example.com", "*.example.com"]
        config = CertificateManager._build_san_config(domains)
        self.assertIn("[alt_names]", config)
        self.assertIn("DNS.1 = example.com", config)
        self.assertIn("DNS.2 = *.example.com", config)


if __name__ == "__main__":
    unittest.main()
