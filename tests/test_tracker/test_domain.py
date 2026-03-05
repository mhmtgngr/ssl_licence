"""Tests for the Domain model including ssl_port support."""

import unittest
from datetime import datetime, timezone

from tracker.domain import Domain, DomainType, DomainStatus, CertificateType


class TestDomainSslPort(unittest.TestCase):

    def test_default_ssl_port_is_443(self):
        domain = Domain(hostname="example.com")
        self.assertEqual(domain.ssl_port, 443)

    def test_custom_ssl_port(self):
        domain = Domain(hostname="example.com", ssl_port=8443)
        self.assertEqual(domain.ssl_port, 8443)

    def test_ssl_port_serialization(self):
        domain = Domain(hostname="example.com", ssl_port=993)
        data = domain.to_dict()
        self.assertEqual(data["ssl_port"], 993)

    def test_ssl_port_deserialization(self):
        data = {"hostname": "example.com", "ssl_port": 8443}
        domain = Domain.from_dict(data)
        self.assertEqual(domain.ssl_port, 8443)

    def test_ssl_port_deserialization_default(self):
        data = {"hostname": "example.com"}
        domain = Domain.from_dict(data)
        self.assertEqual(domain.ssl_port, 443)


class TestDomainClassify(unittest.TestCase):

    def test_root_domain(self):
        domain = Domain(hostname="example.com")
        domain.classify()
        self.assertEqual(domain.domain_type, DomainType.ROOT)
        self.assertEqual(domain.parent_domain, "example.com")

    def test_subdomain(self):
        domain = Domain(hostname="sub.example.com")
        domain.classify()
        self.assertEqual(domain.domain_type, DomainType.SUBDOMAIN)
        self.assertEqual(domain.parent_domain, "example.com")

    def test_wildcard(self):
        domain = Domain(hostname="*.example.com")
        domain.classify()
        self.assertEqual(domain.domain_type, DomainType.WILDCARD)
        self.assertEqual(domain.parent_domain, "example.com")

    def test_ccsld(self):
        domain = Domain(hostname="sub.example.com.tr")
        domain.classify()
        self.assertEqual(domain.domain_type, DomainType.SUBDOMAIN)
        self.assertEqual(domain.parent_domain, "example.com.tr")


class TestDomainToFromDict(unittest.TestCase):

    def test_roundtrip(self):
        domain = Domain(
            hostname="test.example.com",
            ssl_port=8443,
            ssl_issuer="O=Test CA",
            notes="Test domain",
        )
        domain.classify()
        data = domain.to_dict()
        restored = Domain.from_dict(data)
        self.assertEqual(restored.hostname, domain.hostname)
        self.assertEqual(restored.ssl_port, 8443)
        self.assertEqual(restored.ssl_issuer, "O=Test CA")
        self.assertEqual(restored.notes, "Test domain")


if __name__ == "__main__":
    unittest.main()
