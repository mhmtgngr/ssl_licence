"""Tests for Azure DNS service."""

import unittest

from sslcert.azure_dns import AzureDnsService, AzureDnsRecord


class TestAzureDnsService(unittest.TestCase):

    def test_is_configured_no_subscription(self):
        svc = AzureDnsService(subscription_id="", resource_group="")
        self.assertFalse(svc.is_configured())

    def test_extract_resource_group(self):
        rid = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Network/dnszones/example.com"
        self.assertEqual(AzureDnsService._extract_resource_group(rid), "my-rg")

    def test_extract_resource_group_empty(self):
        self.assertEqual(AzureDnsService._extract_resource_group(""), "")

    def test_record_dataclass(self):
        r = AzureDnsRecord(hostname="www.example.com", record_type="A", value="1.2.3.4")
        self.assertEqual(r.hostname, "www.example.com")
        self.assertEqual(r.record_type, "A")
        self.assertEqual(r.value, "1.2.3.4")
        self.assertEqual(r.ttl, 3600)

    def test_record_custom_ttl(self):
        r = AzureDnsRecord(hostname="a.com", record_type="CNAME", value="b.com", ttl=300)
        self.assertEqual(r.ttl, 300)


if __name__ == "__main__":
    unittest.main()
