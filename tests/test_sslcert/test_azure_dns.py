"""Tests for Azure DNS service."""

import unittest
from unittest.mock import patch, MagicMock

from sslcert.azure_dns import AzureDnsService, AzureDnsRecord


class TestAzureDnsService(unittest.TestCase):

    def test_is_configured_no_credentials(self):
        """Returns False when no credentials can be obtained."""
        svc = AzureDnsService(subscription_id="", resource_group="")
        self.assertFalse(svc.is_configured())

    def test_is_configured_with_credentials_no_subscription(self):
        """Returns True with valid credentials even without subscription_id."""
        svc = AzureDnsService(
            tenant_id="t", client_id="c", client_secret="s",
            subscription_id="",
        )
        with patch.object(svc, "_get_credential", return_value=MagicMock()):
            self.assertTrue(svc.is_configured())

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

    def test_list_subscriptions_returns_empty_on_failure(self):
        """list_subscriptions returns [] when credential fails."""
        svc = AzureDnsService(tenant_id="t", client_id="c", client_secret="s")
        with patch.object(svc, "_get_credential", side_effect=Exception("auth fail")):
            self.assertEqual(svc.list_subscriptions(), [])

    def test_find_zone_for_domain_returns_three_tuple(self):
        """find_zone_for_domain returns (zone, rg, subscription_id)."""
        svc = AzureDnsService(subscription_id="sub-123")
        with patch.object(svc, "list_zones", return_value=[
            {"name": "example.com", "resource_group": "rg1",
             "subscription_id": "sub-123", "number_of_record_sets": 5},
        ]):
            zone, rg, sub_id = svc.find_zone_for_domain("www.example.com")
            self.assertEqual(zone, "example.com")
            self.assertEqual(rg, "rg1")
            self.assertEqual(sub_id, "sub-123")

    def test_find_zone_for_domain_not_found(self):
        """find_zone_for_domain returns empty 3-tuple when no match."""
        svc = AzureDnsService(subscription_id="sub-123")
        with patch.object(svc, "list_zones", return_value=[]):
            zone, rg, sub_id = svc.find_zone_for_domain("unknown.com")
            self.assertEqual(zone, "")
            self.assertEqual(rg, "")
            self.assertEqual(sub_id, "")

    def test_list_zones_includes_subscription_id(self):
        """list_zones returns dicts with subscription_id field."""
        svc = AzureDnsService(subscription_id="sub-123",
                              tenant_id="t", client_id="c", client_secret="s")
        mock_zone = MagicMock()
        mock_zone.name = "example.com"
        mock_zone.id = "/subscriptions/sub-123/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com"
        mock_zone.number_of_record_sets = 5

        mock_client = MagicMock()
        mock_client.zones.list.return_value = [mock_zone]

        mock_dns_module = MagicMock()
        mock_dns_module.DnsManagementClient.return_value = mock_client

        with patch.object(svc, "_get_credential", return_value=MagicMock()):
            with patch.dict("sys.modules", {"azure.mgmt.dns": mock_dns_module}):
                zones = svc.list_zones()
                self.assertEqual(len(zones), 1)
                self.assertEqual(zones[0]["subscription_id"], "sub-123")
                self.assertEqual(zones[0]["name"], "example.com")

    def test_list_records_requires_subscription_id(self):
        """list_records returns [] when no subscription_id available."""
        svc = AzureDnsService(subscription_id="",
                              tenant_id="t", client_id="c", client_secret="s")
        with patch.object(svc, "_get_credential", return_value=MagicMock()):
            records = svc.list_records("example.com", "rg1", subscription_id="")
            self.assertEqual(records, [])


if __name__ == "__main__":
    unittest.main()
