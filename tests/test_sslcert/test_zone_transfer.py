"""Tests for DNS zone transfer service."""

import unittest

from sslcert.zone_transfer import ZoneTransferService, ZoneTransferRecord


class TestZoneTransferService(unittest.TestCase):

    def test_transfer_zone_failure_returns_empty(self):
        """On transfer failure, returns empty list gracefully."""
        svc = ZoneTransferService()
        records = svc.transfer_zone("127.0.0.1", "nonexistent.test")
        self.assertEqual(records, [])

    def test_wanted_types(self):
        self.assertEqual(ZoneTransferService.WANTED_TYPES, {"A", "AAAA", "CNAME"})

    def test_record_dataclass(self):
        r = ZoneTransferRecord(
            hostname="www.example.com",
            record_type="A",
            value="1.2.3.4",
            ttl=300,
        )
        self.assertEqual(r.hostname, "www.example.com")
        self.assertEqual(r.record_type, "A")
        self.assertEqual(r.value, "1.2.3.4")
        self.assertEqual(r.ttl, 300)

    def test_record_default_ttl(self):
        r = ZoneTransferRecord(hostname="a.example.com", record_type="CNAME", value="b.example.com")
        self.assertEqual(r.ttl, 3600)


if __name__ == "__main__":
    unittest.main()
