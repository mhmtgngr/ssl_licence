"""Tests for the ProductRegistry."""

import os
import unittest
from datetime import datetime, timedelta

from tracker.product import Product, ProductCategory, SupportStatus
from tracker.registry import ProductRegistry


class TestProductRegistry(unittest.TestCase):

    def setUp(self):
        self.path = "data/test_registry_crud.json"
        self.registry = ProductRegistry(self.path)
        for p in self.registry.list_all():
            self.registry.remove(p.product_id)

    def tearDown(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass

    def _make(self, **kw):
        defaults = dict(
            name="TestApp",
            vendor="Vendor",
            version="1.0",
            category=ProductCategory.SOFTWARE_LICENCE,
        )
        defaults.update(kw)
        return Product(**defaults)

    def test_add_and_get(self):
        p = self._make()
        self.registry.add(p)
        result = self.registry.get(p.product_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "TestApp")

    def test_remove(self):
        p = self._make()
        self.registry.add(p)
        self.assertTrue(self.registry.remove(p.product_id))
        self.assertIsNone(self.registry.get(p.product_id))

    def test_update(self):
        p = self._make()
        self.registry.add(p)
        self.registry.update(p.product_id, name="UpdatedApp")
        result = self.registry.get(p.product_id)
        self.assertEqual(result.name, "UpdatedApp")

    def test_filter_by_category(self):
        self.registry.add(self._make(category=ProductCategory.MICROSOFT))
        self.registry.add(self._make(category=ProductCategory.LOAD_BALANCER))
        ms = self.registry.by_category(ProductCategory.MICROSOFT)
        self.assertEqual(len(ms), 1)

    def test_filter_by_vendor(self):
        self.registry.add(self._make(vendor="Microsoft"))
        self.registry.add(self._make(vendor="Cisco"))
        results = self.registry.by_vendor("Microsoft")
        self.assertEqual(len(results), 1)

    def test_expiring_within_days(self):
        now = datetime.utcnow()
        self.registry.add(self._make(
            licence_expiry=now + timedelta(days=10), name="Soon"
        ))
        self.registry.add(self._make(
            licence_expiry=now + timedelta(days=200), name="Later"
        ))
        soon = self.registry.expiring_within_days(30)
        self.assertEqual(len(soon), 1)
        self.assertEqual(soon[0].name, "Soon")

    def test_persistence(self):
        p = self._make(name="Persisted")
        self.registry.add(p)
        # Load a new registry from same file
        r2 = ProductRegistry(self.path)
        result = r2.get(p.product_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "Persisted")

    def test_summary(self):
        self.registry.add(self._make(annual_cost=1000))
        self.registry.add(self._make(annual_cost=2000))
        s = self.registry.summary()
        self.assertEqual(s["total_products"], 2)
        self.assertEqual(s["total_annual_cost"], 3000)


if __name__ == "__main__":
    unittest.main()
