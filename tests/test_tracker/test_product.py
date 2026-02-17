"""Tests for the Product data model."""

import unittest
from datetime import datetime, timedelta, timezone

from tracker.product import (
    Product,
    ProductCategory,
    SupportStatus,
    LicenceType,
)


class TestProduct(unittest.TestCase):
    """Test Product dataclass and its methods."""

    def _make_product(self, **overrides):
        defaults = dict(
            name="Windows Server",
            vendor="Microsoft",
            version="2022",
            category=ProductCategory.MICROSOFT,
        )
        defaults.update(overrides)
        return Product(**defaults)

    def test_basic_creation(self):
        p = self._make_product()
        self.assertEqual(p.name, "Windows Server")
        self.assertEqual(p.vendor, "Microsoft")
        self.assertTrue(p.is_active)

    def test_support_status_active(self):
        p = self._make_product(
            mainstream_support_end=datetime.now(timezone.utc) + timedelta(days=365),
        )
        self.assertEqual(p.support_status(), SupportStatus.ACTIVE)

    def test_support_status_extended(self):
        p = self._make_product(
            mainstream_support_end=datetime.now(timezone.utc) - timedelta(days=30),
            extended_support_end=datetime.now(timezone.utc) + timedelta(days=365),
        )
        self.assertEqual(p.support_status(), SupportStatus.EXTENDED)

    def test_support_status_end_of_support(self):
        p = self._make_product(
            mainstream_support_end=datetime.now(timezone.utc) - timedelta(days=30),
            extended_support_end=datetime.now(timezone.utc) - timedelta(days=1),
        )
        self.assertEqual(p.support_status(), SupportStatus.END_OF_SUPPORT)

    def test_support_status_end_of_life(self):
        p = self._make_product(
            end_of_life=datetime.now(timezone.utc) - timedelta(days=100),
        )
        self.assertEqual(p.support_status(), SupportStatus.END_OF_LIFE)

    def test_days_until_licence_expiry(self):
        p = self._make_product(
            licence_expiry=datetime.now(timezone.utc) + timedelta(days=30),
        )
        days = p.days_until_licence_expiry()
        self.assertIsNotNone(days)
        self.assertAlmostEqual(days, 30, delta=1)

    def test_days_until_licence_expiry_none(self):
        p = self._make_product()
        self.assertIsNone(p.days_until_licence_expiry())

    def test_is_licence_expired(self):
        p = self._make_product(
            licence_expiry=datetime.now(timezone.utc) - timedelta(days=5),
        )
        self.assertTrue(p.is_licence_expired())

    def test_is_licence_not_expired(self):
        p = self._make_product(
            licence_expiry=datetime.now(timezone.utc) + timedelta(days=100),
        )
        self.assertFalse(p.is_licence_expired())

    def test_serialization_roundtrip(self):
        p = self._make_product(
            licence_expiry=datetime.now(timezone.utc) + timedelta(days=90),
            mainstream_support_end=datetime.now(timezone.utc) + timedelta(days=365),
            annual_cost=5000.0,
            tags=["critical", "production"],
        )
        data = p.to_dict()
        restored = Product.from_dict(data)
        self.assertEqual(restored.name, p.name)
        self.assertEqual(restored.vendor, p.vendor)
        self.assertEqual(restored.annual_cost, 5000.0)
        self.assertEqual(restored.tags, ["critical", "production"])


class TestProductCategory(unittest.TestCase):
    def test_all_categories(self):
        categories = list(ProductCategory)
        self.assertGreater(len(categories), 10)
        self.assertIn(ProductCategory.MICROSOFT, categories)
        self.assertIn(ProductCategory.LOAD_BALANCER, categories)
        self.assertIn(ProductCategory.CLOUD_PLATFORM, categories)


if __name__ == "__main__":
    unittest.main()
