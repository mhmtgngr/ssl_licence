"""Tests for the alert engine."""

import unittest
from datetime import datetime, timedelta

from tracker.product import Product, ProductCategory
from tracker.registry import ProductRegistry
from tracker.alert_engine import (
    AlertEngine,
    AlertLevel,
    AlertType,
    AlertThreshold,
)


class TestAlertEngine(unittest.TestCase):
    """Test AlertEngine alert generation."""

    def setUp(self):
        self.registry = ProductRegistry("data/test_registry.json")
        # Clear any existing data
        for p in self.registry.list_all():
            self.registry.remove(p.product_id)

    def tearDown(self):
        import os
        try:
            os.remove("data/test_registry.json")
        except FileNotFoundError:
            pass

    def _add_product(self, days_to_expiry=None, days_to_support_end=None, **kw):
        now = datetime.utcnow()
        defaults = dict(
            name="Test Product",
            vendor="TestVendor",
            version="1.0",
            category=ProductCategory.SOFTWARE_LICENCE,
        )
        if days_to_expiry is not None:
            defaults["licence_expiry"] = now + timedelta(days=days_to_expiry)
        if days_to_support_end is not None:
            defaults["mainstream_support_end"] = now + timedelta(days=days_to_support_end)
        defaults.update(kw)
        p = Product(**defaults)
        self.registry.add(p)
        return p

    def test_no_alerts_for_distant_expiry(self):
        self._add_product(days_to_expiry=365)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        self.assertEqual(len(alerts), 0)

    def test_critical_alert_one_week(self):
        self._add_product(days_to_expiry=5)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        self.assertTrue(any(a.alert_level == AlertLevel.CRITICAL for a in alerts))

    def test_high_alert_one_month(self):
        self._add_product(days_to_expiry=20)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        levels = {a.alert_level for a in alerts}
        self.assertIn(AlertLevel.HIGH, levels)

    def test_medium_alert_three_months(self):
        self._add_product(days_to_expiry=60)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        levels = {a.alert_level for a in alerts}
        self.assertIn(AlertLevel.MEDIUM, levels)

    def test_expired_alert(self):
        self._add_product(days_to_expiry=-10)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        self.assertTrue(any(a.alert_level == AlertLevel.EXPIRED for a in alerts))

    def test_support_end_alert(self):
        self._add_product(days_to_support_end=15)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        types = {a.alert_type for a in alerts}
        self.assertIn(AlertType.MAINSTREAM_SUPPORT_END, types)

    def test_custom_thresholds(self):
        self._add_product(days_to_expiry=350)
        custom = [
            AlertThreshold(days=365, level=AlertLevel.LOW, label="1 year"),
        ]
        engine = AlertEngine(self.registry, thresholds=custom)
        alerts = engine.evaluate_all()
        self.assertTrue(any(a.alert_level == AlertLevel.LOW for a in alerts))

    def test_filter_by_level(self):
        self._add_product(days_to_expiry=5, name="Critical Product")
        self._add_product(days_to_expiry=60, name="Medium Product")
        engine = AlertEngine(self.registry)
        engine.evaluate_all()
        critical = engine.get_alerts(level=AlertLevel.CRITICAL)
        self.assertTrue(all(a.alert_level == AlertLevel.CRITICAL for a in critical))

    def test_inactive_products_skipped(self):
        p = self._add_product(days_to_expiry=3)
        self.registry.update(p.product_id, is_active=False)
        engine = AlertEngine(self.registry)
        alerts = engine.evaluate_all()
        self.assertEqual(len(alerts), 0)

    def test_dashboard_summary(self):
        self._add_product(days_to_expiry=5)
        self._add_product(days_to_expiry=-10)
        engine = AlertEngine(self.registry)
        summary = engine.get_dashboard_summary()
        self.assertIn("total_alerts", summary)
        self.assertIn("by_level", summary)
        self.assertGreater(summary["total_alerts"], 0)


if __name__ == "__main__":
    unittest.main()
