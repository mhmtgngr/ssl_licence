"""Tests for the AI analyzer."""

import os
import unittest
from datetime import datetime, timedelta

from tracker.product import Product, ProductCategory, SupportStatus
from tracker.registry import ProductRegistry
from tracker.ai.analyzer import LicenceAnalyzer


class TestLicenceAnalyzer(unittest.TestCase):

    def setUp(self):
        self.path = "data/test_analyzer.json"
        self.registry = ProductRegistry(self.path)
        for p in self.registry.list_all():
            self.registry.remove(p.product_id)

    def tearDown(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass

    def test_expired_product_gets_critical_recommendation(self):
        self.registry.add(Product(
            name="Old Server", vendor="Microsoft", version="2012",
            category=ProductCategory.MICROSOFT,
            licence_expiry=datetime.utcnow() - timedelta(days=30),
        ))
        analyzer = LicenceAnalyzer(self.registry)
        recs = analyzer.get_recommendations()
        self.assertTrue(any(r.priority == "critical" for r in recs))

    def test_eol_product_gets_migrate_recommendation(self):
        self.registry.add(Product(
            name="Legacy App", vendor="SomeVendor", version="1.0",
            category=ProductCategory.SOFTWARE_LICENCE,
            end_of_life=datetime.utcnow() - timedelta(days=100),
        ))
        analyzer = LicenceAnalyzer(self.registry)
        recs = analyzer.get_recommendations()
        self.assertTrue(any(r.category == "migrate" for r in recs))

    def test_risk_assessment_scoring(self):
        self.registry.add(Product(
            name="Critical Product", vendor="V", version="1",
            category=ProductCategory.SOFTWARE_LICENCE,
            licence_expiry=datetime.utcnow() - timedelta(days=10),
            end_of_life=datetime.utcnow() - timedelta(days=5),
            environment="production",
        ))
        analyzer = LicenceAnalyzer(self.registry)
        risks = analyzer.risk_assessment()
        self.assertGreater(risks[0].risk_score, 5.0)

    def test_upgrade_plan(self):
        self.registry.add(Product(
            name="Windows Server", vendor="Microsoft", version="2012 R2",
            category=ProductCategory.MICROSOFT,
            extended_support_end=datetime.utcnow() - timedelta(days=100),
        ))
        analyzer = LicenceAnalyzer(self.registry)
        plans = analyzer.upgrade_plan()
        self.assertGreater(len(plans), 0)

    def test_cost_optimization_detects_expired(self):
        self.registry.add(Product(
            name="Expensive Expired", vendor="V", version="1",
            category=ProductCategory.SOFTWARE_LICENCE,
            licence_expiry=datetime.utcnow() - timedelta(days=30),
            annual_cost=50000,
        ))
        analyzer = LicenceAnalyzer(self.registry)
        recs = analyzer.cost_optimization()
        self.assertTrue(any("expired" in r.title.lower() for r in recs))

    def test_full_report_structure(self):
        self.registry.add(Product(
            name="Test", vendor="V", version="1",
            category=ProductCategory.SOFTWARE_LICENCE,
            licence_expiry=datetime.utcnow() + timedelta(days=10),
        ))
        analyzer = LicenceAnalyzer(self.registry)
        report = analyzer.generate_full_report()
        self.assertIn("summary", report)
        self.assertIn("recommendations", report)
        self.assertIn("risk_assessment", report)
        self.assertIn("cost_optimizations", report)

    def test_inactive_products_skipped(self):
        p = Product(
            name="Inactive", vendor="V", version="1",
            category=ProductCategory.SOFTWARE_LICENCE,
            licence_expiry=datetime.utcnow() - timedelta(days=30),
            is_active=False,
        )
        self.registry.add(p)
        analyzer = LicenceAnalyzer(self.registry)
        recs = analyzer.get_recommendations()
        self.assertEqual(len(recs), 0)


if __name__ == "__main__":
    unittest.main()
