"""Tests for the search engine."""

import os
import unittest
from datetime import datetime, timedelta

from tracker.product import Product, ProductCategory
from tracker.registry import ProductRegistry
from tracker.search import SearchEngine


class TestSearchEngine(unittest.TestCase):

    def setUp(self):
        self.path = "data/test_search.json"
        self.registry = ProductRegistry(self.path)
        for p in self.registry.list_all():
            self.registry.remove(p.product_id)

        # Add sample products
        self.registry.add(Product(
            name="Windows Server", vendor="Microsoft", version="2022",
            category=ProductCategory.MICROSOFT,
            tags=["critical", "production"],
        ))
        self.registry.add(Product(
            name="BIG-IP", vendor="F5", version="16.x",
            category=ProductCategory.LOAD_BALANCER,
            tags=["network"],
        ))
        self.registry.add(Product(
            name="SQL Server", vendor="Microsoft", version="2019",
            category=ProductCategory.DATABASE,
        ))
        self.search = SearchEngine(self.registry)

    def tearDown(self):
        try:
            os.remove(self.path)
        except FileNotFoundError:
            pass

    def test_search_by_name(self):
        results = self.search.search("Windows")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].product.name, "Windows Server")

    def test_search_by_vendor(self):
        results = self.search.search("Microsoft")
        self.assertEqual(len(results), 2)

    def test_filter_by_category(self):
        results = self.search.search("", category=ProductCategory.LOAD_BALANCER)
        self.assertEqual(len(results), 1)

    def test_empty_query_returns_all(self):
        results = self.search.search("")
        self.assertEqual(len(results), 3)

    def test_no_results(self):
        results = self.search.search("NonExistentProduct")
        self.assertEqual(len(results), 0)

    def test_find_by_name(self):
        products = self.search.find_by_name("SQL")
        self.assertEqual(len(products), 1)

    def test_cost_report(self):
        report = self.search.cost_report()
        self.assertIn("total_annual_cost", report)
        self.assertEqual(report["product_count"], 3)


if __name__ == "__main__":
    unittest.main()
