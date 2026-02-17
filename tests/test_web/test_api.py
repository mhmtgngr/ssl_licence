"""Tests for the REST API v1 endpoints."""

import json
import unittest

from web import create_app


class TestAPIProducts(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_list_products_returns_json(self):
        response = self.client.get("/api/v1/products")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "application/json")
        self.assertIsInstance(response.get_json(), list)

    def test_get_product_not_found(self):
        response = self.client.get("/api/v1/products/nonexistent")
        self.assertEqual(response.status_code, 404)

    def test_add_product_missing_fields(self):
        response = self.client.post(
            "/api/v1/products",
            data=json.dumps({"name": "Test"}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)
        data = response.get_json()
        self.assertIn("error", data)

    def test_delete_product_not_found(self):
        response = self.client.delete("/api/v1/products/nonexistent")
        self.assertEqual(response.status_code, 404)


class TestAPIDomains(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_list_domains_returns_json(self):
        response = self.client.get("/api/v1/domains")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_get_domain_not_found(self):
        response = self.client.get("/api/v1/domains/nonexistent")
        self.assertEqual(response.status_code, 404)

    def test_add_domain_missing_hostname(self):
        response = self.client.post(
            "/api/v1/domains",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_delete_domain_not_found(self):
        response = self.client.delete("/api/v1/domains/nonexistent")
        self.assertEqual(response.status_code, 404)


class TestAPIAlerts(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_list_alerts_returns_json(self):
        response = self.client.get("/api/v1/alerts")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_alert_summary_returns_json(self):
        response = self.client.get("/api/v1/alerts/summary")
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn("total_alerts", data)

    def test_invalid_level_filter(self):
        response = self.client.get("/api/v1/alerts?level=invalid")
        self.assertEqual(response.status_code, 400)


class TestAPICertificates(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_check_missing_domains(self):
        response = self.client.post(
            "/api/v1/certificates/check",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_history_returns_json(self):
        response = self.client.get("/api/v1/certificates/history")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    def test_chain_check_missing_domain(self):
        response = self.client.post(
            "/api/v1/certificates/chain-check",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_ocsp_check_missing_domain(self):
        response = self.client.post(
            "/api/v1/certificates/ocsp-check",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


class TestAPILicences(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = False
        self.client = self.app.test_client()

    def test_issue_missing_fields(self):
        response = self.client.post(
            "/api/v1/licences",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_validate_missing_key(self):
        response = self.client.post(
            "/api/v1/licences/validate",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
