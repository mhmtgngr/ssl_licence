"""Tests for the /health endpoint."""

import unittest

from web import create_app


class TestHealthEndpoint(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_health_returns_200(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_health_returns_json(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIn(data["status"], ("healthy", "degraded"))
        self.assertIn("version", data)

    def test_health_has_version(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertEqual(data["version"], "0.1.0")

    def test_health_has_timestamp(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIn("timestamp", data)

    def test_health_has_monitor_interval(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIn("monitor_interval_hours", data)
        self.assertIsInstance(data["monitor_interval_hours"], int)

    def test_health_has_scheduler_info(self):
        response = self.client.get("/health")
        data = response.get_json()
        # scheduler key should exist (may be None if not running in test mode)
        self.assertIn("scheduler", data)

    def test_health_has_domains_info(self):
        response = self.client.get("/health")
        data = response.get_json()
        # domains key should exist
        self.assertIn("domains", data)


if __name__ == "__main__":
    unittest.main()
