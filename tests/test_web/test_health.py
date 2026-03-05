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

    def test_health_has_ssl_ports(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertIn("ssl_ports", data)
        self.assertIsInstance(data["ssl_ports"], list)
        # Should contain at least HTTPS (443)
        ports = {p["port"] for p in data["ssl_ports"]}
        self.assertIn(443, ports)
        self.assertIn(8443, ports)
        self.assertIn(993, ports)

    def test_health_ssl_ports_have_description(self):
        response = self.client.get("/health")
        data = response.get_json()
        for entry in data["ssl_ports"]:
            self.assertIn("port", entry)
            self.assertIn("description", entry)
            self.assertIsInstance(entry["port"], int)
            self.assertIsInstance(entry["description"], str)


if __name__ == "__main__":
    unittest.main()
