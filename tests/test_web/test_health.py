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
        self.assertEqual(data["status"], "healthy")
        self.assertIn("version", data)

    def test_health_has_version(self):
        response = self.client.get("/health")
        data = response.get_json()
        self.assertEqual(data["version"], "0.1.0")


if __name__ == "__main__":
    unittest.main()
