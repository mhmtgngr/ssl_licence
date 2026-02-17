"""Tests for CSRF protection."""

import unittest

from web import create_app


class TestCSRFProtection(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.app.config["WTF_CSRF_ENABLED"] = True
        self.client = self.app.test_client()

    def test_post_without_csrf_returns_400(self):
        """POST to a form endpoint without CSRF token should fail."""
        response = self.client.post("/certificates/history/clear")
        self.assertEqual(response.status_code, 400)

    def test_get_requests_unaffected(self):
        """GET requests should not require CSRF."""
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)

    def test_api_exempt_from_csrf(self):
        """API endpoints should be exempt from CSRF."""
        response = self.client.get("/api/v1/products")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
