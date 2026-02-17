"""Tests for licence key generation."""

import unittest
from licence.generator import LicenceGenerator


class TestLicenceGenerator(unittest.TestCase):
    """Test LicenceGenerator methods."""

    def setUp(self):
        self.generator = LicenceGenerator("test-secret-key")

    def test_generate_standard(self):
        licence = self.generator.generate(
            licence_type="standard",
            issued_to="Test User",
            valid_days=365,
        )
        self.assertIsNotNone(licence.key)
        self.assertEqual(licence.licence_type, "standard")
        self.assertEqual(licence.issued_to, "Test User")
        self.assertIsNotNone(licence.expires_at)

    def test_generate_perpetual(self):
        licence = self.generator.generate(
            licence_type="enterprise",
            issued_to="Corp Inc",
        )
        self.assertIsNone(licence.expires_at)

    def test_generate_trial(self):
        licence = self.generator.generate_trial("Trial User", trial_days=14)
        self.assertEqual(licence.licence_type, "trial")
        self.assertEqual(licence.max_users, 1)
        self.assertIn("basic", licence.features)

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            self.generator.generate(
                licence_type="invalid",
                issued_to="Test",
            )

    def test_key_format(self):
        licence = self.generator.generate(
            licence_type="professional",
            issued_to="User",
        )
        parts = licence.key.split("-")
        self.assertEqual(parts[0], "PRO")
        self.assertEqual(len(parts), 4)

    def test_unique_keys(self):
        keys = set()
        for _ in range(100):
            licence = self.generator.generate(
                licence_type="standard",
                issued_to="Test",
            )
            keys.add(licence.key)
        self.assertEqual(len(keys), 100)


if __name__ == "__main__":
    unittest.main()
