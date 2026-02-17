"""Tests for licence key validation."""

import unittest
from licence.generator import LicenceGenerator
from licence.validator import LicenceValidator


class TestLicenceValidator(unittest.TestCase):
    """Test LicenceValidator methods."""

    def setUp(self):
        self.secret = "test-secret-key"
        self.generator = LicenceGenerator(self.secret)
        self.validator = LicenceValidator(self.secret)

    def test_valid_key(self):
        licence = self.generator.generate(
            licence_type="standard",
            issued_to="Test User",
        )
        result = self.validator.validate(licence.key)
        self.assertTrue(result.is_valid)
        self.assertEqual(result.licence_type, "standard")

    def test_invalid_format(self):
        result = self.validator.validate("invalid-key")
        self.assertFalse(result.is_valid)
        self.assertIn("format", result.error.lower())

    def test_tampered_signature(self):
        licence = self.generator.generate(
            licence_type="standard",
            issued_to="Test",
        )
        # Tamper with the signature portion
        parts = licence.key.rsplit("-", 1)
        tampered = f"{parts[0]}-{'A' * 8}"
        result = self.validator.validate(tampered)
        self.assertFalse(result.is_valid)

    def test_wrong_secret(self):
        licence = self.generator.generate(
            licence_type="standard",
            issued_to="Test",
        )
        wrong_validator = LicenceValidator("wrong-secret")
        result = wrong_validator.validate(licence.key)
        self.assertFalse(result.is_valid)

    def test_format_check(self):
        licence = self.generator.generate(
            licence_type="trial",
            issued_to="Test",
        )
        self.assertTrue(self.validator.is_key_format_valid(licence.key))
        self.assertFalse(self.validator.is_key_format_valid("not-a-key"))


if __name__ == "__main__":
    unittest.main()
