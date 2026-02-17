"""Tests for the certificate chain validator."""

import unittest

from sslcert.chain_validator import (
    CertificateChainValidator,
    ChainLink,
    ChainValidationResult,
    ChainValidationStatus,
)


class TestChainValidationResult(unittest.TestCase):

    def test_result_dataclass_fields(self):
        result = ChainValidationResult(
            domain="test.com", status="valid", is_valid=True
        )
        self.assertEqual(result.domain, "test.com")
        self.assertTrue(result.is_valid)
        self.assertEqual(result.chain_length, 0)
        self.assertEqual(result.chain, [])

    def test_result_with_chain(self):
        link = ChainLink(
            subject="CN=test.com",
            issuer="CN=CA",
            not_before="Jan 1 00:00:00 2024 GMT",
            not_after="Dec 31 23:59:59 2025 GMT",
        )
        result = ChainValidationResult(
            domain="test.com",
            status=ChainValidationStatus.VALID,
            chain_length=1,
            chain=[link],
            is_valid=True,
        )
        self.assertEqual(len(result.chain), 1)
        self.assertEqual(result.chain[0].subject, "CN=test.com")


class TestChainLink(unittest.TestCase):

    def test_defaults(self):
        link = ChainLink(
            subject="CN=test", issuer="CN=CA",
            not_before="", not_after="",
        )
        self.assertFalse(link.is_ca)
        self.assertEqual(link.serial_number, "")

    def test_ca_flag(self):
        link = ChainLink(
            subject="CN=Root CA", issuer="CN=Root CA",
            not_before="", not_after="", is_ca=True,
        )
        self.assertTrue(link.is_ca)


class TestCertificateChainValidator(unittest.TestCase):

    def test_connection_failed_for_unreachable_host(self):
        validator = CertificateChainValidator()
        result = validator.validate("nonexistent.invalid.test", timeout=2)
        self.assertEqual(result.status, ChainValidationStatus.CONNECTION_FAILED)
        self.assertFalse(result.is_valid)
        self.assertTrue(len(result.error) > 0)

    def test_evaluate_empty_chain(self):
        validator = CertificateChainValidator()
        status = validator._evaluate_chain([])
        self.assertEqual(status, ChainValidationStatus.INCOMPLETE)

    def test_evaluate_self_signed(self):
        validator = CertificateChainValidator()
        link = ChainLink(
            subject="CN=Self", issuer="CN=Self",
            not_before="", not_after="", is_ca=True,
        )
        status = validator._evaluate_chain([link])
        self.assertEqual(status, ChainValidationStatus.SELF_SIGNED)

    def test_format_dn(self):
        dn = (
            (("commonName", "test.com"),),
            (("organizationName", "Test Inc"),),
        )
        result = CertificateChainValidator._format_dn(dn)
        self.assertIn("commonName=test.com", result)
        self.assertIn("organizationName=Test Inc", result)


if __name__ == "__main__":
    unittest.main()
