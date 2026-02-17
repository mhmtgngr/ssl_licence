"""Tests for the OCSP checker."""

import subprocess
import unittest
from unittest.mock import patch

from sslcert.ocsp_checker import OCSPChecker, OCSPResult, OCSPStatus


class TestOCSPResult(unittest.TestCase):

    def test_defaults(self):
        result = OCSPResult(domain="test.com", status=OCSPStatus.GOOD)
        self.assertEqual(result.domain, "test.com")
        self.assertEqual(result.status, "good")
        self.assertEqual(result.responder_url, "")
        self.assertEqual(result.error, "")

    def test_revoked_result(self):
        result = OCSPResult(
            domain="test.com",
            status=OCSPStatus.REVOKED,
            revocation_time="2024-01-01",
            revocation_reason="keyCompromise",
        )
        self.assertEqual(result.status, "revoked")
        self.assertEqual(result.revocation_reason, "keyCompromise")


class TestOCSPChecker(unittest.TestCase):

    @patch("sslcert.ocsp_checker.subprocess.run")
    def test_check_handles_connection_failure(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, "openssl")
        checker = OCSPChecker()
        result = checker.check("test.com")
        self.assertEqual(result.status, OCSPStatus.ERROR)
        self.assertIn("Failed to fetch certificate", result.error)

    def test_parse_good_response(self):
        checker = OCSPChecker()
        output = "cert.pem: good\n  This Update: Jan  1 00:00:00 2024 GMT"
        result = checker._parse_ocsp_response("test.com", output, "http://ocsp.test")
        self.assertEqual(result.status, OCSPStatus.GOOD)
        self.assertEqual(result.responder_url, "http://ocsp.test")

    def test_parse_revoked_response(self):
        checker = OCSPChecker()
        output = (
            "cert.pem: revoked\n"
            "  Revocation Time: Jan 1 00:00:00 2024 GMT\n"
            "  Reason: keyCompromise\n"
        )
        result = checker._parse_ocsp_response("test.com", output, "http://ocsp.test")
        self.assertEqual(result.status, OCSPStatus.REVOKED)
        self.assertIn("keyCompromise", result.revocation_reason)

    def test_parse_unknown_response(self):
        checker = OCSPChecker()
        result = checker._parse_ocsp_response("test.com", "some other output", "http://ocsp.test")
        self.assertEqual(result.status, OCSPStatus.UNKNOWN)

    def test_extract_ocsp_url_empty_on_failure(self):
        checker = OCSPChecker()
        # With an invalid cert PEM, the URL should be empty
        url = checker._extract_ocsp_url("not-a-cert")
        self.assertEqual(url, "")


if __name__ == "__main__":
    unittest.main()
