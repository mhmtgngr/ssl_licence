"""OCSP revocation status checking via openssl subprocess."""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class OCSPStatus:
    """Possible OCSP response statuses."""

    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class OCSPResult:
    """Result of an OCSP revocation check."""

    domain: str
    status: str
    responder_url: str = ""
    error: str = ""
    revocation_time: str = ""
    revocation_reason: str = ""


class OCSPChecker:
    """Check certificate revocation status via OCSP using openssl."""

    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 10

    def check(self, domain: str, port: int = DEFAULT_PORT) -> OCSPResult:
        """Check OCSP status for a domain's certificate.

        Steps:
        1. Fetch the certificate and issuer via openssl s_client
        2. Extract OCSP responder URL from AIA extension
        3. Query the OCSP responder
        4. Parse the response
        """
        try:
            cert_pem, issuer_pem = self._fetch_certs(domain, port)
        except (subprocess.CalledProcessError, OSError, ValueError) as exc:
            return OCSPResult(
                domain=domain,
                status=OCSPStatus.ERROR,
                error=f"Failed to fetch certificate: {exc}",
            )

        # Extract OCSP responder URL
        ocsp_url = self._extract_ocsp_url(cert_pem)
        if not ocsp_url:
            return OCSPResult(
                domain=domain,
                status=OCSPStatus.ERROR,
                error="No OCSP responder URL found in certificate",
            )

        # Query OCSP responder
        try:
            return self._query_ocsp(domain, cert_pem, issuer_pem, ocsp_url)
        except (subprocess.CalledProcessError, OSError) as exc:
            return OCSPResult(
                domain=domain,
                status=OCSPStatus.ERROR,
                responder_url=ocsp_url,
                error=f"OCSP query failed: {exc}",
            )

    def _fetch_certs(self, domain: str, port: int) -> tuple[str, str]:
        """Fetch the server certificate and issuer certificate."""
        result = subprocess.run(
            [
                "openssl", "s_client",
                "-connect", f"{domain}:{port}",
                "-servername", domain,
                "-showcerts",
            ],
            input=b"",
            capture_output=True,
            timeout=self.DEFAULT_TIMEOUT,
        )
        output = result.stdout.decode("utf-8", errors="replace")

        # Extract PEM certificates from output
        certs = re.findall(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            output,
            re.DOTALL,
        )
        if len(certs) < 1:
            raise ValueError("No certificates found in server response")

        cert_pem = certs[0]
        issuer_pem = certs[1] if len(certs) > 1 else certs[0]
        return cert_pem, issuer_pem

    def _extract_ocsp_url(self, cert_pem: str) -> str:
        """Extract the OCSP responder URL from a certificate's AIA extension."""
        try:
            result = subprocess.run(
                ["openssl", "x509", "-noout", "-ocsp_uri"],
                input=cert_pem.encode(),
                capture_output=True,
                timeout=self.DEFAULT_TIMEOUT,
            )
            url = result.stdout.decode().strip()
            return url if url.startswith("http") else ""
        except (subprocess.CalledProcessError, OSError):
            return ""

    def _query_ocsp(
        self, domain: str, cert_pem: str, issuer_pem: str, ocsp_url: str
    ) -> OCSPResult:
        """Query the OCSP responder and parse the result."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as cert_file, tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as issuer_file:
            cert_file.write(cert_pem)
            cert_file.flush()
            issuer_file.write(issuer_pem)
            issuer_file.flush()

            try:
                result = subprocess.run(
                    [
                        "openssl", "ocsp",
                        "-issuer", issuer_file.name,
                        "-cert", cert_file.name,
                        "-url", ocsp_url,
                        "-resp_text",
                    ],
                    capture_output=True,
                    timeout=self.DEFAULT_TIMEOUT,
                )
                output = result.stdout.decode("utf-8", errors="replace")
                return self._parse_ocsp_response(domain, output, ocsp_url)
            finally:
                Path(cert_file.name).unlink(missing_ok=True)
                Path(issuer_file.name).unlink(missing_ok=True)

    def _parse_ocsp_response(
        self, domain: str, output: str, ocsp_url: str
    ) -> OCSPResult:
        """Parse openssl ocsp output to determine status."""
        output_lower = output.lower()

        if ": good" in output_lower:
            return OCSPResult(
                domain=domain,
                status=OCSPStatus.GOOD,
                responder_url=ocsp_url,
            )
        elif ": revoked" in output_lower:
            # Try to extract revocation details
            rev_time = ""
            rev_reason = ""
            time_match = re.search(r"Revocation Time:\s*(.+)", output)
            if time_match:
                rev_time = time_match.group(1).strip()
            reason_match = re.search(r"Reason:\s*(.+)", output)
            if reason_match:
                rev_reason = reason_match.group(1).strip()

            return OCSPResult(
                domain=domain,
                status=OCSPStatus.REVOKED,
                responder_url=ocsp_url,
                revocation_time=rev_time,
                revocation_reason=rev_reason,
            )
        else:
            return OCSPResult(
                domain=domain,
                status=OCSPStatus.UNKNOWN,
                responder_url=ocsp_url,
                error=output[:200] if output else "Empty OCSP response",
            )
