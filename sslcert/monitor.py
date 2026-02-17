"""SSL Certificate expiry monitoring."""

import datetime
import json
import socket
import ssl as _ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class CertStatus:
    """Status of a monitored certificate."""

    domain: str
    issuer: str
    subject: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    days_remaining: int
    is_expired: bool
    serial_number: str


class CertificateMonitor:
    """Monitor SSL certificates for expiry on remote hosts or local files."""

    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 10

    def check_remote(
        self, domain: str, port: int = DEFAULT_PORT, timeout: int = DEFAULT_TIMEOUT
    ) -> Optional[CertStatus]:
        """Check SSL certificate status for a remote host.

        Args:
            domain: Hostname to check.
            port: TLS port (default 443).
            timeout: Connection timeout in seconds.

        Returns:
            CertStatus with certificate details, or None on failure.
        """
        context = _ssl.create_default_context()
        try:
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
        except (socket.error, _ssl.SSLError, OSError):
            return None

        return self._parse_peer_cert(domain, cert)

    def check_local(self, cert_path: str) -> Optional[CertStatus]:
        """Check SSL certificate status from a local PEM file.

        Args:
            cert_path: Path to a PEM-encoded certificate.

        Returns:
            CertStatus or None if the file cannot be parsed.
        """
        path = Path(cert_path)
        if not path.exists():
            return None

        try:
            cert_pem = path.read_text()
            cert = _ssl.PEM_cert_to_DER_cert(cert_pem)
            # For full parsing we'd need cryptography lib; basic check via openssl
            import subprocess

            result = subprocess.run(
                [
                    "openssl", "x509",
                    "-in", str(path),
                    "-noout", "-subject", "-issuer",
                    "-startdate", "-enddate", "-serial",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
            return self._parse_openssl_output(path.stem, result.stdout)
        except Exception:
            return None

    def check_multiple(self, domains: list[str]) -> list[CertStatus]:
        """Check multiple domains and return their certificate statuses."""
        results = []
        for domain in domains:
            status = self.check_remote(domain)
            if status:
                results.append(status)
        return results

    def get_expiring_soon(
        self, domains: list[str], days_threshold: int = 30
    ) -> list[CertStatus]:
        """Return certificates expiring within the given threshold."""
        statuses = self.check_multiple(domains)
        return [s for s in statuses if s.days_remaining <= days_threshold]

    def export_report(self, statuses: list[CertStatus], output_path: str) -> None:
        """Export certificate statuses to a JSON report file."""
        data = []
        for s in statuses:
            data.append({
                "domain": s.domain,
                "issuer": s.issuer,
                "subject": s.subject,
                "not_before": s.not_before.isoformat(),
                "not_after": s.not_after.isoformat(),
                "days_remaining": s.days_remaining,
                "is_expired": s.is_expired,
                "serial_number": s.serial_number,
            })
        Path(output_path).write_text(json.dumps(data, indent=2))

    @staticmethod
    def _parse_peer_cert(domain: str, cert: dict) -> CertStatus:
        """Parse a peer certificate dict from ssl.getpeercert()."""
        not_before = datetime.datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        )
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        )
        now = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (not_after - now).days

        subject_parts = []
        for rdn in cert.get("subject", ()):
            for attr_name, attr_value in rdn:
                subject_parts.append(f"{attr_name}={attr_value}")

        issuer_parts = []
        for rdn in cert.get("issuer", ()):
            for attr_name, attr_value in rdn:
                issuer_parts.append(f"{attr_name}={attr_value}")

        return CertStatus(
            domain=domain,
            issuer=", ".join(issuer_parts),
            subject=", ".join(subject_parts),
            not_before=not_before,
            not_after=not_after,
            days_remaining=days_remaining,
            is_expired=days_remaining < 0,
            serial_number=cert.get("serialNumber", ""),
        )

    @staticmethod
    def _parse_openssl_output(name: str, output: str) -> Optional[CertStatus]:
        """Parse openssl x509 text output into a CertStatus."""
        fields = {}
        for line in output.strip().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key.strip().lower()] = value.strip()

        try:
            not_before = datetime.datetime.strptime(
                fields.get("notbefore", ""), "%b %d %H:%M:%S %Y %Z"
            )
            not_after = datetime.datetime.strptime(
                fields.get("notafter", ""), "%b %d %H:%M:%S %Y %Z"
            )
        except ValueError:
            return None

        now = datetime.datetime.now(datetime.timezone.utc)
        days_remaining = (not_after - now).days

        return CertStatus(
            domain=name,
            issuer=fields.get("issuer", ""),
            subject=fields.get("subject", ""),
            not_before=not_before,
            not_after=not_after,
            days_remaining=days_remaining,
            is_expired=days_remaining < 0,
            serial_number=fields.get("serial", ""),
        )
