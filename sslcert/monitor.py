"""SSL Certificate expiry monitoring."""

import datetime
import json
import socket
import ssl as _ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Known Certificate Authority mappings: issuer organizationName -> friendly name
_CA_MAP = {
    "let's encrypt": "Let's Encrypt",
    "internet security research group": "Let's Encrypt",
    "isrg": "Let's Encrypt",
    "sectigo": "Sectigo",
    "comodo": "Sectigo",
    "comodo ca": "Sectigo",
    "usertrust": "Sectigo",
    "digicert": "DigiCert",
    "digicert inc": "DigiCert",
    "geotrust": "DigiCert",
    "rapidssl": "DigiCert",
    "thawte": "DigiCert",
    "symantec": "DigiCert",
    "globalsign": "GlobalSign",
    "globalsign nv-sa": "GlobalSign",
    "godaddy": "GoDaddy",
    "godaddy.com, inc.": "GoDaddy",
    "starfield technologies": "GoDaddy",
    "amazon": "Amazon",
    "amazon.com": "Amazon",
    "google trust services": "Google Trust Services",
    "google trust services llc": "Google Trust Services",
    "cloudflare": "Cloudflare",
    "cloudflare, inc.": "Cloudflare",
    "microsoft": "Microsoft",
    "microsoft corporation": "Microsoft",
    "entrust": "Entrust",
    "entrust, inc.": "Entrust",
    "buypass": "Buypass",
    "buypass as": "Buypass",
    "ssl.com": "SSL.com",
    "zerossl": "ZeroSSL",
    "certigna": "Certigna",
    "actalis": "Actalis",
    "e-tugra": "E-Tugra",
    "certum": "Certum",
    "trustwave": "Trustwave",
}


def extract_ca_name(issuer: str) -> str:
    """Extract a clean CA name from raw issuer string.

    Tries to match organizationName or commonName against known CAs.
    Falls back to the raw organizationName or shortened issuer.
    """
    if not issuer:
        return ""

    # Extract organizationName value
    org_name = ""
    cn_name = ""
    for part in issuer.split(","):
        part = part.strip()
        if part.startswith("organizationName="):
            org_name = part.split("=", 1)[1].strip()
        elif part.startswith("commonName="):
            cn_name = part.split("=", 1)[1].strip()

    # Try matching org name against known CAs
    for candidate in (org_name, cn_name):
        if not candidate:
            continue
        candidate_lower = candidate.lower().strip()
        # Direct match
        if candidate_lower in _CA_MAP:
            return _CA_MAP[candidate_lower]
        # Partial match
        for key, friendly in _CA_MAP.items():
            if key in candidate_lower or candidate_lower in key:
                return friendly

    # Fallback: return org name if found, else CN, else raw issuer truncated
    if org_name:
        return org_name
    if cn_name:
        return cn_name
    return issuer[:60] if len(issuer) > 60 else issuer


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
    san_domains: list[str] = None
    certificate_type: str = "unknown"   # single, wildcard, san, unknown
    ca_name: str = ""                   # Friendly CA name

    def __post_init__(self):
        if self.san_domains is None:
            self.san_domains = []
        if not self.ca_name and self.issuer:
            self.ca_name = extract_ca_name(self.issuer)


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
        # Set default socket timeout so getaddrinfo (DNS) also respects it;
        # create_connection's timeout only covers the TCP connect phase.
        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(timeout)
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
        except (socket.error, _ssl.SSLError, OSError, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(prev_timeout)

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
                "san_domains": s.san_domains,
                "certificate_type": s.certificate_type,
                "ca_name": s.ca_name,
            })
        Path(output_path).write_text(json.dumps(data, indent=2))

    @staticmethod
    def _classify_cert_type(san_domains: list[str]) -> str:
        """Classify certificate type based on SAN entries."""
        if not san_domains:
            return "single"
        has_wildcard = any(d.startswith("*.") for d in san_domains)
        if has_wildcard:
            return "wildcard"
        if len(san_domains) > 1:
            return "san"
        return "single"

    @staticmethod
    def _parse_peer_cert(domain: str, cert: dict) -> CertStatus:
        """Parse a peer certificate dict from ssl.getpeercert()."""
        not_before = datetime.datetime.strptime(
            cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
        not_after = datetime.datetime.strptime(
            cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
        ).replace(tzinfo=datetime.timezone.utc)
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

        # Extract SAN domains
        san_domains = []
        for san_type, san_value in cert.get("subjectAltName", ()):
            if san_type == "DNS":
                san_domains.append(san_value)

        cert_type = CertificateMonitor._classify_cert_type(san_domains)

        issuer_str = ", ".join(issuer_parts)
        return CertStatus(
            domain=domain,
            issuer=issuer_str,
            subject=", ".join(subject_parts),
            not_before=not_before,
            not_after=not_after,
            days_remaining=days_remaining,
            is_expired=days_remaining < 0,
            serial_number=cert.get("serialNumber", ""),
            san_domains=san_domains,
            certificate_type=cert_type,
            ca_name=extract_ca_name(issuer_str),
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
