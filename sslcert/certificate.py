"""SSL Certificate generation and management."""

import datetime
import os
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class CertificateInfo:
    """Holds SSL certificate metadata."""

    common_name: str
    organization: str
    country: str = "US"
    state: str = ""
    locality: str = ""
    org_unit: str = ""
    email: str = ""
    san_domains: list[str] = field(default_factory=list)
    valid_days: int = 365


class CertificateManager:
    """Manages SSL certificate lifecycle: creation, renewal, and storage."""

    def __init__(self, base_dir: str = "ssl"):
        self.base_dir = Path(base_dir)
        self.certs_dir = self.base_dir / "certs"
        self.keys_dir = self.base_dir / "keys"
        self.csr_dir = self.base_dir / "csr"
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Create required directories if they don't exist."""
        for d in (self.certs_dir, self.keys_dir, self.csr_dir):
            d.mkdir(parents=True, exist_ok=True)

    def generate_private_key(
        self, name: str, key_size: int = 2048
    ) -> Path:
        """Generate an RSA private key.

        Args:
            name: Base name for the key file.
            key_size: RSA key size in bits (default 2048).

        Returns:
            Path to the generated key file.
        """
        key_path = self.keys_dir / f"{name}.key"
        subprocess.run(
            [
                "openssl", "genrsa",
                "-out", str(key_path),
                str(key_size),
            ],
            check=True,
            capture_output=True,
        )
        os.chmod(key_path, 0o600)
        return key_path

    def generate_csr(
        self, name: str, info: CertificateInfo
    ) -> Path:
        """Generate a Certificate Signing Request.

        Args:
            name: Base name for the CSR file.
            info: Certificate metadata.

        Returns:
            Path to the generated CSR file.
        """
        key_path = self.keys_dir / f"{name}.key"
        csr_path = self.csr_dir / f"{name}.csr"

        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found: {key_path}")

        subject = self._build_subject(info)
        cmd = [
            "openssl", "req", "-new",
            "-key", str(key_path),
            "-out", str(csr_path),
            "-subj", subject,
        ]

        if info.san_domains:
            san_ext = self._build_san_config(info.san_domains)
            config_path = self.csr_dir / f"{name}_san.cnf"
            config_path.write_text(san_ext)
            cmd.extend(["-config", str(config_path)])

        subprocess.run(cmd, check=True, capture_output=True)
        return csr_path

    def generate_self_signed(
        self, name: str, info: CertificateInfo
    ) -> Path:
        """Generate a self-signed SSL certificate.

        Args:
            name: Base name for the certificate file.
            info: Certificate metadata.

        Returns:
            Path to the generated certificate file.
        """
        key_path = self.generate_private_key(name)
        cert_path = self.certs_dir / f"{name}.crt"
        subject = self._build_subject(info)

        subprocess.run(
            [
                "openssl", "req", "-x509", "-new",
                "-key", str(key_path),
                "-out", str(cert_path),
                "-days", str(info.valid_days),
                "-subj", subject,
            ],
            check=True,
            capture_output=True,
        )
        return cert_path

    def get_certificate_expiry(self, cert_path: str) -> Optional[datetime.datetime]:
        """Read the expiry date from a PEM certificate file.

        Args:
            cert_path: Path to the certificate file.

        Returns:
            Expiry datetime, or None if parsing fails.
        """
        try:
            result = subprocess.run(
                [
                    "openssl", "x509",
                    "-enddate", "-noout",
                    "-in", cert_path,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            date_str = result.stdout.strip().split("=", 1)[1]
            return datetime.datetime.strptime(
                date_str, "%b %d %H:%M:%S %Y %Z"
            )
        except (subprocess.CalledProcessError, ValueError, IndexError):
            return None

    def list_certificates(self) -> list[dict]:
        """List all managed certificates with their expiry info."""
        certs = []
        for cert_file in self.certs_dir.glob("*.crt"):
            expiry = self.get_certificate_expiry(str(cert_file))
            certs.append({
                "name": cert_file.stem,
                "path": str(cert_file),
                "expiry": expiry.isoformat() if expiry else "unknown",
            })
        return certs

    @staticmethod
    def _build_subject(info: CertificateInfo) -> str:
        """Build an OpenSSL subject string from certificate info."""
        parts = [f"/CN={info.common_name}"]
        if info.organization:
            parts.append(f"/O={info.organization}")
        if info.country:
            parts.append(f"/C={info.country}")
        if info.state:
            parts.append(f"/ST={info.state}")
        if info.locality:
            parts.append(f"/L={info.locality}")
        if info.org_unit:
            parts.append(f"/OU={info.org_unit}")
        if info.email:
            parts.append(f"/emailAddress={info.email}")
        return "".join(parts)

    @staticmethod
    def _build_san_config(domains: list[str]) -> str:
        """Build an OpenSSL SAN extension config."""
        san_entries = []
        for i, domain in enumerate(domains, 1):
            if domain.replace(".", "").replace("*", "").isalnum():
                san_entries.append(f"DNS.{i} = {domain}")
            else:
                san_entries.append(f"IP.{i} = {domain}")

        return (
            "[req]\n"
            "distinguished_name = req_distinguished_name\n"
            "req_extensions = v3_req\n"
            "\n"
            "[req_distinguished_name]\n"
            "\n"
            "[v3_req]\n"
            "subjectAltName = @alt_names\n"
            "\n"
            "[alt_names]\n"
            + "\n".join(san_entries)
            + "\n"
        )
