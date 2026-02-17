"""Let's Encrypt certificate provisioning via certbot CLI."""

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class AcmeResult:
    """Result of a certbot operation."""

    success: bool
    domain: str
    cert_path: str = ""
    key_path: str = ""
    expiry: Optional[datetime] = None
    message: str = ""
    error: str = ""


class AcmeService:
    """Wraps certbot CLI for Let's Encrypt certificate management."""

    def __init__(self, letsencrypt_dir: str, email: str = "", staging: bool = False):
        self.base_dir = Path(letsencrypt_dir)
        self.config_dir = self.base_dir / "config"
        self.work_dir = self.base_dir / "work"
        self.logs_dir = self.base_dir / "logs"
        self.email = email
        self.staging = staging
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Create required directories."""
        for d in (self.config_dir, self.work_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)

    def issue_certificate(self, domain: str, challenge_type: str = "http") -> AcmeResult:
        """Issue a new Let's Encrypt certificate.

        Args:
            domain: The domain to issue a certificate for.
            challenge_type: "http" for standalone HTTP-01, "dns" for DNS-01 manual.
        """
        cmd = [
            "certbot", "certonly",
            "--non-interactive",
            "--agree-tos",
            "--config-dir", str(self.config_dir),
            "--work-dir", str(self.work_dir),
            "--logs-dir", str(self.logs_dir),
        ]

        if self.email:
            cmd.extend(["--email", self.email])
        else:
            cmd.append("--register-unsafely-without-email")

        if self.staging:
            cmd.append("--staging")

        if challenge_type == "dns":
            cmd.extend(["--preferred-challenges", "dns", "--manual"])
        else:
            cmd.append("--standalone")

        cmd.extend(["-d", domain])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                cert_path, key_path = self._find_cert_paths(domain)
                return AcmeResult(
                    success=True, domain=domain,
                    cert_path=cert_path, key_path=key_path,
                    message=f"Certificate issued for {domain}",
                )
            else:
                return AcmeResult(
                    success=False, domain=domain,
                    error=result.stderr.strip() or result.stdout.strip(),
                    message=f"certbot failed for {domain}",
                )
        except subprocess.TimeoutExpired:
            return AcmeResult(
                success=False, domain=domain,
                error="certbot timed out", message="Timeout",
            )
        except FileNotFoundError:
            return AcmeResult(
                success=False, domain=domain,
                error="certbot not found — install with: apt-get install certbot",
                message="certbot is not installed",
            )

    def renew_certificate(self, domain: str) -> AcmeResult:
        """Renew an existing Let's Encrypt certificate."""
        cmd = [
            "certbot", "renew",
            "--non-interactive",
            "--config-dir", str(self.config_dir),
            "--work-dir", str(self.work_dir),
            "--logs-dir", str(self.logs_dir),
            "--cert-name", domain,
        ]

        if self.staging:
            cmd.append("--staging")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                cert_path, key_path = self._find_cert_paths(domain)
                return AcmeResult(
                    success=True, domain=domain,
                    cert_path=cert_path, key_path=key_path,
                    message=f"Certificate renewed for {domain}",
                )
            else:
                return AcmeResult(
                    success=False, domain=domain,
                    error=result.stderr.strip() or result.stdout.strip(),
                    message=f"Renewal failed for {domain}",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return AcmeResult(
                success=False, domain=domain,
                error=str(e), message="Renewal error",
            )

    def revoke_certificate(self, domain: str) -> AcmeResult:
        """Revoke a Let's Encrypt certificate."""
        cert_path, _ = self._find_cert_paths(domain)
        if not cert_path:
            return AcmeResult(
                success=False, domain=domain,
                error="Certificate not found", message="No certificate to revoke",
            )

        cmd = [
            "certbot", "revoke",
            "--non-interactive",
            "--config-dir", str(self.config_dir),
            "--work-dir", str(self.work_dir),
            "--logs-dir", str(self.logs_dir),
            "--cert-path", cert_path,
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            return AcmeResult(
                success=result.returncode == 0,
                domain=domain,
                message="Certificate revoked" if result.returncode == 0 else "Revocation failed",
                error=result.stderr.strip() if result.returncode != 0 else "",
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return AcmeResult(
                success=False, domain=domain,
                error=str(e), message="Revocation error",
            )

    def get_certificate_info(self, domain: str) -> dict:
        """Get info about an existing Let's Encrypt certificate."""
        cert_path, key_path = self._find_cert_paths(domain)
        if not cert_path:
            return {}

        try:
            result = subprocess.run(
                ["openssl", "x509", "-enddate", "-noout", "-in", cert_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                date_str = result.stdout.strip().split("=", 1)[1]
                expiry = datetime.strptime(
                    date_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=timezone.utc)
                return {
                    "cert_path": cert_path,
                    "key_path": key_path,
                    "expiry": expiry,
                }
        except (subprocess.CalledProcessError, ValueError, IndexError):
            pass

        return {"cert_path": cert_path, "key_path": key_path}

    def _find_cert_paths(self, domain: str) -> tuple[str, str]:
        """Locate cert and key files for a domain."""
        live_dir = self.config_dir / "live" / domain
        cert_path = live_dir / "fullchain.pem"
        key_path = live_dir / "privkey.pem"

        if cert_path.exists():
            return str(cert_path), str(key_path) if key_path.exists() else ""
        return "", ""
