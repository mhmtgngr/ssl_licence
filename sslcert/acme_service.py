"""Let's Encrypt certificate provisioning via certbot CLI."""

import logging
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


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

    def __init__(
        self,
        letsencrypt_dir: str,
        email: str = "",
        staging: bool = False,
        azure_dns_service=None,
    ):
        self.base_dir = Path(letsencrypt_dir)
        self.config_dir = self.base_dir / "config"
        self.work_dir = self.base_dir / "work"
        self.logs_dir = self.base_dir / "logs"
        self.email = email
        self.staging = staging
        self.azure_dns = azure_dns_service
        self._ensure_dirs()

    def _ensure_dirs(self) -> None:
        """Create required directories."""
        for d in (self.config_dir, self.work_dir, self.logs_dir):
            d.mkdir(parents=True, exist_ok=True)

    def issue_certificate(self, domain: str, challenge_type: str = "http") -> AcmeResult:
        """Issue a new Let's Encrypt certificate.

        Args:
            domain: The domain to issue a certificate for.
            challenge_type: "http" for standalone HTTP-01,
                            "dns" for DNS-01 manual,
                            "dns-azure" for automated DNS-01 via Azure DNS.
        """
        if challenge_type == "dns-azure":
            return self._issue_via_azure_dns(domain)

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

    def _issue_via_azure_dns(self, domain: str) -> AcmeResult:
        """Issue certificate using automated DNS-01 via Azure DNS.

        Creates the _acme-challenge TXT record in Azure DNS, runs certbot
        with manual hooks that read the token from a temp file, then cleans up.
        """
        if not self.azure_dns:
            return AcmeResult(
                success=False, domain=domain,
                error="Azure DNS service not configured",
                message="Cannot use dns-azure without Azure DNS credentials",
            )

        zone_name, rg, _sub_id = self.azure_dns.find_zone_for_domain(domain)
        if not zone_name:
            return AcmeResult(
                success=False, domain=domain,
                error=f"No Azure DNS zone found for {domain}",
                message="Domain not managed by configured Azure DNS",
            )

        # Determine the relative _acme-challenge record name
        domain_lower = domain.lower().rstrip(".")
        zone_lower = zone_name.lower().rstrip(".")
        if domain_lower == zone_lower:
            record_name = "_acme-challenge"
        else:
            prefix = domain_lower[: -(len(zone_lower) + 1)]  # strip ".zone"
            record_name = f"_acme-challenge.{prefix}"

        # Write hook scripts that certbot will call
        auth_script = self.base_dir / "azure_auth_hook.sh"
        cleanup_script = self.base_dir / "azure_cleanup_hook.sh"
        token_file = self.base_dir / "acme_token.txt"

        auth_script.write_text(
            "#!/bin/bash\n"
            f'echo "$CERTBOT_VALIDATION" > "{token_file}"\n'
        )
        cleanup_script.write_text(
            "#!/bin/bash\n"
            f'rm -f "{token_file}"\n'
        )
        auth_script.chmod(0o755)
        cleanup_script.chmod(0o755)

        try:
            # Step 1: Get the ACME order and token via certbot dry-run approach.
            # We use certbot with manual plugin and our own pre/post hooks.
            # But certbot --manual doesn't work non-interactively with hooks
            # in all versions, so we use a two-phase approach:
            # Phase 1 - use certbot to get the validation token
            # Phase 2 - create the DNS record and let certbot validate

            cmd = [
                "certbot", "certonly",
                "--non-interactive",
                "--agree-tos",
                "--manual",
                "--preferred-challenges", "dns",
                "--manual-auth-hook", str(auth_script),
                "--manual-cleanup-hook", str(cleanup_script),
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

            cmd.extend(["-d", domain])

            # Override the auth hook to create Azure DNS record
            # We wrap certbot: the auth hook writes the token, we intercept
            # by replacing the auth script with one that also creates the DNS record
            azure_auth_content = (
                "#!/bin/bash\n"
                f'echo "$CERTBOT_VALIDATION" > "{token_file}"\n'
                f'python3 -c "\n'
                f"import sys; sys.path.insert(0, '{Path(__file__).resolve().parent.parent}')\n"
                f"from sslcert.azure_dns import AzureDnsService\n"
                f"svc = AzureDnsService(\n"
                f"    subscription_id='{self.azure_dns.subscription_id}',\n"
                f"    resource_group='{self.azure_dns.resource_group}',\n"
                f"    tenant_id='{self.azure_dns.tenant_id}',\n"
                f"    client_id='{self.azure_dns.client_id}',\n"
                f"    client_secret='{self.azure_dns.client_secret}',\n"
                f")\n"
                f"import os\n"
                f"token = os.environ.get('CERTBOT_VALIDATION', '')\n"
                f"svc.create_txt_record('{zone_name}', '{record_name}', token, '{rg}')\n"
                f"import time; time.sleep(30)  # wait for DNS propagation\n"
                '"\n'
            )
            auth_script.write_text(azure_auth_content)

            azure_cleanup_content = (
                "#!/bin/bash\n"
                f'python3 -c "\n'
                f"import sys; sys.path.insert(0, '{Path(__file__).resolve().parent.parent}')\n"
                f"from sslcert.azure_dns import AzureDnsService\n"
                f"svc = AzureDnsService(\n"
                f"    subscription_id='{self.azure_dns.subscription_id}',\n"
                f"    resource_group='{self.azure_dns.resource_group}',\n"
                f"    tenant_id='{self.azure_dns.tenant_id}',\n"
                f"    client_id='{self.azure_dns.client_id}',\n"
                f"    client_secret='{self.azure_dns.client_secret}',\n"
                f")\n"
                f"svc.delete_txt_record('{zone_name}', '{record_name}', '{rg}')\n"
                '"\n'
            )
            cleanup_script.write_text(azure_cleanup_content)

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )

            if result.returncode == 0:
                cert_path, key_path = self._find_cert_paths(domain)
                logger.info("Certificate issued via Azure DNS-01 for %s", domain)
                return AcmeResult(
                    success=True, domain=domain,
                    cert_path=cert_path, key_path=key_path,
                    message=f"Certificate issued for {domain} via Azure DNS-01",
                )
            else:
                logger.error("certbot Azure DNS-01 failed for %s: %s",
                             domain, result.stderr or result.stdout)
                return AcmeResult(
                    success=False, domain=domain,
                    error=result.stderr.strip() or result.stdout.strip(),
                    message=f"certbot DNS-01 failed for {domain}",
                )
        except subprocess.TimeoutExpired:
            return AcmeResult(
                success=False, domain=domain,
                error="certbot timed out (DNS-01 with Azure)",
                message="Timeout",
            )
        except FileNotFoundError:
            return AcmeResult(
                success=False, domain=domain,
                error="certbot not found — install with: apt-get install certbot",
                message="certbot is not installed",
            )
        finally:
            # Clean up hook scripts and token file
            for f in (auth_script, cleanup_script, token_file):
                f.unlink(missing_ok=True)

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
