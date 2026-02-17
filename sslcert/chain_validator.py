"""Certificate chain validation — verify full chain integrity for remote hosts."""

import socket
import ssl as _ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class ChainValidationStatus:
    """Possible chain validation outcomes."""

    VALID = "valid"
    INCOMPLETE = "incomplete_chain"
    SELF_SIGNED = "self_signed"
    EXPIRED_IN_CHAIN = "expired_in_chain"
    UNTRUSTED_ROOT = "untrusted_root"
    CONNECTION_FAILED = "connection_failed"


@dataclass
class ChainLink:
    """A single certificate in the chain."""

    subject: str
    issuer: str
    not_before: str
    not_after: str
    is_ca: bool = False
    serial_number: str = ""


@dataclass
class ChainValidationResult:
    """Result of a full chain validation."""

    domain: str
    status: str
    chain_length: int = 0
    chain: list[ChainLink] = field(default_factory=list)
    error: str = ""
    is_valid: bool = False


class CertificateChainValidator:
    """Validate SSL certificate chains for remote hosts."""

    DEFAULT_PORT = 443
    DEFAULT_TIMEOUT = 10

    def validate(
        self,
        domain: str,
        port: int = DEFAULT_PORT,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> ChainValidationResult:
        """Validate the full certificate chain for a domain.

        Connects via TLS, retrieves the peer certificate chain,
        and checks ordering, completeness, and expiry of each link.
        """
        try:
            chain_certs = self._fetch_chain(domain, port, timeout)
        except (socket.error, _ssl.SSLError, OSError) as exc:
            return ChainValidationResult(
                domain=domain,
                status=ChainValidationStatus.CONNECTION_FAILED,
                error=str(exc),
            )

        if not chain_certs:
            return ChainValidationResult(
                domain=domain,
                status=ChainValidationStatus.CONNECTION_FAILED,
                error="No certificates returned",
            )

        chain_links = self._parse_chain(chain_certs)
        status = self._evaluate_chain(chain_links)

        return ChainValidationResult(
            domain=domain,
            status=status,
            chain_length=len(chain_links),
            chain=chain_links,
            is_valid=(status == ChainValidationStatus.VALID),
        )

    def _fetch_chain(self, domain: str, port: int, timeout: int) -> list[dict]:
        """Connect to host and retrieve the certificate chain."""
        context = _ssl.create_default_context()
        certs = []

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                # Get the leaf certificate
                leaf = tls.getpeercert()
                if leaf:
                    certs.append(leaf)

                # Try to get the full verified chain (Python 3.10+)
                try:
                    binary_chain = tls.get_verified_chain()
                    if binary_chain and len(binary_chain) > 1:
                        # Parse binary DER certs into readable dicts
                        for der_cert in binary_chain[1:]:
                            parsed = _ssl._ssl._test_decode_cert(der_cert)  # type: ignore[attr-defined]
                            if parsed:
                                certs.append(parsed)
                except (AttributeError, TypeError):
                    # get_verified_chain not available; use leaf only
                    pass

        return certs

    def _parse_chain(self, certs: list[dict]) -> list[ChainLink]:
        """Convert raw cert dicts to ChainLink dataclasses."""
        links = []
        for cert in certs:
            subject = self._format_dn(cert.get("subject", ()))
            issuer = self._format_dn(cert.get("issuer", ()))
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")
            is_ca = subject == issuer  # Self-signed or root CA

            links.append(ChainLink(
                subject=subject,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
                is_ca=is_ca,
                serial_number=cert.get("serialNumber", ""),
            ))
        return links

    def _evaluate_chain(self, links: list[ChainLink]) -> str:
        """Determine overall chain status."""
        if not links:
            return ChainValidationStatus.INCOMPLETE

        # Check for self-signed leaf (single cert, subject == issuer)
        if len(links) == 1 and links[0].is_ca:
            return ChainValidationStatus.SELF_SIGNED

        # Check for expired certificates in chain
        now = datetime.utcnow()
        for link in links:
            try:
                not_after = datetime.strptime(link.not_after, "%b %d %H:%M:%S %Y %Z")
                if not_after < now:
                    return ChainValidationStatus.EXPIRED_IN_CHAIN
            except (ValueError, TypeError):
                pass

        # Chain ordering: each cert's issuer should match next cert's subject
        for i in range(len(links) - 1):
            if links[i].issuer != links[i + 1].subject:
                return ChainValidationStatus.INCOMPLETE

        return ChainValidationStatus.VALID

    @staticmethod
    def _format_dn(dn_tuple) -> str:
        """Format a distinguished name tuple into a readable string."""
        parts = []
        for rdn in dn_tuple:
            for attr_type, attr_value in rdn:
                parts.append(f"{attr_type}={attr_value}")
        return ", ".join(parts)
