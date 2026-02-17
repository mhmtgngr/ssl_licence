"""SSL helper utilities."""

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Optional

PEM_PATTERN = re.compile(
    r"-----BEGIN CERTIFICATE-----\s+.+?\s+-----END CERTIFICATE-----",
    re.DOTALL,
)


def is_certificate_valid(cert_path: str) -> bool:
    """Check if a PEM certificate file is structurally valid.

    Args:
        cert_path: Path to a PEM certificate file.

    Returns:
        True if the certificate can be parsed by openssl.
    """
    try:
        subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-noout"],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def parse_pem_chain(pem_text: str) -> list[str]:
    """Split a PEM bundle into individual certificate strings.

    Args:
        pem_text: PEM-encoded text potentially containing multiple certs.

    Returns:
        List of individual PEM certificate strings.
    """
    return PEM_PATTERN.findall(pem_text)


def fingerprint(cert_path: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute the fingerprint of a PEM certificate.

    Args:
        cert_path: Path to a PEM certificate file.
        algorithm: Hash algorithm (sha256, sha1, md5).

    Returns:
        Hex fingerprint string, or None on error.
    """
    path = Path(cert_path)
    if not path.exists():
        return None

    try:
        result = subprocess.run(
            [
                "openssl", "x509",
                "-in", cert_path,
                "-outform", "DER",
            ],
            check=True,
            capture_output=True,
        )
        h = hashlib.new(algorithm)
        h.update(result.stdout)
        digest = h.hexdigest()
        # Format as colon-separated pairs
        return ":".join(digest[i:i+2].upper() for i in range(0, len(digest), 2))
    except (subprocess.CalledProcessError, ValueError):
        return None
