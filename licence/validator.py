"""Licence key validation."""

import hashlib
import hmac
import re
from datetime import datetime
from dataclasses import dataclass
from typing import Optional


@dataclass
class ValidationResult:
    """Result of a licence validation check."""

    is_valid: bool
    licence_key: str
    licence_type: Optional[str] = None
    error: Optional[str] = None
    expires_at: Optional[datetime] = None
    is_expired: bool = False


class LicenceValidator:
    """Validate licence keys and check their status."""

    # Pattern: TYPE_PREFIX-12HEX-8ALNUM-8HEXSIG
    KEY_PATTERN = re.compile(
        r"^([A-Z]{3})-([A-Z0-9]{12})-([A-Z0-9]{8})-([A-F0-9]{8})$"
    )

    TYPE_MAP = {
        "TRI": "trial",
        "STA": "standard",
        "PRO": "professional",
        "ENT": "enterprise",
    }

    def __init__(self, signing_secret: str):
        """Initialize with the same secret used to generate licences.

        Args:
            signing_secret: HMAC secret for signature verification.
        """
        self._secret = signing_secret.encode()

    def validate(
        self, licence_key: str, check_expiry: bool = True
    ) -> ValidationResult:
        """Validate a licence key format and signature.

        Args:
            licence_key: The licence key string to validate.
            check_expiry: Whether to check expiration (requires stored data).

        Returns:
            ValidationResult with validation status and details.
        """
        match = self.KEY_PATTERN.match(licence_key)
        if not match:
            return ValidationResult(
                is_valid=False,
                licence_key=licence_key,
                error="Invalid licence key format",
            )

        type_prefix, uid, random_part, signature = match.groups()

        licence_type = self.TYPE_MAP.get(type_prefix)
        if not licence_type:
            return ValidationResult(
                is_valid=False,
                licence_key=licence_key,
                error=f"Unknown licence type prefix: {type_prefix}",
            )

        raw_key = f"{type_prefix}-{uid}-{random_part}"
        expected_sig = self._sign(raw_key)[:8].upper()

        if signature != expected_sig:
            return ValidationResult(
                is_valid=False,
                licence_key=licence_key,
                licence_type=licence_type,
                error="Invalid licence signature",
            )

        return ValidationResult(
            is_valid=True,
            licence_key=licence_key,
            licence_type=licence_type,
        )

    def is_key_format_valid(self, licence_key: str) -> bool:
        """Quick check if the key matches the expected format."""
        return bool(self.KEY_PATTERN.match(licence_key))

    def _sign(self, data: str) -> str:
        """Recreate the HMAC signature for verification."""
        return hmac.new(
            self._secret, data.encode(), hashlib.sha256
        ).hexdigest()
