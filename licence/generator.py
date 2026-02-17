"""Software licence key generation."""

import hashlib
import hmac
import secrets
import string
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional


@dataclass
class LicenceData:
    """Data associated with a generated licence."""

    key: str
    licence_type: str
    issued_to: str
    issued_at: datetime
    expires_at: Optional[datetime]
    features: list[str] = field(default_factory=list)
    max_users: int = 1
    metadata: dict = field(default_factory=dict)


class LicenceGenerator:
    """Generate and sign software licence keys."""

    LICENCE_TYPES = ("trial", "standard", "professional", "enterprise")

    def __init__(self, signing_secret: str):
        """Initialize with a secret key used to sign licences.

        Args:
            signing_secret: HMAC secret for licence signature.
        """
        self._secret = signing_secret.encode()

    def generate(
        self,
        licence_type: str,
        issued_to: str,
        valid_days: Optional[int] = None,
        features: Optional[list[str]] = None,
        max_users: int = 1,
        metadata: Optional[dict] = None,
    ) -> LicenceData:
        """Generate a new signed licence.

        Args:
            licence_type: One of trial, standard, professional, enterprise.
            issued_to: Name or ID of the licensee.
            valid_days: Number of days the licence is valid (None = perpetual).
            features: List of enabled feature flags.
            max_users: Maximum concurrent users.
            metadata: Additional key-value pairs.

        Returns:
            LicenceData with generated key and details.
        """
        if licence_type not in self.LICENCE_TYPES:
            raise ValueError(
                f"Invalid licence type '{licence_type}'. "
                f"Must be one of: {self.LICENCE_TYPES}"
            )

        issued_at = datetime.now(timezone.utc)
        expires_at = (
            issued_at + timedelta(days=valid_days) if valid_days else None
        )

        raw_key = self._generate_raw_key(licence_type, issued_to, issued_at)
        signature = self._sign(raw_key)
        licence_key = f"{raw_key}-{signature[:8].upper()}"

        return LicenceData(
            key=licence_key,
            licence_type=licence_type,
            issued_to=issued_to,
            issued_at=issued_at,
            expires_at=expires_at,
            features=features or [],
            max_users=max_users,
            metadata=metadata or {},
        )

    def generate_trial(
        self, issued_to: str, trial_days: int = 30
    ) -> LicenceData:
        """Generate a trial licence with default settings."""
        return self.generate(
            licence_type="trial",
            issued_to=issued_to,
            valid_days=trial_days,
            features=["basic"],
            max_users=1,
        )

    def _generate_raw_key(
        self, licence_type: str, issued_to: str, issued_at: datetime
    ) -> str:
        """Create the raw licence key string before signing."""
        type_prefix = licence_type[:3].upper()
        uid = uuid.uuid4().hex[:12].upper()
        random_part = "".join(
            secrets.choice(string.ascii_uppercase + string.digits)
            for _ in range(8)
        )
        return f"{type_prefix}-{uid}-{random_part}"

    def _sign(self, data: str) -> str:
        """Create an HMAC signature for licence data."""
        return hmac.new(
            self._secret, data.encode(), hashlib.sha256
        ).hexdigest()
