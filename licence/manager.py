"""Licence lifecycle management and storage."""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from licence.generator import LicenceGenerator, LicenceData
from licence.validator import LicenceValidator, ValidationResult


class LicenceManager:
    """High-level licence management: issue, revoke, list, and persist licences."""

    def __init__(
        self,
        signing_secret: str,
        storage_path: str = "licences.json",
    ):
        """Initialize the licence manager.

        Args:
            signing_secret: Secret for signing/verifying licences.
            storage_path: Path to the JSON file storing licence records.
        """
        self._generator = LicenceGenerator(signing_secret)
        self._validator = LicenceValidator(signing_secret)
        self._storage_path = Path(storage_path)
        self._licences: dict[str, dict] = {}
        self._load()

    def issue(
        self,
        licence_type: str,
        issued_to: str,
        valid_days: Optional[int] = None,
        features: Optional[list[str]] = None,
        max_users: int = 1,
    ) -> LicenceData:
        """Issue a new licence and persist it.

        Args:
            licence_type: Type of licence to issue.
            issued_to: Licensee name or identifier.
            valid_days: Validity period in days (None = perpetual).
            features: Enabled feature flags.
            max_users: Max concurrent users.

        Returns:
            The generated LicenceData.
        """
        licence = self._generator.generate(
            licence_type=licence_type,
            issued_to=issued_to,
            valid_days=valid_days,
            features=features,
            max_users=max_users,
        )
        self._licences[licence.key] = self._serialize(licence)
        self._save()
        return licence

    def validate(self, licence_key: str) -> ValidationResult:
        """Validate a licence key and check if it's active."""
        result = self._validator.validate(licence_key)

        if result.is_valid and licence_key in self._licences:
            record = self._licences[licence_key]
            if record.get("revoked"):
                result.is_valid = False
                result.error = "Licence has been revoked"
            elif record.get("expires_at"):
                expires = datetime.fromisoformat(record["expires_at"])
                result.expires_at = expires
                if expires < datetime.utcnow():
                    result.is_valid = False
                    result.is_expired = True
                    result.error = "Licence has expired"

        return result

    def revoke(self, licence_key: str) -> bool:
        """Revoke an existing licence.

        Args:
            licence_key: The licence key to revoke.

        Returns:
            True if the licence was found and revoked.
        """
        if licence_key not in self._licences:
            return False
        self._licences[licence_key]["revoked"] = True
        self._licences[licence_key]["revoked_at"] = datetime.utcnow().isoformat()
        self._save()
        return True

    def list_active(self) -> list[dict]:
        """Return all active (non-revoked, non-expired) licences."""
        active = []
        now = datetime.utcnow()
        for key, record in self._licences.items():
            if record.get("revoked"):
                continue
            expires_at = record.get("expires_at")
            if expires_at and datetime.fromisoformat(expires_at) < now:
                continue
            active.append({"key": key, **record})
        return active

    def list_all(self) -> list[dict]:
        """Return all licences regardless of status."""
        return [{"key": k, **v} for k, v in self._licences.items()]

    def get(self, licence_key: str) -> Optional[dict]:
        """Get details for a specific licence key."""
        if licence_key in self._licences:
            return {"key": licence_key, **self._licences[licence_key]}
        return None

    def _load(self) -> None:
        """Load licences from the storage file."""
        if self._storage_path.exists():
            try:
                data = json.loads(self._storage_path.read_text())
                self._licences = data
            except (json.JSONDecodeError, IOError):
                self._licences = {}

    def _save(self) -> None:
        """Persist licences to the storage file."""
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._storage_path.write_text(
            json.dumps(self._licences, indent=2, default=str)
        )

    @staticmethod
    def _serialize(licence: LicenceData) -> dict:
        """Convert LicenceData to a JSON-serializable dict."""
        return {
            "licence_type": licence.licence_type,
            "issued_to": licence.issued_to,
            "issued_at": licence.issued_at.isoformat(),
            "expires_at": licence.expires_at.isoformat() if licence.expires_at else None,
            "features": licence.features,
            "max_users": licence.max_users,
            "metadata": licence.metadata,
            "revoked": False,
        }
