"""Data store classes extracted from services.py for single-responsibility."""

import json
import logging
from pathlib import Path

from utils.safe_io import atomic_write_json

logger = logging.getLogger(__name__)


class AzureScanStore:
    """Persist Azure resource scan results to JSON."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, bindings: list, summary: dict) -> None:
        from datetime import datetime, timezone
        data = {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "bindings": [
                {
                    "resource_type": b.resource_type,
                    "resource_name": b.resource_name,
                    "resource_group": b.resource_group,
                    "subscription_id": b.subscription_id,
                    "subscription_name": b.subscription_name,
                    "resource_id": b.resource_id,
                    "hostname": b.hostname,
                    "hostname_type": b.hostname_type,
                    "ssl_enabled": b.ssl_enabled,
                    "ssl_thumbprint": b.ssl_thumbprint,
                    "ssl_subject": b.ssl_subject,
                    "ssl_expiry": b.ssl_expiry.isoformat() if b.ssl_expiry else None,
                    "ssl_state": b.ssl_state,
                    "tracked": b.tracked,
                    "tracked_domain_id": b.tracked_domain_id,
                }
                for b in bindings
            ],
        }
        atomic_write_json(self._path, data)

    def load(self) -> dict | None:
        if not self._path.exists():
            return None
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def load_bindings(self) -> list:
        """Load raw binding dicts from cache."""
        data = self.load()
        if not data:
            return []
        return data.get("bindings", [])

    def get_bindings_for_hostname(self, hostname: str) -> list[dict]:
        """Return cached bindings matching a specific hostname."""
        bindings = self.load_bindings()
        h = hostname.lower()
        return [b for b in bindings if b.get("hostname", "").lower() == h]


class CertCheckStore:
    """Simple JSON-file store for certificate check history."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[dict]:
        if self._path.exists():
            return json.loads(self._path.read_text())
        return []

    def _save(self, data: list[dict]) -> None:
        atomic_write_json(self._path, data)

    def add(self, entry: dict) -> None:
        data = self._load()
        data.insert(0, entry)
        self._save(data)

    def list_all(self) -> list[dict]:
        return self._load()

    def clear(self) -> None:
        self._save([])
