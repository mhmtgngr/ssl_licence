"""JSON-backed settings store for runtime configuration."""

import json
from pathlib import Path
from typing import Any


class SettingsStore:
    """Persist application settings to a JSON file.

    Supports dot-notation keys (e.g. ``azure_dns.tenant_id``) and
    section-level bulk get/set.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self, data: dict) -> None:
        self._path.write_text(json.dumps(data, indent=2))

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value using dot-notation key (e.g. ``azure_dns.tenant_id``)."""
        data = self._load()
        parts = key.split(".", 1)
        if len(parts) == 2:
            section = data.get(parts[0], {})
            return section.get(parts[1], default)
        return data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a value using dot-notation key."""
        data = self._load()
        parts = key.split(".", 1)
        if len(parts) == 2:
            section = data.setdefault(parts[0], {})
            section[parts[1]] = value
        else:
            data[key] = value
        self._save(data)

    def get_section(self, section: str) -> dict:
        """Get all key-value pairs in a section."""
        return dict(self._load().get(section, {}))

    def set_section(self, section: str, values: dict) -> None:
        """Set all key-value pairs in a section (merges with existing)."""
        data = self._load()
        existing = data.get(section, {})
        existing.update(values)
        data[section] = existing
        self._save(data)

    def get_all(self) -> dict:
        """Return the entire settings dictionary."""
        return self._load()
