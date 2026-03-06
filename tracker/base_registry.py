"""Generic base registry — shared CRUD and persistence for all registries."""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Generic, Optional, TypeVar

from utils.safe_io import atomic_write_json

logger = logging.getLogger(__name__)

T = TypeVar("T")


class BaseRegistry(ABC, Generic[T]):
    """Abstract base providing CRUD, persistence, and list operations.

    Subclasses must implement:
        - ``_get_id(item)`` — return the unique identifier for an item
        - ``_set_timestamps(item, created)`` — set created_at/updated_at
        - ``_to_dict(item)`` — serialize an item to a dict
        - ``_from_dict(data)`` — deserialize a dict to an item
        - ``_entity_name`` — human-readable name for log messages
    """

    def __init__(self, storage_path: str):
        self._path = Path(storage_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._items: dict[str, T] = {}
        self._load()

    @abstractmethod
    def _get_id(self, item: T) -> str:
        """Return the unique ID of an item."""

    @abstractmethod
    def _set_timestamps(self, item: T, created: bool = False) -> None:
        """Set created_at (if created=True) and updated_at on the item."""

    @abstractmethod
    def _to_dict(self, item: T) -> dict:
        """Serialize item to a dict."""

    @abstractmethod
    def _from_dict(self, data: dict) -> T:
        """Deserialize a dict to an item. May raise KeyError/ValueError."""

    @property
    def _entity_name(self) -> str:
        """Human-readable name for log messages (e.g. 'product', 'domain')."""
        return "item"

    # ---- CRUD ----

    def add(self, item: T) -> T:
        """Add an item to the registry."""
        self._set_timestamps(item, created=True)
        self._items[self._get_id(item)] = item
        self._save()
        return item

    def update(self, item_id: str, **fields) -> Optional[T]:
        """Update fields on an existing item."""
        item = self._items.get(item_id)
        if not item:
            return None
        for key, value in fields.items():
            if hasattr(item, key):
                setattr(item, key, value)
        self._set_timestamps(item)
        self._save()
        return item

    def remove(self, item_id: str) -> bool:
        """Remove an item from the registry."""
        if item_id in self._items:
            del self._items[item_id]
            self._save()
            return True
        return False

    def get(self, item_id: str) -> Optional[T]:
        """Get an item by ID."""
        return self._items.get(item_id)

    def list_all(self) -> list[T]:
        """Return all items."""
        return list(self._items.values())

    # ---- Persistence ----

    def _save(self) -> None:
        """Save registry to disk atomically."""
        data = [self._to_dict(item) for item in self._items.values()]
        atomic_write_json(self._path, data)

    def _load(self) -> None:
        """Load registry from disk."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for entry in data:
                try:
                    item = self._from_dict(entry)
                    self._items[self._get_id(item)] = item
                except (KeyError, ValueError) as e:
                    logger.warning("Skipping invalid %s entry: %s", self._entity_name, e)
        except json.JSONDecodeError as e:
            logger.error("Failed to parse %s registry %s: %s", self._entity_name, self._path, e)
