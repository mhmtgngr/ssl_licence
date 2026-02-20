"""Audit log — track user actions across the application."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


class AuditAction(str, Enum):
    DOMAIN_ADD = "domain_add"
    DOMAIN_DELETE = "domain_delete"
    DOMAIN_EDIT = "domain_edit"
    DOMAIN_REFRESH = "domain_refresh"
    DOMAIN_BULK_REFRESH = "domain_bulk_refresh"
    DOMAIN_IMPORT = "domain_import"
    ALERT_ACKNOWLEDGE = "alert_acknowledge"
    SETTINGS_CHANGE = "settings_change"
    AZURE_SCAN = "azure_scan"
    CERTIFICATE_ISSUE = "certificate_issue"
    CERTIFICATE_RENEW = "certificate_renew"
    EXPORT = "export"
    SCHEDULED_CHECK = "scheduled_check"
    AUTO_RENEWAL = "auto_renewal"
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_ADD = "user_add"
    USER_DELETE = "user_delete"
    USER_EDIT = "user_edit"


@dataclass
class AuditEntry:
    action: AuditAction
    target: str
    detail: str
    user: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "action": self.action.value,
            "target": self.target,
            "detail": self.detail,
            "user": self.user,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AuditEntry":
        return cls(
            entry_id=data.get("entry_id", ""),
            action=AuditAction(data["action"]),
            target=data.get("target", ""),
            detail=data.get("detail", ""),
            user=data.get("user", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


MAX_ENTRIES = 10000


class AuditLog:
    """JSON-file-backed audit log."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, action, target: str, detail: str = "", user: str = "") -> AuditEntry:
        if isinstance(action, str):
            action = AuditAction(action)
        entry = AuditEntry(action=action, target=target, detail=detail, user=user)
        data = self._load()
        data.insert(0, entry.to_dict())
        if len(data) > MAX_ENTRIES:
            data = data[:MAX_ENTRIES]
        self._save(data)
        return entry

    def list_all(self, limit: int = 500) -> list[AuditEntry]:
        data = self._load()
        return [AuditEntry.from_dict(d) for d in data[:limit]]

    def filter(
        self,
        action: AuditAction = None,
        target: str = None,
        limit: int = 500,
    ) -> list[AuditEntry]:
        entries = self.list_all(limit=MAX_ENTRIES)
        if action:
            entries = [e for e in entries if e.action == action]
        if target:
            t = target.lower()
            entries = [e for e in entries if t in e.target.lower()]
        return entries[:limit]

    def _load(self) -> list[dict]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self, data: list[dict]) -> None:
        self._path.write_text(json.dumps(data, indent=2, default=str))
