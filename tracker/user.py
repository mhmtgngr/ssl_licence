"""User model and JSON-file-backed user store."""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from werkzeug.security import generate_password_hash, check_password_hash


class UserRole(str, Enum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


@dataclass
class User:
    username: str
    role: UserRole = UserRole.VIEWER
    display_name: str = ""
    password_hash: str = ""
    user_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None
    disabled: bool = False
    auth_source: str = "local"  # "local" or "oidc"

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def to_dict(self) -> dict:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "display_name": self.display_name,
            "role": self.role.value,
            "password_hash": self.password_hash,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "disabled": self.disabled,
            "auth_source": self.auth_source,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "User":
        return cls(
            user_id=data.get("user_id", ""),
            username=data["username"],
            display_name=data.get("display_name", ""),
            role=UserRole(data.get("role", "viewer")),
            password_hash=data.get("password_hash", ""),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else datetime.now(timezone.utc)
            ),
            last_login=(
                datetime.fromisoformat(data["last_login"])
                if data.get("last_login")
                else None
            ),
            disabled=data.get("disabled", False),
            auth_source=data.get("auth_source", "local"),
        )


class UserStore:
    """JSON-file-backed user store."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_default_admin()

    def _load(self) -> list[dict]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                return []
        return []

    def _save(self, data: list[dict]) -> None:
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def _ensure_default_admin(self) -> None:
        """Create a default admin user if no users exist."""
        data = self._load()
        if not data:
            admin = User(
                username="admin",
                role=UserRole.ADMIN,
                display_name="Administrator",
            )
            admin.set_password("admin")
            self._save([admin.to_dict()])

    def get_by_username(self, username: str) -> User | None:
        data = self._load()
        for item in data:
            if item["username"].lower() == username.lower():
                return User.from_dict(item)
        return None

    def get_by_id(self, user_id: str) -> User | None:
        data = self._load()
        for item in data:
            if item.get("user_id") == user_id:
                return User.from_dict(item)
        return None

    def list_all(self) -> list[User]:
        return [User.from_dict(d) for d in self._load()]

    def add(self, user: User) -> User:
        data = self._load()
        data.append(user.to_dict())
        self._save(data)
        return user

    def update(self, user_id: str, **fields) -> User | None:
        data = self._load()
        for i, item in enumerate(data):
            if item.get("user_id") == user_id:
                user = User.from_dict(item)
                for key, value in fields.items():
                    if hasattr(user, key):
                        setattr(user, key, value)
                data[i] = user.to_dict()
                self._save(data)
                return user
        return None

    def remove(self, user_id: str) -> bool:
        data = self._load()
        new_data = [d for d in data if d.get("user_id") != user_id]
        if len(new_data) < len(data):
            self._save(new_data)
            return True
        return False

    def authenticate(self, username: str, password: str) -> User | None:
        """Return user if credentials valid, else None."""
        user = self.get_by_username(username)
        if user and not user.disabled and user.check_password(password):
            self.update(user.user_id, last_login=datetime.now(timezone.utc))
            return user
        return None
