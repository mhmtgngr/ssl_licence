"""Domain registry — persistent storage and CRUD for tracked domains."""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from tracker.domain import Domain, DomainStatus, DomainType


class DomainRegistry:
    """Central registry for all tracked domains with DNS/SSL/hosting data."""

    def __init__(self, storage_path: str = "data/domains/registry.json"):
        self._path = Path(storage_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._domains: dict[str, Domain] = {}
        self._load()

    # ---- CRUD ----

    def add(self, domain: Domain) -> Domain:
        """Add a domain to the registry."""
        domain.created_at = datetime.now(timezone.utc)
        domain.updated_at = datetime.now(timezone.utc)
        self._domains[domain.domain_id] = domain
        self._save()
        return domain

    def update(self, domain_id: str, **fields) -> Optional[Domain]:
        """Update fields on an existing domain."""
        domain = self._domains.get(domain_id)
        if not domain:
            return None
        for key, value in fields.items():
            if hasattr(domain, key):
                setattr(domain, key, value)
        domain.updated_at = datetime.now(timezone.utc)
        self._save()
        return domain

    def remove(self, domain_id: str) -> bool:
        """Remove a domain from the registry."""
        if domain_id in self._domains:
            del self._domains[domain_id]
            self._save()
            return True
        return False

    def get(self, domain_id: str) -> Optional[Domain]:
        """Get a domain by ID."""
        return self._domains.get(domain_id)

    def list_all(self) -> list[Domain]:
        """Return all domains."""
        return list(self._domains.values())

    # ---- Filters ----

    def by_status(self, status: DomainStatus) -> list[Domain]:
        """Filter domains by status."""
        return [d for d in self._domains.values() if d.status == status]

    def by_type(self, dtype: DomainType) -> list[Domain]:
        """Filter domains by type."""
        return [d for d in self._domains.values() if d.domain_type == dtype]

    def by_parent(self, parent: str) -> list[Domain]:
        """Filter domains by parent domain."""
        parent_lower = parent.lower()
        return [
            d for d in self._domains.values()
            if d.parent_domain.lower() == parent_lower
        ]

    def get_by_hostname(self, hostname: str) -> Optional[Domain]:
        """Find a domain by hostname."""
        hostname_lower = hostname.lower()
        for d in self._domains.values():
            if d.hostname.lower() == hostname_lower:
                return d
        return None

    # ---- Stats ----

    def summary(self) -> dict:
        """Get a summary of the domain registry."""
        domains = self.list_all()

        by_status = {}
        for d in domains:
            st = d.status.value
            by_status[st] = by_status.get(st, 0) + 1

        by_type = {}
        for d in domains:
            dt = d.domain_type.value
            by_type[dt] = by_type.get(dt, 0) + 1

        parents = set()
        for d in domains:
            if d.parent_domain:
                parents.add(d.parent_domain)

        ssl_ok = sum(1 for d in domains if d.ssl_status == "ok")
        ssl_warning = sum(1 for d in domains if d.ssl_status == "warning")
        ssl_expired = sum(1 for d in domains if d.ssl_status in ("expired", "fail"))

        return {
            "total_domains": len(domains),
            "by_status": by_status,
            "by_type": by_type,
            "parent_domains": len(parents),
            "ssl_ok": ssl_ok,
            "ssl_warning": ssl_warning,
            "ssl_expired": ssl_expired,
        }

    # ---- Persistence ----

    def _save(self) -> None:
        """Save registry to disk."""
        data = [d.to_dict() for d in self._domains.values()]
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def _load(self) -> None:
        """Load registry from disk."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for item in data:
                domain = Domain.from_dict(item)
                self._domains[domain.domain_id] = domain
        except (json.JSONDecodeError, KeyError):
            pass
