"""Domain registry — persistent storage and CRUD for tracked domains."""

import logging
from datetime import datetime, timezone
from typing import Optional

from tracker.base_registry import BaseRegistry
from tracker.domain import Domain, DomainStatus, DomainType

logger = logging.getLogger(__name__)


class DomainRegistry(BaseRegistry[Domain]):
    """Central registry for all tracked domains with DNS/SSL/hosting data."""

    def __init__(self, storage_path: str = "data/domains/registry.json"):
        super().__init__(storage_path)

    # ---- BaseRegistry hooks ----

    def _get_id(self, item: Domain) -> str:
        return item.domain_id

    def _set_timestamps(self, item: Domain, created: bool = False) -> None:
        now = datetime.now(timezone.utc)
        if created:
            item.created_at = now
        item.updated_at = now

    def _to_dict(self, item: Domain) -> dict:
        return item.to_dict()

    def _from_dict(self, data: dict) -> Domain:
        return Domain.from_dict(data)

    @property
    def _entity_name(self) -> str:
        return "domain"

    # ---- Filters ----

    def by_status(self, status: DomainStatus) -> list[Domain]:
        """Filter domains by status."""
        return [d for d in self._items.values() if d.status == status]

    def by_type(self, dtype: DomainType) -> list[Domain]:
        """Filter domains by type."""
        return [d for d in self._items.values() if d.domain_type == dtype]

    def by_parent(self, parent: str) -> list[Domain]:
        """Filter domains by parent domain."""
        parent_lower = parent.lower()
        return [
            d for d in self._items.values()
            if d.parent_domain.lower() == parent_lower
        ]

    def get_by_hostname(self, hostname: str) -> Optional[Domain]:
        """Find a domain by hostname."""
        hostname_lower = hostname.lower()
        for d in self._items.values():
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
