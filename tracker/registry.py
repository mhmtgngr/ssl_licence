"""Product registry — persistent storage and CRUD for tracked products."""

import logging
from datetime import datetime, timezone
from typing import Optional

from tracker.base_registry import BaseRegistry
from tracker.product import Product, ProductCategory, SupportStatus

logger = logging.getLogger(__name__)


class ProductRegistry(BaseRegistry[Product]):
    """Central registry for all tracked product licences and support dates."""

    def __init__(self, storage_path: str = "data/products/registry.json"):
        super().__init__(storage_path)

    # ---- BaseRegistry hooks ----

    def _get_id(self, item: Product) -> str:
        return item.product_id

    def _set_timestamps(self, item: Product, created: bool = False) -> None:
        now = datetime.now(timezone.utc)
        if created:
            item.created_at = now
        item.updated_at = now

    def _to_dict(self, item: Product) -> dict:
        return item.to_dict()

    def _from_dict(self, data: dict) -> Product:
        return Product.from_dict(data)

    @property
    def _entity_name(self) -> str:
        return "product"

    # ---- Filters ----

    def by_category(self, category: ProductCategory) -> list[Product]:
        """Filter products by category."""
        return [p for p in self._items.values() if p.category == category]

    def by_vendor(self, vendor: str) -> list[Product]:
        """Filter products by vendor (case-insensitive)."""
        vendor_lower = vendor.lower()
        return [
            p for p in self._items.values()
            if p.vendor.lower() == vendor_lower
        ]

    def by_environment(self, env: str) -> list[Product]:
        """Filter products by environment."""
        return [p for p in self._items.values() if p.environment == env]

    def by_status(self, status: SupportStatus) -> list[Product]:
        """Filter products by current support status."""
        return [
            p for p in self._items.values()
            if p.support_status() == status
        ]

    def by_tag(self, tag: str) -> list[Product]:
        """Filter products by tag."""
        return [p for p in self._items.values() if tag in p.tags]

    def expiring_within_days(self, days: int) -> list[Product]:
        """Get products whose licence expires within N days."""
        results = []
        for p in self._items.values():
            remaining = p.days_until_licence_expiry()
            if remaining is not None and 0 < remaining <= days:
                results.append(p)
        return sorted(results, key=lambda p: p.days_until_licence_expiry())

    def support_ending_within_days(self, days: int) -> list[Product]:
        """Get products whose support ends within N days."""
        results = []
        for p in self._items.values():
            remaining = p.days_until_support_end()
            if remaining is not None and 0 < remaining <= days:
                results.append(p)
        return sorted(results, key=lambda p: p.days_until_support_end())

    def already_expired(self) -> list[Product]:
        """Get products with already-expired licences."""
        return [p for p in self._items.values() if p.is_licence_expired()]

    def already_end_of_support(self) -> list[Product]:
        """Get products that have reached end of support/life."""
        return [
            p for p in self._items.values()
            if p.support_status() in (
                SupportStatus.END_OF_SUPPORT,
                SupportStatus.END_OF_LIFE,
            )
        ]

    # ---- Stats ----

    def summary(self) -> dict:
        """Get a summary of the entire registry."""
        products = self.list_all()
        total_cost = sum(p.annual_cost for p in products)

        by_category = {}
        for p in products:
            cat = p.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        by_status = {}
        for p in products:
            st = p.support_status().value
            by_status[st] = by_status.get(st, 0) + 1

        by_vendor = {}
        for p in products:
            by_vendor[p.vendor] = by_vendor.get(p.vendor, 0) + 1

        return {
            "total_products": len(products),
            "active_products": sum(1 for p in products if p.is_active),
            "total_annual_cost": total_cost,
            "expired_licences": len(self.already_expired()),
            "end_of_support": len(self.already_end_of_support()),
            "expiring_30_days": len(self.expiring_within_days(30)),
            "expiring_90_days": len(self.expiring_within_days(90)),
            "by_category": by_category,
            "by_status": by_status,
            "by_vendor": by_vendor,
        }
