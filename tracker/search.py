"""
Comprehensive search engine for the product registry.

Supports full-text search across all product fields, faceted filtering,
and sorted result views.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from tracker.product import Product, ProductCategory, SupportStatus


@dataclass
class SearchResult:
    """A search result with relevance score."""

    product: Product
    score: float
    matched_fields: list[str]


class SearchEngine:
    """Search and filter products in the registry."""

    def __init__(self, registry):
        self._registry = registry

    def search(
        self,
        query: str,
        category: Optional[ProductCategory] = None,
        vendor: Optional[str] = None,
        status: Optional[SupportStatus] = None,
        environment: Optional[str] = None,
        tags: Optional[list[str]] = None,
        min_days_to_expiry: Optional[int] = None,
        max_days_to_expiry: Optional[int] = None,
        sort_by: str = "relevance",
        limit: int = 50,
    ) -> list[SearchResult]:
        """Full-text search with faceted filtering.

        Args:
            query: Free-text search string (matched against name, vendor, notes, tags).
            category: Filter by product category.
            vendor: Filter by vendor name.
            status: Filter by support status.
            environment: Filter by environment (production, staging, etc.).
            tags: Filter by tags (any match).
            min_days_to_expiry: Minimum days until licence expiry.
            max_days_to_expiry: Maximum days until licence expiry.
            sort_by: "relevance", "expiry_asc", "expiry_desc", "name", "vendor".
            limit: Maximum results to return.

        Returns:
            Sorted list of SearchResult.
        """
        products = self._registry.list_all()
        results = []

        for product in products:
            # Apply filters
            if category and product.category != category:
                continue
            if vendor and product.vendor.lower() != vendor.lower():
                continue
            if status and product.support_status() != status:
                continue
            if environment and product.environment != environment:
                continue
            if tags and not any(t in product.tags for t in tags):
                continue

            days = product.days_until_licence_expiry()
            if min_days_to_expiry is not None and days is not None:
                if days < min_days_to_expiry:
                    continue
            if max_days_to_expiry is not None and days is not None:
                if days > max_days_to_expiry:
                    continue

            # Score text match
            score, matched = self._score_match(product, query)
            if query and score == 0:
                continue

            results.append(SearchResult(
                product=product,
                score=score,
                matched_fields=matched,
            ))

        # Sort
        results = self._sort_results(results, sort_by)
        return results[:limit]

    def find_by_name(self, name: str) -> list[Product]:
        """Quick search by product name (substring)."""
        name_lower = name.lower()
        return [
            p for p in self._registry.list_all()
            if name_lower in p.name.lower()
        ]

    def find_duplicates(self) -> list[list[Product]]:
        """Find products that might be duplicates (same name + vendor)."""
        seen = {}
        for p in self._registry.list_all():
            key = (p.name.lower(), p.vendor.lower())
            seen.setdefault(key, []).append(p)
        return [group for group in seen.values() if len(group) > 1]

    def cost_report(
        self, category: Optional[ProductCategory] = None
    ) -> dict:
        """Generate a cost summary, optionally filtered by category."""
        products = self._registry.list_all()
        if category:
            products = [p for p in products if p.category == category]

        total = sum(p.annual_cost for p in products)

        by_vendor = {}
        for p in products:
            by_vendor[p.vendor] = by_vendor.get(p.vendor, 0) + p.annual_cost

        by_category = {}
        for p in products:
            cat = p.category.value
            by_category[cat] = by_category.get(cat, 0) + p.annual_cost

        by_env = {}
        for p in products:
            by_env[p.environment] = by_env.get(p.environment, 0) + p.annual_cost

        return {
            "total_annual_cost": total,
            "product_count": len(products),
            "by_vendor": dict(sorted(by_vendor.items(), key=lambda x: -x[1])),
            "by_category": dict(sorted(by_category.items(), key=lambda x: -x[1])),
            "by_environment": by_env,
        }

    def expiry_timeline(self, months_ahead: int = 12) -> list[dict]:
        """Build a timeline of upcoming expiries/end-of-support dates."""
        now = datetime.now(timezone.utc)
        events = []

        for p in self._registry.list_all():
            for date_field, label in [
                ("licence_expiry", "Licence Expiry"),
                ("mainstream_support_end", "Mainstream Support End"),
                ("extended_support_end", "Extended Support End"),
                ("end_of_life", "End of Life"),
            ]:
                date_val = getattr(p, date_field)
                if not date_val:
                    continue
                days = (date_val - now).days
                if 0 <= days <= months_ahead * 30:
                    events.append({
                        "date": date_val.isoformat(),
                        "days_remaining": days,
                        "event": label,
                        "product": p.name,
                        "vendor": p.vendor,
                        "version": p.version,
                        "product_id": p.product_id,
                    })

        return sorted(events, key=lambda e: e["days_remaining"])

    def _score_match(self, product: Product, query: str) -> tuple[float, list[str]]:
        """Score a product against a search query."""
        if not query:
            return (1.0, [])

        query_lower = query.lower()
        terms = query_lower.split()
        score = 0.0
        matched = []

        searchable = {
            "name": (product.name.lower(), 3.0),
            "vendor": (product.vendor.lower(), 2.5),
            "version": (product.version.lower(), 2.0),
            "category": (product.category.value.lower(), 1.5),
            "department": (product.department.lower(), 1.0),
            "owner": (product.owner.lower(), 1.0),
            "notes": (product.notes.lower(), 0.5),
            "environment": (product.environment.lower(), 1.0),
            "tags": (" ".join(product.tags).lower(), 1.5),
        }

        for term in terms:
            for field_name, (text, weight) in searchable.items():
                if term in text:
                    score += weight
                    if field_name not in matched:
                        matched.append(field_name)

        return (score, matched)

    @staticmethod
    def _sort_results(results: list[SearchResult], sort_by: str) -> list[SearchResult]:
        """Sort search results."""
        if sort_by == "relevance":
            return sorted(results, key=lambda r: -r.score)
        elif sort_by == "expiry_asc":
            def expiry_key(r):
                d = r.product.days_until_licence_expiry()
                return d if d is not None else float("inf")
            return sorted(results, key=expiry_key)
        elif sort_by == "expiry_desc":
            def expiry_key_desc(r):
                d = r.product.days_until_licence_expiry()
                return -(d if d is not None else float("-inf"))
            return sorted(results, key=expiry_key_desc)
        elif sort_by == "name":
            return sorted(results, key=lambda r: r.product.name.lower())
        elif sort_by == "vendor":
            return sorted(results, key=lambda r: r.product.vendor.lower())
        return results
