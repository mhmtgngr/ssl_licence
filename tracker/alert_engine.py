"""
Alert engine — monitors products and generates alerts at configurable thresholds.

Default thresholds: 6 months, 3 months, 1 month, 1 week, expired.
Supports licence expiry, end-of-support, and end-of-life alerts.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from tracker.product import Product, SupportStatus


class AlertLevel(str, Enum):
    """Severity level of an alert."""

    INFO = "info"                # > 6 months away
    LOW = "low"                  # 6 months
    MEDIUM = "medium"            # 3 months
    HIGH = "high"                # 1 month
    CRITICAL = "critical"        # 1 week
    EXPIRED = "expired"          # Already past due


class AlertType(str, Enum):
    """Type of alert trigger."""

    LICENCE_EXPIRY = "licence_expiry"
    MAINSTREAM_SUPPORT_END = "mainstream_support_end"
    EXTENDED_SUPPORT_END = "extended_support_end"
    END_OF_LIFE = "end_of_life"


@dataclass
class AlertThreshold:
    """A single alert threshold."""

    days: int
    level: AlertLevel
    label: str


@dataclass
class Alert:
    """A generated alert for a product."""

    product_id: str
    product_name: str
    vendor: str
    alert_type: AlertType
    alert_level: AlertLevel
    days_remaining: int
    target_date: datetime
    message: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "product_id": self.product_id,
            "product_name": self.product_name,
            "vendor": self.vendor,
            "alert_type": self.alert_type.value,
            "alert_level": self.alert_level.value,
            "days_remaining": self.days_remaining,
            "target_date": self.target_date.isoformat(),
            "message": self.message,
            "generated_at": self.generated_at.isoformat(),
            "acknowledged": self.acknowledged,
        }


# Default thresholds: 6 months, 3 months, 1 month, 1 week
DEFAULT_THRESHOLDS = [
    AlertThreshold(days=180, level=AlertLevel.LOW, label="6 months"),
    AlertThreshold(days=90, level=AlertLevel.MEDIUM, label="3 months"),
    AlertThreshold(days=30, level=AlertLevel.HIGH, label="1 month"),
    AlertThreshold(days=7, level=AlertLevel.CRITICAL, label="1 week"),
]


class AlertEngine:
    """Evaluate products against thresholds and generate alerts.

    Usage:
        engine = AlertEngine(registry)
        alerts = engine.evaluate_all()

        # Filter by level
        critical = engine.get_alerts(level=AlertLevel.CRITICAL)

        # Custom thresholds
        engine = AlertEngine(registry, thresholds=[
            AlertThreshold(days=365, level=AlertLevel.INFO, label="1 year"),
            AlertThreshold(days=180, level=AlertLevel.LOW, label="6 months"),
        ])
    """

    def __init__(
        self,
        registry,
        thresholds: Optional[list[AlertThreshold]] = None,
        history_path: str = "data/alerts_history.json",
    ):
        self._registry = registry
        self._thresholds = sorted(
            thresholds or DEFAULT_THRESHOLDS,
            key=lambda t: t.days,
        )
        self._history_path = Path(history_path)
        self._alerts: list[Alert] = []

    def evaluate_all(self) -> list[Alert]:
        """Evaluate all products and generate alerts."""
        self._alerts = []
        for product in self._registry.list_all():
            if not product.is_active:
                continue
            self._alerts.extend(self._evaluate_product(product))
        self._alerts.sort(key=lambda a: a.days_remaining)
        return self._alerts

    def evaluate_product(self, product_id: str) -> list[Alert]:
        """Evaluate a single product."""
        product = self._registry.get(product_id)
        if not product:
            return []
        return self._evaluate_product(product)

    def get_alerts(
        self,
        level: Optional[AlertLevel] = None,
        alert_type: Optional[AlertType] = None,
        vendor: Optional[str] = None,
    ) -> list[Alert]:
        """Filter generated alerts."""
        results = self._alerts
        if level:
            results = [a for a in results if a.alert_level == level]
        if alert_type:
            results = [a for a in results if a.alert_type == alert_type]
        if vendor:
            v = vendor.lower()
            results = [a for a in results if a.vendor.lower() == v]
        return results

    def get_critical_alerts(self) -> list[Alert]:
        """Get only CRITICAL and EXPIRED alerts."""
        return [
            a for a in self._alerts
            if a.alert_level in (AlertLevel.CRITICAL, AlertLevel.EXPIRED)
        ]

    def get_dashboard_summary(self) -> dict:
        """Summary suitable for a monitoring dashboard."""
        if not self._alerts:
            self.evaluate_all()

        by_level = {}
        for level in AlertLevel:
            count = sum(1 for a in self._alerts if a.alert_level == level)
            if count:
                by_level[level.value] = count

        by_type = {}
        for atype in AlertType:
            count = sum(1 for a in self._alerts if a.alert_type == atype)
            if count:
                by_type[atype.value] = count

        upcoming_critical = [
            a.to_dict() for a in self._alerts
            if a.alert_level in (AlertLevel.CRITICAL, AlertLevel.EXPIRED)
        ][:10]

        return {
            "total_alerts": len(self._alerts),
            "by_level": by_level,
            "by_type": by_type,
            "critical_items": upcoming_critical,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def save_history(self) -> None:
        """Persist alert history to file."""
        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        data = [a.to_dict() for a in self._alerts]
        self._history_path.write_text(json.dumps(data, indent=2))

    def _evaluate_product(self, product: Product) -> list[Alert]:
        """Generate alerts for a single product based on all date fields."""
        alerts = []
        now = datetime.now(timezone.utc)

        # Check licence expiry
        if product.licence_expiry:
            alerts.extend(
                self._check_date(
                    product, product.licence_expiry, AlertType.LICENCE_EXPIRY, now
                )
            )

        # Check mainstream support end
        if product.mainstream_support_end:
            alerts.extend(
                self._check_date(
                    product,
                    product.mainstream_support_end,
                    AlertType.MAINSTREAM_SUPPORT_END,
                    now,
                )
            )

        # Check extended support end
        if product.extended_support_end:
            alerts.extend(
                self._check_date(
                    product,
                    product.extended_support_end,
                    AlertType.EXTENDED_SUPPORT_END,
                    now,
                )
            )

        # Check end of life
        if product.end_of_life:
            alerts.extend(
                self._check_date(
                    product, product.end_of_life, AlertType.END_OF_LIFE, now
                )
            )

        return alerts

    def _check_date(
        self,
        product: Product,
        target_date: datetime,
        alert_type: AlertType,
        now: datetime,
    ) -> list[Alert]:
        """Check a date against thresholds and produce matching alerts."""
        days_remaining = (target_date - now).days

        if days_remaining < 0:
            return [
                Alert(
                    product_id=product.product_id,
                    product_name=product.name,
                    vendor=product.vendor,
                    alert_type=alert_type,
                    alert_level=AlertLevel.EXPIRED,
                    days_remaining=days_remaining,
                    target_date=target_date,
                    message=(
                        f"EXPIRED: {product.name} ({product.vendor}) — "
                        f"{alert_type.value} was {abs(days_remaining)} days ago"
                    ),
                )
            ]

        # Find the most severe matching threshold
        matched = None
        for threshold in self._thresholds:
            if days_remaining <= threshold.days:
                matched = threshold
                break

        if not matched:
            return []

        return [
            Alert(
                product_id=product.product_id,
                product_name=product.name,
                vendor=product.vendor,
                alert_type=alert_type,
                alert_level=matched.level,
                days_remaining=days_remaining,
                target_date=target_date,
                message=(
                    f"{matched.level.value.upper()}: {product.name} ({product.vendor}) — "
                    f"{alert_type.value} in {days_remaining} days "
                    f"(within {matched.label} threshold)"
                ),
            )
        ]
