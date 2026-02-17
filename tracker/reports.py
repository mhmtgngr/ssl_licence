"""
Report generation for product licence tracking.

Generates JSON, CSV, and formatted text reports covering:
- Overall dashboard / summary
- Expiry timeline
- Compliance status
- Cost analysis
"""

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from tracker.product import ProductCategory, SupportStatus


class ReportGenerator:
    """Generate reports from registry and alert data."""

    def __init__(self, registry, alert_engine):
        self._registry = registry
        self._alerts = alert_engine

    def dashboard_report(self) -> dict:
        """Full dashboard report combining registry summary and alerts."""
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "registry": self._registry.summary(),
            "alerts": self._alerts.get_dashboard_summary(),
        }

    def expiry_report(self, days_ahead: int = 180) -> dict:
        """Report of all items expiring within N days."""
        licence_expiring = self._registry.expiring_within_days(days_ahead)
        support_ending = self._registry.support_ending_within_days(days_ahead)
        already_expired = self._registry.already_expired()
        already_eos = self._registry.already_end_of_support()

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "days_ahead": days_ahead,
            "licence_expiring": [p.to_dict() for p in licence_expiring],
            "support_ending": [p.to_dict() for p in support_ending],
            "already_expired_licences": [p.to_dict() for p in already_expired],
            "already_end_of_support": [p.to_dict() for p in already_eos],
            "totals": {
                "licence_expiring": len(licence_expiring),
                "support_ending": len(support_ending),
                "already_expired": len(already_expired),
                "already_eos": len(already_eos),
            },
        }

    def compliance_report(self) -> dict:
        """Compliance report — flags issues that need attention."""
        products = self._registry.list_all()
        issues = []

        for p in products:
            if not p.is_active:
                continue

            # Expired licence
            if p.is_licence_expired():
                issues.append({
                    "product_id": p.product_id,
                    "name": p.name,
                    "vendor": p.vendor,
                    "issue": "expired_licence",
                    "severity": "critical",
                    "detail": (
                        f"Licence expired {abs(p.days_until_licence_expiry())} days ago"
                    ),
                })

            # End of support
            if p.support_status() in (
                SupportStatus.END_OF_SUPPORT,
                SupportStatus.END_OF_LIFE,
            ):
                issues.append({
                    "product_id": p.product_id,
                    "name": p.name,
                    "vendor": p.vendor,
                    "issue": "end_of_support",
                    "severity": "high",
                    "detail": f"Status: {p.support_status().value}",
                })

            # Missing dates
            if not p.licence_expiry and p.licence_type.value not in (
                "perpetual", "open_source", "pay_as_you_go"
            ):
                issues.append({
                    "product_id": p.product_id,
                    "name": p.name,
                    "vendor": p.vendor,
                    "issue": "missing_expiry_date",
                    "severity": "medium",
                    "detail": "No licence expiry date set for non-perpetual licence",
                })

            # Missing owner
            if not p.owner:
                issues.append({
                    "product_id": p.product_id,
                    "name": p.name,
                    "vendor": p.vendor,
                    "issue": "no_owner_assigned",
                    "severity": "low",
                    "detail": "No owner assigned to this product",
                })

        issues.sort(
            key=lambda i: {"critical": 0, "high": 1, "medium": 2, "low": 3}[
                i["severity"]
            ]
        )

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_issues": len(issues),
            "by_severity": {
                "critical": sum(1 for i in issues if i["severity"] == "critical"),
                "high": sum(1 for i in issues if i["severity"] == "high"),
                "medium": sum(1 for i in issues if i["severity"] == "medium"),
                "low": sum(1 for i in issues if i["severity"] == "low"),
            },
            "issues": issues,
        }

    def cost_report(self) -> dict:
        """Detailed cost analysis report."""
        products = self._registry.list_all()
        active = [p for p in products if p.is_active]

        total = sum(p.annual_cost for p in active)
        expired_cost = sum(
            p.annual_cost for p in active if p.is_licence_expired()
        )
        eos_cost = sum(
            p.annual_cost
            for p in active
            if p.support_status()
            in (SupportStatus.END_OF_SUPPORT, SupportStatus.END_OF_LIFE)
        )

        by_vendor = {}
        for p in active:
            by_vendor.setdefault(p.vendor, {"count": 0, "cost": 0})
            by_vendor[p.vendor]["count"] += 1
            by_vendor[p.vendor]["cost"] += p.annual_cost

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "total_annual_cost": total,
            "cost_on_expired_licences": expired_cost,
            "cost_on_eos_products": eos_cost,
            "potential_savings": expired_cost + eos_cost,
            "by_vendor": by_vendor,
        }

    def export_json(self, report: dict, path: str) -> None:
        """Export any report to JSON file."""
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(report, indent=2, default=str))

    def export_csv(self, path: str) -> None:
        """Export all products to CSV."""
        products = self._registry.list_all()
        if not products:
            return

        output = io.StringIO()
        fieldnames = list(products[0].to_dict().keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for p in products:
            writer.writerow(p.to_dict())

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(output.getvalue())

    def format_text_summary(self) -> str:
        """Generate a human-readable text summary."""
        summary = self._registry.summary()
        alerts = self._alerts.get_dashboard_summary()

        lines = [
            "=" * 60,
            "  PRODUCT LICENCE & SUPPORT TRACKING DASHBOARD",
            f"  Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            "=" * 60,
            "",
            f"  Total Products:     {summary['total_products']}",
            f"  Active Products:    {summary['active_products']}",
            f"  Annual Cost:        ${summary['total_annual_cost']:,.2f}",
            "",
            "  --- ALERTS ---",
            f"  Total Alerts:       {alerts.get('total_alerts', 0)}",
        ]

        for level, count in alerts.get("by_level", {}).items():
            lines.append(f"    {level.upper():12s}: {count}")

        lines.extend([
            "",
            "  --- BY STATUS ---",
        ])
        for status, count in summary.get("by_status", {}).items():
            lines.append(f"    {status:20s}: {count}")

        lines.extend([
            "",
            "  --- URGENT ITEMS ---",
        ])
        for item in alerts.get("critical_items", [])[:5]:
            lines.append(f"    [{item['alert_level'].upper()}] {item['message']}")

        lines.append("=" * 60)
        return "\n".join(lines)
