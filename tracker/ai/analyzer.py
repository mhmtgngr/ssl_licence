"""
AI-powered licence analysis and recommendation engine.

Uses heuristic rules and pattern matching to provide:
- Risk assessment for upcoming expirations
- Migration and upgrade recommendations
- Cost optimization suggestions
- Compliance gap analysis
- Lifecycle planning advice

This module works offline without external API calls,
using built-in knowledge of product lifecycle patterns.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from tracker.product import Product, ProductCategory, SupportStatus, LicenceType
from tracker.products.microsoft import MICROSOFT_LIFECYCLE
from tracker.products.network import NETWORK_PRODUCTS


@dataclass
class Recommendation:
    """A single AI recommendation."""

    product_id: str
    product_name: str
    category: str          # "upgrade", "renew", "migrate", "cost", "compliance"
    priority: str          # "critical", "high", "medium", "low"
    title: str
    description: str
    suggested_action: str
    estimated_impact: str  # "high", "medium", "low"


@dataclass
class RiskAssessment:
    """Risk assessment for a product."""

    product_id: str
    product_name: str
    risk_score: float      # 0.0 (no risk) to 10.0 (critical)
    risk_factors: list[str]
    mitigation: list[str]


class LicenceAnalyzer:
    """AI-powered analysis engine for licence and support management.

    Analyzes the product registry and produces:
    - Prioritized recommendations
    - Risk scores
    - Migration paths
    - Cost optimization insights

    Usage:
        analyzer = LicenceAnalyzer(registry)
        recommendations = analyzer.get_recommendations()
        risk_report = analyzer.risk_assessment()
        plan = analyzer.upgrade_plan()
    """

    def __init__(self, registry):
        self._registry = registry

    def get_recommendations(self) -> list[Recommendation]:
        """Generate all recommendations for the registry."""
        recs = []
        for product in self._registry.list_all():
            if not product.is_active:
                continue
            recs.extend(self._analyze_product(product))
        recs.sort(
            key=lambda r: {"critical": 0, "high": 1, "medium": 2, "low": 3}[
                r.priority
            ]
        )
        return recs

    def risk_assessment(self) -> list[RiskAssessment]:
        """Score risk for each product in the registry."""
        assessments = []
        for product in self._registry.list_all():
            if not product.is_active:
                continue
            assessments.append(self._assess_risk(product))
        assessments.sort(key=lambda a: -a.risk_score)
        return assessments

    def upgrade_plan(self) -> list[dict]:
        """Suggest an upgrade/migration plan for at-risk products."""
        plans = []
        for product in self._registry.list_all():
            if not product.is_active:
                continue
            plan = self._suggest_upgrade(product)
            if plan:
                plans.append(plan)
        plans.sort(key=lambda p: p.get("urgency_score", 0), reverse=True)
        return plans

    def cost_optimization(self) -> list[Recommendation]:
        """Identify cost saving opportunities."""
        recs = []
        products = self._registry.list_all()

        # Detect duplicates
        seen = {}
        for p in products:
            key = (p.name.lower(), p.vendor.lower())
            seen.setdefault(key, []).append(p)

        for key, group in seen.items():
            if len(group) > 1:
                total = sum(p.annual_cost for p in group)
                recs.append(Recommendation(
                    product_id=group[0].product_id,
                    product_name=group[0].name,
                    category="cost",
                    priority="medium",
                    title=f"Potential duplicate: {group[0].name}",
                    description=(
                        f"Found {len(group)} entries for {group[0].name} "
                        f"({group[0].vendor}). Combined cost: ${total:,.2f}/yr. "
                        f"Consider consolidating licences."
                    ),
                    suggested_action="Review and consolidate duplicate entries",
                    estimated_impact="medium",
                ))

        # Expired licences still costing money
        for p in products:
            if p.is_licence_expired() and p.annual_cost > 0:
                recs.append(Recommendation(
                    product_id=p.product_id,
                    product_name=p.name,
                    category="cost",
                    priority="high",
                    title=f"Cost on expired licence: {p.name}",
                    description=(
                        f"Paying ${p.annual_cost:,.2f}/yr for {p.name} "
                        f"but the licence is expired. Either renew or decommission."
                    ),
                    suggested_action="Renew or decommission to stop unnecessary costs",
                    estimated_impact="high",
                ))

        # EOS products
        for p in products:
            status = p.support_status()
            if status in (SupportStatus.END_OF_SUPPORT, SupportStatus.END_OF_LIFE):
                if p.annual_cost > 0:
                    recs.append(Recommendation(
                        product_id=p.product_id,
                        product_name=p.name,
                        category="cost",
                        priority="medium",
                        title=f"Spending on unsupported product: {p.name}",
                        description=(
                            f"{p.name} ({p.vendor}) has reached {status.value}. "
                            f"Current annual cost: ${p.annual_cost:,.2f}. "
                            f"Migrating could avoid risk and reduce spend."
                        ),
                        suggested_action="Plan migration to supported version",
                        estimated_impact="high",
                    ))

        return recs

    def generate_full_report(self) -> dict:
        """Generate a comprehensive AI analysis report."""
        recommendations = self.get_recommendations()
        risks = self.risk_assessment()
        upgrades = self.upgrade_plan()
        cost_recs = self.cost_optimization()

        high_risk = [r for r in risks if r.risk_score >= 7.0]

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "total_recommendations": len(recommendations),
                "critical_recommendations": sum(
                    1 for r in recommendations if r.priority == "critical"
                ),
                "high_risk_products": len(high_risk),
                "upgrade_candidates": len(upgrades),
                "cost_optimizations": len(cost_recs),
            },
            "recommendations": [
                {
                    "product": r.product_name,
                    "category": r.category,
                    "priority": r.priority,
                    "title": r.title,
                    "description": r.description,
                    "action": r.suggested_action,
                }
                for r in recommendations[:20]
            ],
            "risk_assessment": [
                {
                    "product": r.product_name,
                    "risk_score": r.risk_score,
                    "factors": r.risk_factors,
                    "mitigation": r.mitigation,
                }
                for r in risks[:20]
            ],
            "upgrade_plan": upgrades[:20],
            "cost_optimizations": [
                {
                    "product": r.product_name,
                    "title": r.title,
                    "description": r.description,
                    "action": r.suggested_action,
                }
                for r in cost_recs
            ],
        }

    # ---- Internal analysis methods ----

    def _analyze_product(self, product: Product) -> list[Recommendation]:
        """Analyze a single product and produce recommendations."""
        recs = []

        # Licence expiry
        days_to_expiry = product.days_until_licence_expiry()
        if days_to_expiry is not None:
            if days_to_expiry < 0:
                recs.append(Recommendation(
                    product_id=product.product_id,
                    product_name=product.name,
                    category="renew",
                    priority="critical",
                    title=f"EXPIRED: {product.name} licence",
                    description=(
                        f"{product.name} ({product.vendor} {product.version}) "
                        f"licence expired {abs(days_to_expiry)} days ago. "
                        f"Immediate renewal required to maintain compliance."
                    ),
                    suggested_action="Renew licence immediately or decommission",
                    estimated_impact="high",
                ))
            elif days_to_expiry <= 7:
                recs.append(Recommendation(
                    product_id=product.product_id,
                    product_name=product.name,
                    category="renew",
                    priority="critical",
                    title=f"Licence expires this week: {product.name}",
                    description=(
                        f"{product.name} licence expires in {days_to_expiry} days. "
                        f"Urgent renewal needed."
                    ),
                    suggested_action="Initiate emergency licence renewal",
                    estimated_impact="high",
                ))
            elif days_to_expiry <= 30:
                recs.append(Recommendation(
                    product_id=product.product_id,
                    product_name=product.name,
                    category="renew",
                    priority="high",
                    title=f"Licence expiring soon: {product.name}",
                    description=(
                        f"{product.name} licence expires in {days_to_expiry} days. "
                        f"Start renewal process."
                    ),
                    suggested_action="Begin licence renewal process with vendor",
                    estimated_impact="high",
                ))
            elif days_to_expiry <= 90:
                recs.append(Recommendation(
                    product_id=product.product_id,
                    product_name=product.name,
                    category="renew",
                    priority="medium",
                    title=f"Plan licence renewal: {product.name}",
                    description=(
                        f"{product.name} licence expires in {days_to_expiry} days. "
                        f"Plan renewal and budget accordingly."
                    ),
                    suggested_action="Add to renewal pipeline, confirm budget",
                    estimated_impact="medium",
                ))

        # Support status
        status = product.support_status()
        if status == SupportStatus.END_OF_LIFE:
            recs.append(Recommendation(
                product_id=product.product_id,
                product_name=product.name,
                category="migrate",
                priority="critical",
                title=f"End of Life: {product.name} {product.version}",
                description=(
                    f"{product.name} {product.version} ({product.vendor}) "
                    f"has reached end of life. No patches, no security updates. "
                    f"This is a significant security and compliance risk."
                ),
                suggested_action="Migrate to supported version immediately",
                estimated_impact="high",
            ))
        elif status == SupportStatus.END_OF_SUPPORT:
            recs.append(Recommendation(
                product_id=product.product_id,
                product_name=product.name,
                category="upgrade",
                priority="high",
                title=f"End of Support: {product.name} {product.version}",
                description=(
                    f"{product.name} {product.version} support has ended. "
                    f"Security patches are no longer provided."
                ),
                suggested_action="Plan upgrade to a supported version",
                estimated_impact="high",
            ))
        elif status == SupportStatus.EXTENDED:
            days_to_end = product.days_until_support_end()
            if days_to_end is not None and days_to_end <= 180:
                recs.append(Recommendation(
                    product_id=product.product_id,
                    product_name=product.name,
                    category="upgrade",
                    priority="medium",
                    title=f"Extended support ending: {product.name} {product.version}",
                    description=(
                        f"{product.name} {product.version} extended support "
                        f"ends in {days_to_end} days. Plan migration."
                    ),
                    suggested_action="Begin planning migration to newer version",
                    estimated_impact="medium",
                ))

        return recs

    def _assess_risk(self, product: Product) -> RiskAssessment:
        """Calculate risk score for a product."""
        score = 0.0
        factors = []
        mitigation = []

        # Licence expiry risk
        days = product.days_until_licence_expiry()
        if days is not None:
            if days < 0:
                score += 4.0
                factors.append(f"Licence expired {abs(days)} days ago")
                mitigation.append("Renew licence immediately")
            elif days <= 7:
                score += 3.0
                factors.append(f"Licence expires in {days} days")
                mitigation.append("Urgent renewal needed")
            elif days <= 30:
                score += 2.0
                factors.append(f"Licence expires in {days} days")
                mitigation.append("Initiate renewal process")
            elif days <= 90:
                score += 1.0
                factors.append(f"Licence expires in {days} days")

        # Support status risk
        status = product.support_status()
        if status == SupportStatus.END_OF_LIFE:
            score += 3.0
            factors.append("Product has reached end of life")
            mitigation.append("Migrate to supported version")
        elif status == SupportStatus.END_OF_SUPPORT:
            score += 2.5
            factors.append("Product support has ended")
            mitigation.append("Plan upgrade to supported version")
        elif status == SupportStatus.EXTENDED:
            score += 1.0
            factors.append("Running on extended support")

        # Environment risk multiplier
        if product.environment == "production":
            score *= 1.2
            if score > 0:
                factors.append("Production environment (higher impact)")
        elif product.environment == "dr":
            score *= 1.1

        # Missing information risk
        if not product.owner:
            score += 0.5
            factors.append("No owner assigned")
            mitigation.append("Assign a responsible owner")

        if (
            not product.licence_expiry
            and product.licence_type.value
            not in ("perpetual", "open_source", "pay_as_you_go")
        ):
            score += 0.5
            factors.append("No licence expiry date tracked")
            mitigation.append("Determine and set licence expiry date")

        score = min(score, 10.0)

        return RiskAssessment(
            product_id=product.product_id,
            product_name=product.name,
            risk_score=round(score, 1),
            risk_factors=factors,
            mitigation=mitigation,
        )

    def _suggest_upgrade(self, product: Product) -> Optional[dict]:
        """Suggest upgrade path for a product if needed."""
        status = product.support_status()
        days_to_support_end = product.days_until_support_end()

        needs_upgrade = (
            status in (SupportStatus.END_OF_SUPPORT, SupportStatus.END_OF_LIFE)
            or (days_to_support_end is not None and days_to_support_end <= 180)
        )

        if not needs_upgrade:
            return None

        # Try to find a newer version from catalogues
        upgrade_target = self._find_upgrade_target(product)

        urgency = 10.0 if status == SupportStatus.END_OF_LIFE else 7.0
        if days_to_support_end is not None and days_to_support_end > 0:
            urgency = max(1.0, 10.0 - (days_to_support_end / 30))

        plan = {
            "product_id": product.product_id,
            "product_name": product.name,
            "vendor": product.vendor,
            "current_version": product.version,
            "current_status": status.value,
            "urgency_score": round(urgency, 1),
            "recommended_action": "migrate" if status == SupportStatus.END_OF_LIFE else "upgrade",
        }

        if upgrade_target:
            plan["suggested_target"] = upgrade_target
        else:
            plan["suggested_target"] = "Contact vendor for latest supported version"

        return plan

    def _find_upgrade_target(self, product: Product) -> Optional[str]:
        """Try to determine the newest available version from built-in catalogues."""
        vendor_lower = product.vendor.lower()
        name_lower = product.name.lower()

        # Check Microsoft catalogue
        if "microsoft" in vendor_lower or product.category == ProductCategory.MICROSOFT:
            for ms_product, versions in MICROSOFT_LIFECYCLE.items():
                if ms_product.lower() in name_lower or name_lower in ms_product.lower():
                    sorted_versions = list(versions.keys())
                    if sorted_versions:
                        latest = sorted_versions[-1]
                        if latest != product.version:
                            return f"{ms_product} {latest}"

        # Check network catalogue
        for vendor, products in NETWORK_PRODUCTS.items():
            if vendor.lower() in vendor_lower:
                for prod_name, versions in products.items():
                    if prod_name.lower() in name_lower:
                        sorted_versions = list(versions.keys())
                        if sorted_versions:
                            latest = sorted_versions[-1]
                            if latest != product.version:
                                return f"{prod_name} {latest}"

        return None
