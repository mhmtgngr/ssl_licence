"""Analysis route — AI-powered risk assessment and recommendations."""

from flask import Blueprint, render_template, request
from web.services import get_registry, get_analyzer

bp = Blueprint("analysis", __name__)


@bp.route("/")
def index():
    registry = get_registry()
    analyzer = get_analyzer(registry)
    section = request.args.get("section", "recommendations")

    recommendations = analyzer.get_recommendations()
    risk_assessments = analyzer.risk_assessment()
    cost_optimizations = analyzer.cost_optimization()
    upgrade_plans = analyzer.upgrade_plan()

    return render_template(
        "analysis/index.html",
        section=section,
        recommendations=recommendations,
        risk_assessments=risk_assessments,
        cost_optimizations=cost_optimizations,
        upgrade_plans=upgrade_plans,
    )
