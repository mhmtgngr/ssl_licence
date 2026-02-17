"""Dashboard route — home page with summary."""

from flask import Blueprint, render_template
from web.services import get_registry, get_alert_engine

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    registry = get_registry()
    engine = get_alert_engine(registry)
    summary = registry.summary()
    alert_summary = engine.get_dashboard_summary()
    critical_alerts = engine.get_critical_alerts()
    return render_template(
        "dashboard.html",
        summary=summary,
        alert_summary=alert_summary,
        critical_alerts=critical_alerts,
    )
