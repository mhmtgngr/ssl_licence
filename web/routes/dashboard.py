"""Dashboard route — home page with summary."""

from flask import Blueprint, render_template
from web.services import get_registry, get_alert_engine, get_domain_registry

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    registry = get_registry()
    engine = get_alert_engine(registry)
    summary = registry.summary()
    alert_summary = engine.get_dashboard_summary()
    critical_alerts = engine.get_critical_alerts()
    domain_summary = get_domain_registry().summary()
    return render_template(
        "dashboard.html",
        summary=summary,
        alert_summary=alert_summary,
        critical_alerts=critical_alerts,
        domain_summary=domain_summary,
    )
