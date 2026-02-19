"""Dashboard route — home page with summary."""

from flask import Blueprint, render_template, request
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

    from web.sort_utils import sort_items
    critical_alerts, sort_field, sort_order = sort_items(
        critical_alerts,
        request.args.get("sort"),
        request.args.get("order"),
        {
            "level": lambda a: a.alert_level.value,
            "product": lambda a: (a.product_name or "").lower(),
            "vendor": lambda a: (a.vendor or "").lower(),
            "type": lambda a: a.alert_type.value,
            "days": lambda a: a.days_remaining if a.days_remaining is not None else 999999,
            "date": lambda a: a.target_date,
        },
    )

    return render_template(
        "dashboard.html",
        summary=summary,
        alert_summary=alert_summary,
        critical_alerts=critical_alerts,
        domain_summary=domain_summary,
        sort_field=sort_field,
        sort_order=sort_order,
    )
