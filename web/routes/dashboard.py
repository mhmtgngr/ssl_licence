"""Dashboard route — home page with summary and charts."""

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
    domain_registry = get_domain_registry()
    domain_summary = domain_registry.summary()

    # Chart data
    all_domains = domain_registry.list_all()

    ssl_chart_data = {
        "OK": sum(1 for d in all_domains if d.ssl_status == "ok"),
        "Warning": sum(1 for d in all_domains if d.ssl_status == "warning"),
        "Expired": sum(1 for d in all_domains if d.ssl_status == "expired"),
        "Fail": sum(1 for d in all_domains if d.ssl_status == "fail"),
    }

    expiry_chart_data = {"0-30d": 0, "31-60d": 0, "61-90d": 0, "91-180d": 0, "180d+": 0}
    for d in all_domains:
        if d.ssl_days_remaining is not None and d.ssl_days_remaining >= 0:
            days = d.ssl_days_remaining
            if days <= 30:
                expiry_chart_data["0-30d"] += 1
            elif days <= 60:
                expiry_chart_data["31-60d"] += 1
            elif days <= 90:
                expiry_chart_data["61-90d"] += 1
            elif days <= 180:
                expiry_chart_data["91-180d"] += 1
            else:
                expiry_chart_data["180d+"] += 1

    ca_counts = {}
    for d in all_domains:
        ca = d.ssl_ca_name or "Unknown"
        ca_counts[ca] = ca_counts.get(ca, 0) + 1
    ca_chart_data = dict(sorted(ca_counts.items(), key=lambda x: x[1], reverse=True)[:10])

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
        ssl_chart_data=ssl_chart_data,
        expiry_chart_data=expiry_chart_data,
        ca_chart_data=ca_chart_data,
        sort_field=sort_field,
        sort_order=sort_order,
    )
