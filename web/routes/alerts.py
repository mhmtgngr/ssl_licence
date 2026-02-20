"""Alerts route — list alerts with severity filtering and acknowledgment."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.auth import login_required, role_required, current_username
from web.services import get_registry, get_alert_engine, get_audit_log
from tracker.alert_engine import AlertLevel, AlertType

bp = Blueprint("alerts", __name__)


@bp.route("/")
@login_required
def list_alerts():
    registry = get_registry()
    engine = get_alert_engine(registry)

    level_filter = request.args.get("level")
    type_filter = request.args.get("type")
    vendor_filter = request.args.get("vendor")

    level = AlertLevel(level_filter) if level_filter else None
    alert_type = AlertType(type_filter) if type_filter else None

    alerts = engine.get_alerts(
        level=level, alert_type=alert_type,
        vendor=vendor_filter or None,
    )
    summary = engine.get_dashboard_summary()

    from web.sort_utils import sort_items
    alerts, sort_field, sort_order = sort_items(
        alerts,
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
        "alerts/list.html",
        alerts=alerts,
        summary=summary,
        filters={"level": level_filter, "type": type_filter, "vendor": vendor_filter},
        sort_field=sort_field,
        sort_order=sort_order,
    )


@bp.route("/acknowledge", methods=["POST"])
@role_required("admin", "editor")
def acknowledge():
    product_id = request.form.get("product_id", "")
    alert_type = request.form.get("alert_type", "")
    if not product_id or not alert_type:
        flash("Invalid alert reference.", "danger")
        return redirect(url_for("alerts.list_alerts"))

    registry = get_registry()
    engine = get_alert_engine(registry)
    if engine.acknowledge_alert(product_id, alert_type):
        get_audit_log().log("alert_acknowledge", product_id, f"Type: {alert_type}", user=current_username())
        flash("Alert acknowledged.", "success")
    else:
        flash("Alert not found.", "danger")
    return redirect(url_for("alerts.list_alerts"))
