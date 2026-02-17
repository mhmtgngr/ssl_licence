"""Alerts route — list alerts with severity filtering and acknowledgment."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.services import get_registry, get_alert_engine
from tracker.alert_engine import AlertLevel, AlertType

bp = Blueprint("alerts", __name__)


@bp.route("/")
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

    return render_template(
        "alerts/list.html",
        alerts=alerts,
        summary=summary,
        filters={"level": level_filter, "type": type_filter, "vendor": vendor_filter},
    )


@bp.route("/acknowledge", methods=["POST"])
def acknowledge():
    product_id = request.form.get("product_id", "")
    alert_type = request.form.get("alert_type", "")
    if not product_id or not alert_type:
        flash("Invalid alert reference.", "danger")
        return redirect(url_for("alerts.list_alerts"))

    registry = get_registry()
    engine = get_alert_engine(registry)
    if engine.acknowledge_alert(product_id, alert_type):
        flash("Alert acknowledged.", "success")
    else:
        flash("Alert not found.", "danger")
    return redirect(url_for("alerts.list_alerts"))
