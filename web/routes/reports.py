"""Reports route — expiry, compliance, cost, dashboard reports."""

from flask import Blueprint, render_template, request
from web.services import get_registry, get_alert_engine, get_report_generator

bp = Blueprint("reports", __name__)


@bp.route("/")
def index():
    report_type = request.args.get("type", "expiry")
    days = int(request.args.get("days", 180))

    registry = get_registry()
    engine = get_alert_engine(registry)
    report_gen = get_report_generator(registry, engine)

    if report_type == "compliance":
        report = report_gen.compliance_report()
    elif report_type == "cost":
        report = report_gen.cost_report()
    elif report_type == "dashboard":
        report = report_gen.dashboard_report()
    else:
        report = report_gen.expiry_report(days_ahead=days)

    return render_template(
        "reports/index.html",
        report=report,
        report_type=report_type,
        days=days,
    )
