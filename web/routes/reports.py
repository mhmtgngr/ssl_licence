"""Reports route — expiry, compliance, cost, dashboard, daily reports."""

import json
from pathlib import Path

from flask import Blueprint, render_template, request
from web.services import get_registry, get_alert_engine, get_report_generator, PROJECT_ROOT

bp = Blueprint("reports", __name__)

DAILY_REPORTS_DIR = PROJECT_ROOT / "data" / "daily_reports"


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


@bp.route("/daily")
def daily():
    """View daily health check reports."""
    reports = []
    if DAILY_REPORTS_DIR.exists():
        for f in sorted(DAILY_REPORTS_DIR.glob("*.json"), reverse=True):
            data = json.loads(f.read_text())
            data["_file"] = f.stem
            reports.append(data)

    selected = request.args.get("date")
    detail = None
    if selected:
        report_file = DAILY_REPORTS_DIR / f"{selected}.json"
        if report_file.exists():
            detail = json.loads(report_file.read_text())

    return render_template("reports/daily.html", reports=reports, detail=detail, selected=selected)
