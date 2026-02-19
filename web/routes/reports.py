"""Reports route — expiry, compliance, cost, dashboard, daily reports."""

import json
from pathlib import Path

from flask import Blueprint, render_template, request
from web.services import get_registry, get_alert_engine, get_report_generator, _DATA_DIR
from web.sort_utils import sort_items

bp = Blueprint("reports", __name__)

DAILY_REPORTS_DIR = _DATA_DIR / "daily_reports"


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

    sort_f = request.args.get("sort")
    sort_o = request.args.get("order")

    # Sort report sub-lists in place
    if report_type == "expiry":
        if hasattr(report, "licence_expiring") and report.licence_expiring:
            report.licence_expiring, _, _ = sort_items(
                report.licence_expiring, sort_f, sort_o,
                {
                    "name": lambda p: (p.get("name") or getattr(p, "name", "") or "").lower(),
                    "vendor": lambda p: (p.get("vendor") or getattr(p, "vendor", "") or "").lower(),
                    "version": lambda p: (p.get("version") or getattr(p, "version", "") or "").lower(),
                    "days_left": lambda p: p.get("days_until_licence_expiry") or getattr(p, "days_until_licence_expiry", 999999) or 999999,
                    "expiry": lambda p: str(p.get("licence_expiry") or getattr(p, "licence_expiry", "") or ""),
                },
            )
        if hasattr(report, "already_expired_licences") and report.already_expired_licences:
            report.already_expired_licences, _, _ = sort_items(
                report.already_expired_licences, sort_f, sort_o,
                {
                    "name": lambda p: (p.get("name") or getattr(p, "name", "") or "").lower(),
                    "vendor": lambda p: (p.get("vendor") or getattr(p, "vendor", "") or "").lower(),
                    "version": lambda p: (p.get("version") or getattr(p, "version", "") or "").lower(),
                    "expiry": lambda p: str(p.get("licence_expiry") or getattr(p, "licence_expiry", "") or ""),
                },
            )
    elif report_type == "compliance" and hasattr(report, "issues") and report.issues:
        report.issues, _, _ = sort_items(
            report.issues, sort_f, sort_o,
            {
                "severity": lambda i: i.get("severity") or getattr(i, "severity", "") or "",
                "product": lambda i: (i.get("name") or getattr(i, "name", "") or "").lower(),
                "vendor": lambda i: (i.get("vendor") or getattr(i, "vendor", "") or "").lower(),
                "issue": lambda i: (i.get("issue") or getattr(i, "issue", "") or "").lower(),
            },
        )
    elif report_type == "cost" and hasattr(report, "by_vendor") and report.by_vendor:
        vendor_items = list(report.by_vendor.items())
        vendor_items, _, _ = sort_items(
            vendor_items, sort_f, sort_o,
            {
                "vendor": lambda v: v[0].lower(),
                "products": lambda v: v[1].get("count", 0) if isinstance(v[1], dict) else getattr(v[1], "count", 0),
                "cost": lambda v: v[1].get("cost", 0) if isinstance(v[1], dict) else getattr(v[1], "cost", 0),
            },
        )
        from collections import OrderedDict
        report.by_vendor = OrderedDict(vendor_items)

    sort_field = sort_f or ""
    sort_order = sort_o if sort_o in ("asc", "desc") else "asc"

    return render_template(
        "reports/index.html",
        report=report,
        report_type=report_type,
        days=days,
        sort_field=sort_field,
        sort_order=sort_order,
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

    # Sort the overview table (when no date selected)
    sort_field = request.args.get("sort", "")
    sort_order = request.args.get("order", "asc")
    if not selected and reports:
        reports, sort_field, sort_order = sort_items(
            reports, sort_field, sort_order,
            {
                "date": lambda r: r.get("_file", ""),
                "certs": lambda r: r.get("certificates", {}).get("ok", 0),
                "domains": lambda r: r.get("domains", {}).get("ok", 0) if r.get("domains") else 0,
                "licences": lambda r: r.get("licences", {}).get("ok", 0),
                "alerts": lambda r: r.get("product_alerts", {}).get("total", 0),
            },
        )

    return render_template(
        "reports/daily.html", reports=reports, detail=detail,
        selected=selected, sort_field=sort_field, sort_order=sort_order,
    )
