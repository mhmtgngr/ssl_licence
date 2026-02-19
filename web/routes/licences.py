"""Licence routes — list, issue, validate, revoke."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.services import get_licence_manager

bp = Blueprint("licences", __name__)


@bp.route("/")
def list_licences():
    mgr = get_licence_manager()
    licences = mgr.list_all()
    active_count = len(mgr.list_active())

    from flask import request
    from web.sort_utils import sort_items
    licences, sort_field, sort_order = sort_items(
        licences,
        request.args.get("sort"),
        request.args.get("order"),
        {
            "type": lambda l: (l.get("licence_type") or "").lower(),
            "issued_to": lambda l: (l.get("issued_to") or "").lower(),
            "issued_at": lambda l: l.get("issued_at") or "",
            "expires_at": lambda l: l.get("expires_at") or "9999",
            "status": lambda l: (1 if l.get("revoked") else 0),
        },
    )

    return render_template(
        "licences/list.html",
        licences=licences,
        active_count=active_count,
        sort_field=sort_field,
        sort_order=sort_order,
    )


@bp.route("/issue", methods=["GET", "POST"])
def issue():
    if request.method == "POST":
        issued_to = request.form.get("issued_to", "").strip()
        licence_type = request.form.get("licence_type", "").strip()
        if not issued_to or not licence_type:
            flash("Licence type and Issued To are required.", "danger")
            return redirect(url_for("licences.issue"))

        mgr = get_licence_manager()
        valid_days = request.form.get("valid_days")
        valid_days = int(valid_days) if valid_days else None
        features = [f.strip() for f in request.form.get("features", "").split(",") if f.strip()]

        try:
            licence = mgr.issue(
                licence_type=licence_type,
                issued_to=issued_to,
                valid_days=valid_days,
                features=features or None,
                max_users=int(request.form.get("max_users", 1)),
            )
            flash(f"Licence issued: {licence.key}", "success")
        except ValueError as e:
            flash(f"Error: {e}", "danger")

        return redirect(url_for("licences.list_licences"))
    return render_template("licences/issue.html")


@bp.route("/validate", methods=["GET", "POST"])
def validate():
    result = None
    key = ""
    if request.method == "POST":
        key = request.form.get("licence_key", "").strip()
        if not key:
            flash("Please enter a licence key.", "danger")
            return redirect(url_for("licences.validate"))
        mgr = get_licence_manager()
        result = mgr.validate(key)
    return render_template("licences/validate.html", result=result, key=key)


@bp.route("/revoke", methods=["POST"])
def revoke():
    key = request.form.get("licence_key", "")
    mgr = get_licence_manager()
    if mgr.revoke(key):
        flash(f"Licence revoked: {key}", "success")
    else:
        flash(f"Licence not found: {key}", "danger")
    return redirect(url_for("licences.list_licences"))
