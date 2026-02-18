"""Settings route — configure Azure DNS, ACME, and alert settings."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.services import get_settings_store, get_azure_dns_service

bp = Blueprint("settings", __name__)


@bp.route("/")
def index():
    store = get_settings_store()
    azure_dns = store.get_section("azure_dns")
    acme = store.get_section("acme")
    alerts = store.get_section("alerts")
    return render_template(
        "settings/index.html",
        azure_dns=azure_dns,
        acme=acme,
        alerts=alerts,
    )


@bp.route("/azure-dns", methods=["POST"])
def save_azure_dns():
    store = get_settings_store()
    store.set_section("azure_dns", {
        "tenant_id": request.form.get("tenant_id", "").strip(),
        "client_id": request.form.get("client_id", "").strip(),
        "client_secret": request.form.get("client_secret", "").strip(),
        "subscription_id": request.form.get("subscription_id", "").strip(),
        "resource_group": request.form.get("resource_group", "").strip(),
    })
    flash("Azure DNS settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/acme", methods=["POST"])
def save_acme():
    store = get_settings_store()
    store.set_section("acme", {
        "email": request.form.get("email", "").strip(),
        "staging": request.form.get("staging") == "on",
    })
    flash("Let's Encrypt settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/alerts", methods=["POST"])
def save_alerts():
    store = get_settings_store()
    try:
        warning_days = int(request.form.get("ssl_warning_days", "30"))
    except ValueError:
        warning_days = 30
    store.set_section("alerts", {
        "ssl_expiry_enabled": request.form.get("ssl_expiry_enabled") == "on",
        "ssl_warning_days": warning_days,
    })
    flash("Alert settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/test-azure", methods=["POST"])
def test_azure():
    try:
        svc = get_azure_dns_service()
        if svc.is_configured():
            subs = svc.list_subscriptions()
            zones = svc.list_zones()
            sub_names = ", ".join(s["display_name"] for s in subs) if subs else "none"
            flash(
                f"Azure DNS connection successful — "
                f"{len(subs)} subscription(s) ({sub_names}), "
                f"{len(zones)} zone(s) found.",
                "success",
            )
        else:
            flash("Azure DNS credentials invalid or missing. Set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET.", "danger")
    except Exception as e:
        flash(f"Azure DNS connection failed: {e}", "danger")
    return redirect(url_for("settings.index"))
