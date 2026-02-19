"""Settings route — configure Azure DNS, ACME, and alert settings."""

from flask import Blueprint, render_template, request, redirect, url_for, flash
from web.services import get_settings_store, get_azure_dns_service, get_audit_log

bp = Blueprint("settings", __name__)


@bp.route("/")
def index():
    store = get_settings_store()
    azure_dns = store.get_section("azure_dns")
    acme = store.get_section("acme")
    alerts = store.get_section("alerts")
    notify_email = store.get_section("notify_email")
    notify_slack = store.get_section("notify_slack")
    notify_webhook = store.get_section("notify_webhook")
    return render_template(
        "settings/index.html",
        azure_dns=azure_dns,
        acme=acme,
        alerts=alerts,
        notify_email=notify_email,
        notify_slack=notify_slack,
        notify_webhook=notify_webhook,
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
    get_audit_log().log("settings_change", "azure_dns", "Updated Azure DNS credentials")
    flash("Azure DNS settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/acme", methods=["POST"])
def save_acme():
    store = get_settings_store()
    store.set_section("acme", {
        "email": request.form.get("email", "").strip(),
        "staging": request.form.get("staging") == "on",
    })
    get_audit_log().log("settings_change", "acme", "Updated ACME/Let's Encrypt settings")
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
    get_audit_log().log("settings_change", "alerts", f"Warning days: {warning_days}")
    flash("Alert settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/notify-email", methods=["POST"])
def save_notify_email():
    store = get_settings_store()
    try:
        smtp_port = int(request.form.get("smtp_port", "587"))
    except ValueError:
        smtp_port = 587
    store.set_section("notify_email", {
        "enabled": request.form.get("email_enabled") == "on",
        "smtp_host": request.form.get("smtp_host", "").strip(),
        "smtp_port": smtp_port,
        "username": request.form.get("smtp_username", "").strip(),
        "password": request.form.get("smtp_password", "").strip(),
        "from_addr": request.form.get("smtp_from", "").strip(),
        "to_addrs": request.form.get("smtp_to", "").strip(),
        "use_tls": request.form.get("smtp_tls") == "on",
    })
    get_audit_log().log("settings_change", "notify_email", "Updated email notification settings")
    flash("Email notification settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/notify-slack", methods=["POST"])
def save_notify_slack():
    store = get_settings_store()
    store.set_section("notify_slack", {
        "enabled": request.form.get("slack_enabled") == "on",
        "webhook_url": request.form.get("slack_webhook_url", "").strip(),
    })
    get_audit_log().log("settings_change", "notify_slack", "Updated Slack notification settings")
    flash("Slack notification settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/notify-webhook", methods=["POST"])
def save_notify_webhook():
    store = get_settings_store()
    store.set_section("notify_webhook", {
        "enabled": request.form.get("webhook_enabled") == "on",
        "url": request.form.get("webhook_url", "").strip(),
        "headers": request.form.get("webhook_headers", "").strip(),
    })
    get_audit_log().log("settings_change", "notify_webhook", "Updated webhook notification settings")
    flash("Webhook notification settings saved.", "success")
    return redirect(url_for("settings.index"))


@bp.route("/test-notify/<channel>", methods=["POST"])
def test_notify(channel):
    from web.services import get_notification_dispatcher
    dispatcher = get_notification_dispatcher()
    success, message = dispatcher.test_channel(channel)
    flash(message, "success" if success else "danger")
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
