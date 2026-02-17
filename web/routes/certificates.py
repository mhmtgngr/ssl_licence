"""Certificate routes — list managed certs, check remote domains."""

from datetime import datetime, timezone

from flask import Blueprint, render_template, request, flash, redirect, url_for
from web.services import get_certificate_manager, get_certificate_monitor, get_cert_checks_store

bp = Blueprint("certificates", __name__)


@bp.route("/")
def list_certs():
    mgr = get_certificate_manager()
    certs = mgr.list_certificates()
    return render_template("certificates/list.html", certs=certs)


@bp.route("/check", methods=["GET", "POST"])
def check_remote():
    results = []
    domains_input = ""
    if request.method == "POST":
        domains_input = request.form.get("domains", "")
        domains = [d.strip() for d in domains_input.replace(",", "\n").splitlines() if d.strip()]
        if domains:
            monitor = get_certificate_monitor()
            store = get_cert_checks_store()
            for domain in domains:
                status = monitor.check_remote(domain)
                entry = {
                    "domain": domain,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                }
                if status:
                    entry.update({
                        "status": "ok" if not status.is_expired else "expired",
                        "issuer": status.issuer,
                        "not_after": status.not_after.isoformat(),
                        "days_remaining": status.days_remaining,
                        "is_expired": status.is_expired,
                    })
                else:
                    entry.update({
                        "status": "fail",
                        "error": f"Could not connect to {domain}",
                    })
                store.add(entry)
                results.append({
                    "domain": domain,
                    "status": status,
                    "error": None if status else f"Could not connect to {domain}",
                })
        else:
            flash("Please enter at least one domain.", "warning")
    return render_template(
        "certificates/check.html",
        results=results,
        domains_input=domains_input,
    )


@bp.route("/history")
def check_history():
    store = get_cert_checks_store()
    checks = store.list_all()
    return render_template("certificates/history.html", checks=checks)


@bp.route("/history/clear", methods=["POST"])
def clear_history():
    store = get_cert_checks_store()
    store.clear()
    flash("Check history cleared.", "success")
    return redirect(url_for("certificates.check_history"))
