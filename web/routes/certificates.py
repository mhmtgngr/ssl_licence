"""Certificate routes — list managed certs, check remote domains."""

from flask import Blueprint, render_template, request, flash
from web.services import get_certificate_manager, get_certificate_monitor

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
            for domain in domains:
                status = monitor.check_remote(domain)
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
