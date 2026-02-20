"""Certificate routes — list managed certs, check remote domains."""

from datetime import datetime, timezone

from flask import Blueprint, render_template, request, flash, redirect, url_for
from web.auth import login_required, role_required
from web.services import (
    get_certificate_manager,
    get_certificate_monitor,
    get_cert_checks_store,
    get_chain_validator,
    get_ocsp_checker,
)

bp = Blueprint("certificates", __name__)


@bp.route("/")
@login_required
def list_certs():
    mgr = get_certificate_manager()
    certs = mgr.list_certificates()

    from flask import request as req
    from web.sort_utils import sort_items
    certs, sort_field, sort_order = sort_items(
        certs,
        req.args.get("sort"),
        req.args.get("order"),
        {
            "name": lambda c: (c.name or "").lower(),
            "path": lambda c: (c.path or "").lower(),
            "expiry": lambda c: str(c.expiry or ""),
        },
    )
    return render_template(
        "certificates/list.html", certs=certs,
        sort_field=sort_field, sort_order=sort_order,
    )


@bp.route("/check", methods=["GET", "POST"])
@login_required
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
@login_required
def check_history():
    store = get_cert_checks_store()
    checks = store.list_all()

    from flask import request as req
    from web.sort_utils import sort_items
    checks, sort_field, sort_order = sort_items(
        checks,
        req.args.get("sort"),
        req.args.get("order"),
        {
            "domain": lambda c: (c.get("domain") or "").lower(),
            "status": lambda c: c.get("status") or "",
            "issuer": lambda c: (c.get("issuer") or "").lower(),
            "expiry": lambda c: c.get("not_after") or "",
            "days": lambda c: c.get("days_remaining") if c.get("days_remaining") is not None else 999999,
            "checked": lambda c: c.get("checked_at") or "",
        },
    )
    return render_template(
        "certificates/history.html", checks=checks,
        sort_field=sort_field, sort_order=sort_order,
    )


@bp.route("/history/clear", methods=["GET", "POST"])
@role_required("admin", "editor")
def clear_history():
    if request.method == "GET":
        return redirect(url_for("certificates.list_certs"))
    store = get_cert_checks_store()
    store.clear()
    flash("Check history cleared.", "success")
    return redirect(url_for("certificates.check_history"))


@bp.route("/chain-check", methods=["GET", "POST"])
@login_required
def chain_check():
    """Validate certificate chain for a domain."""
    result = None
    domain = ""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if domain:
            validator = get_chain_validator()
            result = validator.validate(domain)
        else:
            flash("Please enter a domain.", "warning")
    return render_template("certificates/chain_check.html", result=result, domain=domain)


@bp.route("/ocsp-check", methods=["GET", "POST"])
@login_required
def ocsp_check():
    """Check OCSP revocation status for a domain."""
    result = None
    domain = ""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        if domain:
            checker = get_ocsp_checker()
            result = checker.check(domain)
        else:
            flash("Please enter a domain.", "warning")
    return render_template("certificates/ocsp_check.html", result=result, domain=domain)
