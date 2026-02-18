"""Domain management routes — CRUD, DNS discovery, SSL checks, SOA/hosting info."""

from datetime import datetime, timezone

from flask import Blueprint, render_template, request, redirect, url_for, flash

from web.services import (
    get_domain_registry,
    get_dns_service,
    get_certificate_monitor,
    get_acme_service,
    get_azure_dns_service,
    get_zone_transfer_service,
)
from tracker.domain import Domain, DomainStatus, DomainType

bp = Blueprint("domains", __name__)


def _update_domain_ssl(domain: Domain, monitor) -> None:
    """Check SSL for a domain and update its fields."""
    status = monitor.check_remote(domain.hostname)
    if status:
        domain.ssl_issuer = status.issuer
        domain.ssl_expiry = status.not_after
        domain.ssl_days_remaining = status.days_remaining
        if status.is_expired:
            domain.ssl_status = "expired"
            domain.status = DomainStatus.EXPIRED
        elif status.days_remaining <= domain.warning_days:
            domain.ssl_status = "warning"
            domain.status = DomainStatus.EXPIRING
        else:
            domain.ssl_status = "ok"
            domain.status = DomainStatus.ACTIVE
    else:
        domain.ssl_status = "fail"
        domain.status = DomainStatus.UNREACHABLE


def _update_domain_dns(domain: Domain, dns) -> None:
    """Run full DNS lookup and update domain fields."""
    info = dns.full_lookup(domain.hostname)
    domain.ip_address = info["ip_address"]
    domain.nameservers = info["nameservers"]
    domain.soa_primary_ns = info["soa_primary_ns"]
    domain.soa_admin_email = info["soa_admin_email"]
    domain.soa_serial = info["soa_serial"]
    domain.soa_refresh = info["soa_refresh"]
    domain.soa_retry = info["soa_retry"]
    domain.soa_expire = info["soa_expire"]
    domain.soa_minimum_ttl = info["soa_minimum_ttl"]
    domain.reverse_dns = info["reverse_dns"]
    domain.hosting_provider = info["hosting_provider"]
    domain.registrar = info.get("registrar", "")
    domain.registration_expiry = info.get("registration_expiry")
    domain.registration_days_remaining = info.get("registration_days_remaining")
    domain.domain_created_date = info.get("domain_created_date")
    domain.dnssec = info.get("dnssec", "")


@bp.route("/")
def list_domains():
    registry = get_domain_registry()
    domains = registry.list_all()

    # Filters
    status_filter = request.args.get("status", "")
    type_filter = request.args.get("type", "")
    parent_filter = request.args.get("parent", "")
    q = request.args.get("q", "").strip().lower()

    if status_filter:
        try:
            domains = [d for d in domains if d.status == DomainStatus(status_filter)]
        except ValueError:
            pass
    if type_filter:
        try:
            domains = [d for d in domains if d.domain_type == DomainType(type_filter)]
        except ValueError:
            pass
    if parent_filter:
        domains = [d for d in domains if d.parent_domain.lower() == parent_filter.lower()]
    if q:
        domains = [
            d for d in domains
            if q in d.hostname.lower() or q in d.ip_address.lower()
            or q in d.hosting_provider.lower()
        ]

    # Get unique parent domains for filter dropdown
    all_domains = registry.list_all()
    parents = sorted(set(d.parent_domain for d in all_domains if d.parent_domain))
    summary = registry.summary()

    return render_template(
        "domains/list.html",
        domains=domains,
        summary=summary,
        parents=parents,
        status_filter=status_filter,
        type_filter=type_filter,
        parent_filter=parent_filter,
        q=q,
    )


@bp.route("/add", methods=["GET", "POST"])
def add_domain():
    if request.method == "POST":
        hostname = request.form.get("hostname", "").strip().lower()
        if not hostname:
            flash("Hostname is required.", "danger")
            return redirect(url_for("domains.add_domain"))

        registry = get_domain_registry()
        if registry.get_by_hostname(hostname):
            flash(f"Domain {hostname} is already tracked.", "warning")
            return redirect(url_for("domains.list_domains"))

        domain = Domain(hostname=hostname)
        domain.notes = request.form.get("notes", "")
        domain.tags = [
            t.strip() for t in request.form.get("tags", "").split(",") if t.strip()
        ]
        domain.warning_days = int(request.form.get("warning_days", 30))
        domain.classify()

        # Auto-lookup DNS and SSL
        dns = get_dns_service()
        monitor = get_certificate_monitor()
        _update_domain_dns(domain, dns)
        _update_domain_ssl(domain, monitor)
        domain.last_checked = datetime.now(timezone.utc)

        registry.add(domain)
        flash(f"Domain {hostname} added and checked.", "success")
        return redirect(url_for("domains.detail", domain_id=domain.domain_id))

    return render_template("domains/add.html")


@bp.route("/<domain_id>")
def detail(domain_id):
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))
    return render_template("domains/detail.html", domain=domain)


@bp.route("/<domain_id>/edit", methods=["GET", "POST"])
def edit_domain(domain_id):
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))

    if request.method == "POST":
        notes = request.form.get("notes", "")
        tags = [
            t.strip() for t in request.form.get("tags", "").split(",") if t.strip()
        ]
        warning_days = int(request.form.get("warning_days", 30))
        status = request.form.get("status", domain.status.value)
        try:
            status = DomainStatus(status)
        except ValueError:
            status = domain.status

        registry.update(
            domain_id,
            notes=notes,
            tags=tags,
            warning_days=warning_days,
            status=status,
        )
        flash("Domain updated.", "success")
        return redirect(url_for("domains.detail", domain_id=domain_id))

    return render_template("domains/edit.html", domain=domain)


@bp.route("/<domain_id>/delete", methods=["POST"])
def delete_domain(domain_id):
    registry = get_domain_registry()
    if registry.remove(domain_id):
        flash("Domain deleted.", "success")
    else:
        flash("Domain not found.", "danger")
    return redirect(url_for("domains.list_domains"))


@bp.route("/<domain_id>/refresh", methods=["POST"])
def refresh_domain(domain_id):
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))

    dns = get_dns_service()
    monitor = get_certificate_monitor()
    _update_domain_dns(domain, dns)
    _update_domain_ssl(domain, monitor)
    domain.last_checked = datetime.now(timezone.utc)

    registry.update(
        domain_id,
        ip_address=domain.ip_address,
        nameservers=domain.nameservers,
        soa_primary_ns=domain.soa_primary_ns,
        soa_admin_email=domain.soa_admin_email,
        soa_serial=domain.soa_serial,
        soa_refresh=domain.soa_refresh,
        soa_retry=domain.soa_retry,
        soa_expire=domain.soa_expire,
        soa_minimum_ttl=domain.soa_minimum_ttl,
        reverse_dns=domain.reverse_dns,
        hosting_provider=domain.hosting_provider,
        registrar=domain.registrar,
        registration_expiry=domain.registration_expiry,
        registration_days_remaining=domain.registration_days_remaining,
        domain_created_date=domain.domain_created_date,
        dnssec=domain.dnssec,
        ssl_issuer=domain.ssl_issuer,
        ssl_expiry=domain.ssl_expiry,
        ssl_days_remaining=domain.ssl_days_remaining,
        ssl_status=domain.ssl_status,
        status=domain.status,
        last_checked=domain.last_checked,
    )
    flash(f"Refreshed {domain.hostname}.", "success")
    return redirect(url_for("domains.detail", domain_id=domain_id))


@bp.route("/discover", methods=["GET", "POST"])
def discover():
    results = None
    root_domain = ""

    if request.method == "POST":
        action = request.form.get("action", "discover")

        if action == "discover":
            root_domain = request.form.get("domain", "").strip().lower()
            if not root_domain:
                flash("Please enter a domain.", "danger")
            else:
                dns = get_dns_service()
                results = dns.discover_subdomains(root_domain)
                results = [r for r in results if r["resolvable"]]
                if not results:
                    flash(f"No resolvable subdomains found for {root_domain}.", "info")

        elif action == "add_selected":
            selected = request.form.getlist("selected")
            if not selected:
                flash("No subdomains selected.", "warning")
                return redirect(url_for("domains.discover"))

            registry = get_domain_registry()
            dns = get_dns_service()
            monitor = get_certificate_monitor()
            added = 0

            for hostname in selected:
                if registry.get_by_hostname(hostname):
                    continue
                domain = Domain(hostname=hostname)
                domain.auto_discovered = True
                domain.classify()
                _update_domain_dns(domain, dns)
                _update_domain_ssl(domain, monitor)
                domain.last_checked = datetime.now(timezone.utc)
                registry.add(domain)
                added += 1

            flash(f"Added {added} domain(s).", "success")
            return redirect(url_for("domains.list_domains"))

    return render_template(
        "domains/discover.html",
        results=results,
        root_domain=root_domain,
    )


@bp.route("/<domain_id>/letsencrypt", methods=["POST"])
def issue_letsencrypt(domain_id):
    """Issue a Let's Encrypt certificate for a domain."""
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))

    challenge_type = request.form.get("challenge_type", "http")
    auto_renew = request.form.get("auto_renew") == "on"

    acme = get_acme_service()
    result = acme.issue_certificate(domain.hostname, challenge_type=challenge_type)

    if result.success:
        registry.update(
            domain_id,
            le_enabled=True,
            le_cert_path=result.cert_path,
            le_key_path=result.key_path,
            le_last_renewed=datetime.now(timezone.utc),
            le_auto_renew=auto_renew,
            le_challenge_type=challenge_type,
        )
        flash(f"Let's Encrypt certificate issued for {domain.hostname}.", "success")
    else:
        flash(f"Let's Encrypt failed: {result.error}", "danger")

    return redirect(url_for("domains.detail", domain_id=domain_id))


@bp.route("/<domain_id>/letsencrypt/renew", methods=["POST"])
def renew_letsencrypt(domain_id):
    """Renew a Let's Encrypt certificate."""
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))

    if not domain.le_enabled:
        flash("Let's Encrypt is not enabled for this domain.", "warning")
        return redirect(url_for("domains.detail", domain_id=domain_id))

    acme = get_acme_service()
    result = acme.renew_certificate(domain.hostname)

    if result.success:
        registry.update(
            domain_id,
            le_cert_path=result.cert_path,
            le_key_path=result.key_path,
            le_last_renewed=datetime.now(timezone.utc),
        )
        flash(f"Certificate renewed for {domain.hostname}.", "success")
    else:
        flash(f"Renewal failed: {result.error}", "danger")

    return redirect(url_for("domains.detail", domain_id=domain_id))


@bp.route("/<domain_id>/letsencrypt/toggle", methods=["POST"])
def toggle_auto_renew(domain_id):
    """Toggle auto-renewal for Let's Encrypt."""
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        flash("Domain not found.", "danger")
        return redirect(url_for("domains.list_domains"))

    new_value = not domain.le_auto_renew
    registry.update(domain_id, le_auto_renew=new_value)
    state = "enabled" if new_value else "disabled"
    flash(f"Auto-renewal {state} for {domain.hostname}.", "info")
    return redirect(url_for("domains.detail", domain_id=domain_id))


# ── Domain Import (Azure DNS + Zone Transfer) ──────────────────────


def _import_selected(selected: list[str], tag: str) -> int:
    """Import selected hostnames as tracked domains with full checks."""
    registry = get_domain_registry()
    dns = get_dns_service()
    monitor = get_certificate_monitor()
    added = 0

    for hostname in selected:
        if registry.get_by_hostname(hostname):
            continue
        domain = Domain(hostname=hostname)
        domain.auto_discovered = True
        domain.tags = [tag]
        domain.classify()
        _update_domain_dns(domain, dns)
        _update_domain_ssl(domain, monitor)
        domain.last_checked = datetime.now(timezone.utc)
        registry.add(domain)
        added += 1

    return added


@bp.route("/import")
def import_domains():
    """Import page with tabs for Azure DNS and Zone Transfer."""
    azure_dns = get_azure_dns_service()
    return render_template(
        "domains/import.html",
        azure_configured=azure_dns.is_configured(),
    )


@bp.route("/import/azure", methods=["POST"])
def import_azure():
    """Import domains from Azure DNS zones."""
    azure_dns = get_azure_dns_service()
    if not azure_dns.is_configured():
        flash("Azure DNS is not configured. Set AZURE_SUBSCRIPTION_ID and credentials.", "danger")
        return redirect(url_for("domains.import_domains"))

    action = request.form.get("action", "list_zones")

    if action == "list_zones":
        zones = azure_dns.list_zones()
        if not zones:
            flash("No Azure DNS zones found.", "info")
        return render_template(
            "domains/import.html",
            azure_configured=True,
            active_tab="azure",
            azure_zones=zones,
        )

    elif action == "list_records":
        zone_name = request.form.get("zone_name", "")
        resource_group = request.form.get("resource_group", "")
        if not zone_name:
            flash("Please select a zone.", "danger")
            return redirect(url_for("domains.import_domains"))

        records = azure_dns.list_records(zone_name, resource_group)
        seen = set()
        unique_records = []
        for r in records:
            if r.hostname not in seen:
                seen.add(r.hostname)
                unique_records.append({"hostname": r.hostname, "type": r.record_type, "value": r.value})

        return render_template(
            "domains/import.html",
            azure_configured=True,
            active_tab="azure",
            azure_records=unique_records,
            zone_name=zone_name,
            resource_group=resource_group,
        )

    elif action == "add_selected":
        selected = request.form.getlist("selected")
        if not selected:
            flash("No domains selected.", "warning")
            return redirect(url_for("domains.import_domains"))

        added = _import_selected(selected, "azure-dns")
        flash(f"Imported {added} domain(s) from Azure DNS.", "success")
        return redirect(url_for("domains.list_domains"))

    return redirect(url_for("domains.import_domains"))


@bp.route("/import/zone-transfer", methods=["POST"])
def import_zone_transfer():
    """Import domains via DNS zone transfer (AXFR)."""
    action = request.form.get("action", "transfer")

    if action == "transfer":
        server = request.form.get("server", "").strip()
        zone_name = request.form.get("zone_name", "").strip().lower()
        tsig_key = request.form.get("tsig_key", "").strip() or None

        if not server or not zone_name:
            flash("Server and zone name are required.", "danger")
            return redirect(url_for("domains.import_domains"))

        zt = get_zone_transfer_service()
        records = zt.transfer_zone(server, zone_name, tsig_key=tsig_key)

        if not records:
            flash(
                f"Zone transfer returned no records for {zone_name} from {server}. "
                "Check that AXFR is allowed from this host.", "warning"
            )
            return render_template(
                "domains/import.html",
                azure_configured=get_azure_dns_service().is_configured(),
                active_tab="zone-transfer",
                zt_server=server,
                zt_zone=zone_name,
            )

        seen = set()
        unique_records = []
        for r in records:
            if r.hostname not in seen:
                seen.add(r.hostname)
                unique_records.append({"hostname": r.hostname, "type": r.record_type, "value": r.value})

        return render_template(
            "domains/import.html",
            azure_configured=get_azure_dns_service().is_configured(),
            active_tab="zone-transfer",
            zt_records=unique_records,
            zt_server=server,
            zt_zone=zone_name,
        )

    elif action == "add_selected":
        selected = request.form.getlist("selected")
        if not selected:
            flash("No domains selected.", "warning")
            return redirect(url_for("domains.import_domains"))

        added = _import_selected(selected, "zone-transfer")
        flash(f"Imported {added} domain(s) via zone transfer.", "success")
        return redirect(url_for("domains.list_domains"))

    return redirect(url_for("domains.import_domains"))
