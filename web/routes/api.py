"""REST API v1 — JSON endpoints for automation and integration."""

from datetime import datetime, timezone

from flask import Blueprint, g, jsonify, request

from web.auth import role_required, current_username
from web.services import (
    get_registry,
    get_alert_engine,
    get_certificate_monitor,
    get_cert_checks_store,
    get_licence_manager,
    get_domain_registry,
    get_dns_service,
    get_azure_scan_store,
    get_audit_log,
)
from tracker.product import Product, ProductCategory, LicenceType
from tracker.alert_engine import AlertLevel, AlertType
from tracker.domain import Domain, DomainStatus

bp = Blueprint("api", __name__)


@bp.before_request
def api_auth():
    """Authenticate API requests via API key if no user already set."""
    if g.get("current_user"):
        return

    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
    if api_key:
        import secrets as _secrets
        from web.services import get_settings_store
        store = get_settings_store()
        stored_keys = store.get_section("api_keys")
        for key_name, key_value in stored_keys.items():
            if _secrets.compare_digest(api_key, key_value):
                from tracker.user import User, UserRole
                g.current_user = User(
                    username=f"api:{key_name}",
                    role=UserRole.EDITOR,
                    display_name=f"API Key: {key_name}",
                    user_id=f"apikey-{key_name}",
                )
                return

    return jsonify({"error": "Authentication required. Provide X-API-Key header or session cookie."}), 401


def _error(message, status=400):
    return jsonify({"error": message}), status


# ── Products ─────────────────────────────────────────────────────────

@bp.route("/products")
def list_products():
    registry = get_registry()
    category = request.args.get("category")
    vendor = request.args.get("vendor")
    if category:
        try:
            products = registry.by_category(ProductCategory(category))
        except ValueError:
            return _error(f"Invalid category: {category}")
    elif vendor:
        products = registry.by_vendor(vendor)
    else:
        products = registry.list_all()
    return jsonify([p.to_dict() for p in products])


@bp.route("/products/<product_id>")
def get_product(product_id):
    registry = get_registry()
    product = registry.get(product_id)
    if not product:
        return _error("Product not found", 404)
    return jsonify(product.to_dict())


@bp.route("/products", methods=["POST"])
@role_required("admin", "editor")
def add_product():
    data = request.get_json(silent=True) or {}
    required = ["name", "vendor", "version", "category"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return _error(f"Missing required fields: {', '.join(missing)}")

    try:
        category = ProductCategory(data["category"])
    except ValueError:
        return _error(f"Invalid category: {data['category']}")

    licence_type = LicenceType.SUBSCRIPTION
    if data.get("licence_type"):
        try:
            licence_type = LicenceType(data["licence_type"])
        except ValueError:
            return _error(f"Invalid licence_type: {data['licence_type']}")

    def parse_date(val):
        if not val:
            return None
        try:
            return datetime.strptime(val, "%Y-%m-%d")
        except ValueError:
            return None

    product = Product(
        name=data["name"],
        vendor=data["vendor"],
        version=data["version"],
        category=category,
        licence_type=licence_type,
        licence_key=data.get("licence_key", ""),
        licence_quantity=int(data.get("licence_quantity", 1)),
        licence_expiry=parse_date(data.get("licence_expiry")),
        mainstream_support_end=parse_date(data.get("mainstream_support_end")),
        extended_support_end=parse_date(data.get("extended_support_end")),
        end_of_life=parse_date(data.get("end_of_life")),
        annual_cost=float(data.get("annual_cost", 0)),
        environment=data.get("environment", "production"),
        department=data.get("department", ""),
        owner=data.get("owner", ""),
        notes=data.get("notes", ""),
        tags=data.get("tags", []),
    )
    registry = get_registry()
    registry.add(product)
    return jsonify(product.to_dict()), 201


@bp.route("/products/<product_id>", methods=["DELETE"])
@role_required("admin", "editor")
def delete_product(product_id):
    registry = get_registry()
    if registry.remove(product_id):
        return jsonify({"deleted": True})
    return _error("Product not found", 404)


# ── Domains ──────────────────────────────────────────────────────────

@bp.route("/domains")
def list_domains():
    registry = get_domain_registry()
    domains = registry.list_all()

    status_filter = request.args.get("status")
    if status_filter:
        try:
            domains = [d for d in domains if d.status == DomainStatus(status_filter)]
        except ValueError:
            return _error(f"Invalid status: {status_filter}")

    ssl_status = request.args.get("ssl_status")
    if ssl_status:
        domains = [d for d in domains if d.ssl_status == ssl_status]

    parent = request.args.get("parent")
    if parent:
        domains = [d for d in domains if d.parent_domain == parent]

    ca = request.args.get("ca")
    if ca:
        domains = [d for d in domains if d.ssl_ca_name and ca.lower() in d.ssl_ca_name.lower()]

    q = request.args.get("q", "").strip().lower()
    if q:
        domains = [d for d in domains if q in d.hostname.lower()
                    or (d.ip_address and q in d.ip_address)
                    or (d.ssl_ca_name and q in d.ssl_ca_name.lower())]

    return jsonify([d.to_dict() for d in domains])


@bp.route("/domains/refresh-all", methods=["POST"])
@role_required("admin", "editor")
def api_refresh_all():
    """Trigger background bulk refresh of all domains."""
    from web.scheduler import scheduler
    from web.routes.domains import _background_refresh_all

    if not scheduler.running:
        return _error("Scheduler not running", 503)

    scheduler.add_job(
        func=_background_refresh_all,
        trigger="date",
        id="api_bulk_refresh",
        replace_existing=True,
    )
    domain_count = len(get_domain_registry().list_all())
    return jsonify({"status": "started", "domain_count": domain_count})


@bp.route("/domains/export")
def api_export_domains():
    """JSON export of all tracked domains."""
    registry = get_domain_registry()
    domains = registry.list_all()
    return jsonify({
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "total": len(domains),
        "domains": [d.to_dict() for d in domains],
    })


@bp.route("/domains/<domain_id>")
def get_domain(domain_id):
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        return _error("Domain not found", 404)
    return jsonify(domain.to_dict())


@bp.route("/domains", methods=["POST"])
@role_required("admin", "editor")
def add_domain():
    data = request.get_json(silent=True) or {}
    hostname = data.get("hostname", "").strip().lower()
    if not hostname:
        return _error("hostname is required")

    registry = get_domain_registry()
    if registry.get_by_hostname(hostname):
        return _error(f"Domain {hostname} is already tracked", 409)

    domain = Domain(hostname=hostname)
    domain.notes = data.get("notes", "")
    domain.tags = data.get("tags", [])
    domain.warning_days = int(data.get("warning_days", 30))
    domain.classify()
    domain.last_checked = datetime.now(timezone.utc)
    registry.add(domain)
    return jsonify(domain.to_dict()), 201


@bp.route("/domains/<domain_id>", methods=["DELETE"])
@role_required("admin", "editor")
def delete_domain(domain_id):
    registry = get_domain_registry()
    if registry.remove(domain_id):
        return jsonify({"deleted": True})
    return _error("Domain not found", 404)


@bp.route("/domains/<domain_id>/refresh", methods=["POST"])
@role_required("admin", "editor")
def refresh_domain(domain_id):
    from web.routes.domains import _update_domain_dns, _update_domain_ssl

    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        return _error("Domain not found", 404)

    dns = get_dns_service()
    monitor = get_certificate_monitor()
    _update_domain_dns(domain, dns)
    _update_domain_ssl(domain, monitor)
    domain.last_checked = datetime.now(timezone.utc)

    registry.update(
        domain_id,
        ip_address=domain.ip_address,
        nameservers=domain.nameservers,
        ssl_issuer=domain.ssl_issuer,
        ssl_expiry=domain.ssl_expiry,
        ssl_days_remaining=domain.ssl_days_remaining,
        ssl_status=domain.ssl_status,
        ssl_certificate_type=domain.ssl_certificate_type,
        ssl_san_domains=domain.ssl_san_domains,
        ssl_ca_name=domain.ssl_ca_name,
        status=domain.status,
        last_checked=domain.last_checked,
    )
    return jsonify(domain.to_dict())


# ── Alerts ───────────────────────────────────────────────────────────

@bp.route("/alerts")
def list_alerts():
    registry = get_registry()
    engine = get_alert_engine(registry)

    level_filter = request.args.get("level")
    type_filter = request.args.get("type")
    vendor_filter = request.args.get("vendor")

    level = None
    if level_filter:
        try:
            level = AlertLevel(level_filter)
        except ValueError:
            return _error(f"Invalid level: {level_filter}")

    alert_type = None
    if type_filter:
        try:
            alert_type = AlertType(type_filter)
        except ValueError:
            return _error(f"Invalid type: {type_filter}")

    alerts = engine.get_alerts(
        level=level, alert_type=alert_type,
        vendor=vendor_filter or None,
    )
    return jsonify([a.to_dict() for a in alerts])


@bp.route("/alerts/summary")
def alert_summary():
    registry = get_registry()
    engine = get_alert_engine(registry)
    return jsonify(engine.get_dashboard_summary())


@bp.route("/alerts/<product_id>/acknowledge", methods=["POST"])
@role_required("admin", "editor")
def acknowledge_alert(product_id):
    data = request.get_json(silent=True) or {}
    alert_type = data.get("alert_type", "")
    if not alert_type:
        return _error("alert_type is required")

    registry = get_registry()
    engine = get_alert_engine(registry)
    if engine.acknowledge_alert(product_id, alert_type):
        return jsonify({"acknowledged": True})
    return _error("Alert not found", 404)


# ── Certificates ─────────────────────────────────────────────────────

@bp.route("/certificates/check", methods=["POST"])
@role_required("admin", "editor")
def check_certificates():
    data = request.get_json(silent=True) or {}
    domains = data.get("domains", [])
    if not domains:
        return _error("domains list is required")

    monitor = get_certificate_monitor()
    store = get_cert_checks_store()
    results = []

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
        results.append(entry)

    return jsonify(results)


@bp.route("/certificates/history")
def certificate_history():
    store = get_cert_checks_store()
    return jsonify(store.list_all())


@bp.route("/certificates/chain-check", methods=["POST"])
def api_chain_check():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return _error("domain is required")

    from web.services import get_chain_validator
    validator = get_chain_validator()
    result = validator.validate(domain)
    return jsonify({
        "domain": result.domain,
        "status": result.status,
        "is_valid": result.is_valid,
        "chain_length": result.chain_length,
        "chain": [
            {
                "subject": link.subject,
                "issuer": link.issuer,
                "not_before": link.not_before,
                "not_after": link.not_after,
                "is_ca": link.is_ca,
            }
            for link in result.chain
        ],
        "error": result.error,
    })


@bp.route("/certificates/ocsp-check", methods=["POST"])
def api_ocsp_check():
    data = request.get_json(silent=True) or {}
    domain = data.get("domain", "").strip()
    if not domain:
        return _error("domain is required")

    from web.services import get_ocsp_checker
    checker = get_ocsp_checker()
    result = checker.check(domain)
    return jsonify({
        "domain": result.domain,
        "status": result.status,
        "responder_url": result.responder_url,
        "error": result.error,
    })


# ── Licences ─────────────────────────────────────────────────────────

@bp.route("/licences", methods=["POST"])
@role_required("admin", "editor")
def issue_licence():
    data = request.get_json(silent=True) or {}
    if not data.get("licence_type") or not data.get("issued_to"):
        return _error("licence_type and issued_to are required")

    mgr = get_licence_manager()
    valid_days = data.get("valid_days")
    features = data.get("features")

    try:
        licence = mgr.issue(
            licence_type=data["licence_type"],
            issued_to=data["issued_to"],
            valid_days=int(valid_days) if valid_days else None,
            features=features,
            max_users=int(data.get("max_users", 1)),
        )
        return jsonify({"key": licence.key, "licence_type": licence.licence_type}), 201
    except ValueError as e:
        return _error(str(e))


@bp.route("/licences/validate", methods=["POST"])
def validate_licence():
    data = request.get_json(silent=True) or {}
    key = data.get("key", "")
    if not key:
        return _error("key is required")

    mgr = get_licence_manager()
    result = mgr.validate(key)
    return jsonify({
        "is_valid": result.is_valid,
        "licence_type": result.licence_type,
        "error": result.error,
    })


# ── Azure Resources ─────────────────────────────────────────────────

@bp.route("/azure-resources")
def api_azure_resources():
    """Return cached Azure resource scan results."""
    store = get_azure_scan_store()
    cached = store.load()
    if not cached:
        return jsonify({"bindings": [], "scanned_at": None, "total": 0})

    return jsonify({
        "scanned_at": cached.get("scanned_at"),
        "total": len(cached.get("bindings", [])),
        "bindings": cached.get("bindings", []),
    })


@bp.route("/azure-resources/scan", methods=["POST"])
@role_required("admin", "editor")
def api_azure_scan():
    """Trigger an Azure resource scan."""
    from web.services import get_azure_resource_scanner
    from sslcert.azure_resources import match_bindings_to_registry

    scanner = get_azure_resource_scanner()
    if not scanner.is_configured():
        return _error("Azure scanner not configured (missing credentials)", 503)

    bindings = scanner.scan_all()
    registry = get_domain_registry()
    bindings = match_bindings_to_registry(bindings, registry)

    summary = {
        "total": len(bindings),
        "tracked": sum(1 for b in bindings if b.tracked),
        "untracked": sum(1 for b in bindings if not b.tracked),
        "ssl_enabled": sum(1 for b in bindings if b.ssl_enabled),
        "by_type": {},
    }
    for b in bindings:
        summary["by_type"][b.resource_type] = summary["by_type"].get(b.resource_type, 0) + 1

    store = get_azure_scan_store()
    store.save(bindings, summary)

    untracked_hosts = [b.hostname for b in bindings if not b.tracked]
    return jsonify({
        "total": summary["total"],
        "tracked": summary["tracked"],
        "untracked": summary["untracked"],
        "untracked_domains": untracked_hosts,
    })


# ── Audit Log ───────────────────────────────────────────────────────

@bp.route("/audit")
def api_audit():
    """Return audit log entries."""
    audit = get_audit_log()
    entries = audit.list_all()

    action_filter = request.args.get("action")
    if action_filter:
        entries = [e for e in entries if e.action == action_filter]

    q = request.args.get("q", "").strip().lower()
    if q:
        entries = [e for e in entries if q in e.target.lower() or q in e.detail.lower()]

    limit = request.args.get("limit", type=int, default=100)
    entries = entries[:limit]

    return jsonify([
        {
            "timestamp": e.timestamp,
            "action": e.action,
            "target": e.target,
            "detail": e.detail,
            "user": e.user,
        }
        for e in entries
    ])
