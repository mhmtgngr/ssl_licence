"""REST API v1 — JSON endpoints for automation and integration."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request

from web.services import (
    get_registry,
    get_alert_engine,
    get_certificate_monitor,
    get_cert_checks_store,
    get_licence_manager,
    get_domain_registry,
    get_dns_service,
)
from tracker.product import Product, ProductCategory, LicenceType
from tracker.alert_engine import AlertLevel, AlertType
from tracker.domain import Domain, DomainStatus

bp = Blueprint("api", __name__)


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
    return jsonify([d.to_dict() for d in domains])


@bp.route("/domains/<domain_id>")
def get_domain(domain_id):
    registry = get_domain_registry()
    domain = registry.get(domain_id)
    if not domain:
        return _error("Domain not found", 404)
    return jsonify(domain.to_dict())


@bp.route("/domains", methods=["POST"])
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
def delete_domain(domain_id):
    registry = get_domain_registry()
    if registry.remove(domain_id):
        return jsonify({"deleted": True})
    return _error("Domain not found", 404)


@bp.route("/domains/<domain_id>/refresh", methods=["POST"])
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
