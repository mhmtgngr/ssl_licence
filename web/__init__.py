"""Flask application factory for SSL Licence Dashboard."""

import os
import sys
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()  # Load .env file if present (already gitignored)

from flask import Flask, jsonify, render_template, request
from flask_wtf.csrf import CSRFProtect

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

csrf = CSRFProtect()


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-dashboard-key")
    app.config["WTF_CSRF_TIME_LIMIT"] = 3600

    csrf.init_app(app)

    from web.routes.dashboard import bp as dashboard_bp
    from web.routes.products import bp as products_bp
    from web.routes.alerts import bp as alerts_bp
    from web.routes.reports import bp as reports_bp
    from web.routes.analysis import bp as analysis_bp
    from web.routes.licences import bp as licences_bp
    from web.routes.certificates import bp as certificates_bp
    from web.routes.domains import bp as domains_bp
    from web.routes.settings import bp as settings_bp
    from web.routes.audit import bp as audit_bp
    from web.routes.api import bp as api_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(products_bp, url_prefix="/products")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    app.register_blueprint(licences_bp, url_prefix="/licences")
    app.register_blueprint(certificates_bp, url_prefix="/certificates")
    app.register_blueprint(domains_bp, url_prefix="/domains")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(audit_bp, url_prefix="/audit")
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    csrf.exempt(api_bp)

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Not found"}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("errors/500.html"), 500

    @app.route("/health")
    def health_check():
        return jsonify({"status": "healthy", "version": "0.1.0"}), 200

    @app.context_processor
    def inject_enums():
        from tracker.product import ProductCategory, LicenceType, SupportStatus
        from tracker.alert_engine import AlertLevel, AlertType
        from tracker.domain import DomainType, DomainStatus, CertificateType
        from tracker.audit import AuditAction
        return {
            "ProductCategory": ProductCategory,
            "LicenceType": LicenceType,
            "SupportStatus": SupportStatus,
            "AlertLevel": AlertLevel,
            "AlertType": AlertType,
            "DomainType": DomainType,
            "DomainStatus": DomainStatus,
            "CertificateType": CertificateType,
            "AuditAction": AuditAction,
        }

    @app.context_processor
    def inject_sort_url():
        from urllib.parse import urlencode

        def sort_url(field):
            args = dict(request.args)
            if args.get("sort") == field and args.get("order", "asc") == "asc":
                args["order"] = "desc"
            else:
                args["order"] = "asc"
            args["sort"] = field
            return "?" + urlencode(args)
        return {"sort_url": sort_url}

    # Start scheduler (only in non-testing mode)
    if not app.config.get("TESTING"):
        from web.scheduler import init_scheduler
        init_scheduler(app)

    return app
