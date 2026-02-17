"""Flask application factory for SSL Licence Dashboard."""

import sys
from pathlib import Path

from flask import Flask

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def create_app():
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config["SECRET_KEY"] = "dev-dashboard-key"

    from web.routes.dashboard import bp as dashboard_bp
    from web.routes.products import bp as products_bp
    from web.routes.alerts import bp as alerts_bp
    from web.routes.reports import bp as reports_bp
    from web.routes.analysis import bp as analysis_bp
    from web.routes.licences import bp as licences_bp
    from web.routes.certificates import bp as certificates_bp
    from web.routes.domains import bp as domains_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(products_bp, url_prefix="/products")
    app.register_blueprint(alerts_bp, url_prefix="/alerts")
    app.register_blueprint(reports_bp, url_prefix="/reports")
    app.register_blueprint(analysis_bp, url_prefix="/analysis")
    app.register_blueprint(licences_bp, url_prefix="/licences")
    app.register_blueprint(certificates_bp, url_prefix="/certificates")
    app.register_blueprint(domains_bp, url_prefix="/domains")

    @app.context_processor
    def inject_enums():
        from tracker.product import ProductCategory, LicenceType, SupportStatus
        from tracker.alert_engine import AlertLevel, AlertType
        from tracker.domain import DomainType, DomainStatus
        return {
            "ProductCategory": ProductCategory,
            "LicenceType": LicenceType,
            "SupportStatus": SupportStatus,
            "AlertLevel": AlertLevel,
            "AlertType": AlertType,
            "DomainType": DomainType,
            "DomainStatus": DomainStatus,
        }

    return app
