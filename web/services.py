"""Backend service container for the web dashboard.

Uses a simple DI container (``ServiceContainer``) that caches instances
per request scope, avoiding redundant object creation while keeping
services easily replaceable for testing.
"""

import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DATA_DIR = Path(os.environ.get("SSL_LICENCE_DATA_DIR", str(PROJECT_ROOT / "data")))

REGISTRY_PATH = str(_DATA_DIR / "products" / "registry.json")
SETTINGS_PATH = str(_DATA_DIR / "settings.json")
LICENCE_STORAGE = str(_DATA_DIR / "licences.json")
CERT_CHECKS_PATH = _DATA_DIR / "cert_checks.json"
SSLCERT_BASE_DIR = str(PROJECT_ROOT / "sslcert")
DOMAIN_REGISTRY_PATH = str(_DATA_DIR / "domains" / "registry.json")
LETSENCRYPT_DIR = str(_DATA_DIR / "letsencrypt")
AZURE_SCAN_PATH = _DATA_DIR / "azure_resources_scan.json"
AUDIT_LOG_PATH = str(_DATA_DIR / "audit_log.json")
USERS_PATH = str(_DATA_DIR / "users.json")
SSL_NOTIFICATIONS_PATH = str(_DATA_DIR / "ssl_notifications.json")


class ServiceContainer:
    """Lightweight dependency injection container with optional caching.

    Services are registered as factory functions. Instances can be cached
    (singleton-per-container) or created fresh each call.

    Usage::

        container = ServiceContainer()
        container.register("registry", lambda c: ProductRegistry(path), cached=True)
        registry = container.get("registry")

        # Override for testing
        container.set("registry", mock_registry)
    """

    def __init__(self):
        self._factories: dict[str, Callable] = {}
        self._cached: dict[str, Any] = {}
        self._cache_flags: dict[str, bool] = {}
        self._lock = threading.Lock()

    def register(self, name: str, factory: Callable[["ServiceContainer"], Any],
                 cached: bool = False) -> None:
        """Register a service factory.

        Args:
            name: Service identifier.
            factory: Callable receiving the container, returning the service.
            cached: If True, the instance is cached after first creation.
        """
        self._factories[name] = factory
        self._cache_flags[name] = cached
        # Clear any existing cached instance on re-registration
        self._cached.pop(name, None)

    def get(self, name: str) -> Any:
        """Retrieve a service instance."""
        if name in self._cached:
            return self._cached[name]

        factory = self._factories.get(name)
        if factory is None:
            raise KeyError(f"Service '{name}' is not registered")

        instance = factory(self)
        if self._cache_flags.get(name, False):
            with self._lock:
                # Double-check after acquiring lock
                if name not in self._cached:
                    self._cached[name] = instance
                return self._cached[name]
        return instance

    def set(self, name: str, instance: Any) -> None:
        """Directly set a service instance (useful for testing)."""
        self._cached[name] = instance
        self._cache_flags[name] = True

    def reset(self, name: Optional[str] = None) -> None:
        """Clear cached instance(s). If name is None, clears all."""
        if name:
            self._cached.pop(name, None)
        else:
            self._cached.clear()


# ── Global container ─────────────────────────────────────────────

_container = ServiceContainer()


def _register_defaults(c: ServiceContainer) -> None:
    """Register all default service factories."""

    c.register("registry", lambda c: _make_registry())
    c.register("domain_registry", lambda c: _make_domain_registry())
    c.register("settings_store", lambda c: _make_settings_store(), cached=True)
    c.register("alert_engine", lambda c: _make_alert_engine(c))
    c.register("report_generator", lambda c: _make_report_generator(c))
    c.register("search_engine", lambda c: _make_search_engine(c))
    c.register("analyzer", lambda c: _make_analyzer(c))
    c.register("licence_manager", lambda c: _make_licence_manager())
    c.register("certificate_manager", lambda c: _make_certificate_manager())
    c.register("certificate_monitor", lambda c: _make_certificate_monitor())
    c.register("dns_service", lambda c: _make_dns_service())
    c.register("acme_service", lambda c: _make_acme_service(c))
    c.register("azure_dns_service", lambda c: _make_azure_dns_service(c))
    c.register("azure_resource_scanner", lambda c: _make_azure_resource_scanner(c))
    c.register("zone_transfer_service", lambda c: _make_zone_transfer_service())
    c.register("chain_validator", lambda c: _make_chain_validator())
    c.register("ocsp_checker", lambda c: _make_ocsp_checker())
    c.register("notification_dispatcher", lambda c: _make_notification_dispatcher(c))
    c.register("audit_log", lambda c: _make_audit_log())
    c.register("user_store", lambda c: _make_user_store())
    c.register("ssl_notification_tracker", lambda c: _make_ssl_notification_tracker())
    c.register("cert_checks_store", lambda c: _make_cert_checks_store())
    c.register("azure_scan_store", lambda c: _make_azure_scan_store())


# ── Factory functions ────────────────────────────────────────────

def _make_registry():
    from tracker.registry import ProductRegistry
    return ProductRegistry(REGISTRY_PATH)


def _make_domain_registry():
    from tracker.domain_registry import DomainRegistry
    return DomainRegistry(DOMAIN_REGISTRY_PATH)


def _make_settings_store():
    from web.settings_store import SettingsStore
    return SettingsStore(SETTINGS_PATH)


def _make_alert_engine(c: ServiceContainer):
    from tracker.alert_engine import AlertEngine
    registry = c.get("registry")
    domain_registry = c.get("domain_registry")
    engine = AlertEngine(
        registry,
        history_path=str(_DATA_DIR / "alerts_history.json"),
        domain_registry=domain_registry,
    )
    engine.evaluate_all()
    return engine


def _make_report_generator(c: ServiceContainer):
    from tracker.reports import ReportGenerator
    return ReportGenerator(c.get("registry"), c.get("alert_engine"))


def _make_search_engine(c: ServiceContainer):
    from tracker.search import SearchEngine
    return SearchEngine(c.get("registry"))


def _make_analyzer(c: ServiceContainer):
    from tracker.ai.analyzer import LicenceAnalyzer
    return LicenceAnalyzer(c.get("registry"))


def _make_licence_manager():
    from licence.manager import LicenceManager
    from config.settings import LICENCE_SIGNING_SECRET
    return LicenceManager(LICENCE_SIGNING_SECRET, LICENCE_STORAGE)


def _make_certificate_manager():
    from sslcert.certificate import CertificateManager
    return CertificateManager(SSLCERT_BASE_DIR)


def _make_certificate_monitor():
    from sslcert.monitor import CertificateMonitor
    return CertificateMonitor()


def _make_dns_service():
    from sslcert.dns_discovery import DnsService
    return DnsService()


def _make_acme_service(c: ServiceContainer):
    from sslcert.acme_service import AcmeService
    from config.settings import ACME_EMAIL, LETSENCRYPT_DIR, CERTBOT_STAGING
    store = c.get("settings_store")
    acme = store.get_section("acme")
    azure_dns = c.get("azure_dns_service")
    return AcmeService(
        letsencrypt_dir=str(LETSENCRYPT_DIR),
        email=acme.get("email") or ACME_EMAIL,
        staging=acme.get("staging", CERTBOT_STAGING),
        azure_dns_service=azure_dns if azure_dns.is_configured() else None,
    )


def _make_azure_dns_service(c: ServiceContainer):
    from sslcert.azure_dns import AzureDnsService
    from config.settings import (
        AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP,
        AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    )
    store = c.get("settings_store")
    azure = store.get_section("azure_dns")
    return AzureDnsService(
        subscription_id=azure.get("subscription_id") or AZURE_SUBSCRIPTION_ID,
        resource_group=azure.get("resource_group") or AZURE_RESOURCE_GROUP,
        tenant_id=azure.get("tenant_id") or AZURE_TENANT_ID,
        client_id=azure.get("client_id") or AZURE_CLIENT_ID,
        client_secret=azure.get("client_secret") or AZURE_CLIENT_SECRET,
    )


def _make_azure_resource_scanner(c: ServiceContainer):
    from sslcert.azure_resources import AzureResourceScanner
    from config.settings import (
        AZURE_SUBSCRIPTION_ID,
        AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    )
    store = c.get("settings_store")
    azure = store.get_section("azure_dns")
    return AzureResourceScanner(
        subscription_id=azure.get("subscription_id") or AZURE_SUBSCRIPTION_ID,
        tenant_id=azure.get("tenant_id") or AZURE_TENANT_ID,
        client_id=azure.get("client_id") or AZURE_CLIENT_ID,
        client_secret=azure.get("client_secret") or AZURE_CLIENT_SECRET,
    )


def _make_zone_transfer_service():
    from sslcert.zone_transfer import ZoneTransferService
    return ZoneTransferService()


def _make_chain_validator():
    from sslcert.chain_validator import CertificateChainValidator
    return CertificateChainValidator()


def _make_ocsp_checker():
    from sslcert.ocsp_checker import OCSPChecker
    return OCSPChecker()


def _make_notification_dispatcher(c: ServiceContainer):
    from tracker.notifications.dispatcher import NotificationDispatcher
    return NotificationDispatcher(c.get("settings_store"))


def _make_audit_log():
    from tracker.audit import AuditLog
    return AuditLog(AUDIT_LOG_PATH)


def _make_user_store():
    from tracker.user import UserStore
    return UserStore(USERS_PATH)


def _make_ssl_notification_tracker():
    from tracker.ssl_notifier import SslNotificationTracker
    return SslNotificationTracker(SSL_NOTIFICATIONS_PATH)


def _make_cert_checks_store():
    from web.stores import CertCheckStore
    return CertCheckStore(CERT_CHECKS_PATH)


def _make_azure_scan_store():
    from web.stores import AzureScanStore
    return AzureScanStore(AZURE_SCAN_PATH)


# Initialize default registrations
_register_defaults(_container)


# ── Public API (backward-compatible) ─────────────────────────────
# These functions maintain the existing interface used throughout the app.

def get_container() -> ServiceContainer:
    """Get the global service container (for advanced use or testing)."""
    return _container


def get_registry():
    return _container.get("registry")


def get_alert_engine(registry=None):
    if registry is not None:
        from tracker.alert_engine import AlertEngine
        domain_registry = get_domain_registry()
        engine = AlertEngine(
            registry,
            history_path=str(_DATA_DIR / "alerts_history.json"),
            domain_registry=domain_registry,
        )
        engine.evaluate_all()
        return engine
    return _container.get("alert_engine")


def get_report_generator(registry=None, alert_engine=None):
    if registry is not None or alert_engine is not None:
        from tracker.reports import ReportGenerator
        if registry is None:
            registry = get_registry()
        if alert_engine is None:
            alert_engine = get_alert_engine(registry)
        return ReportGenerator(registry, alert_engine)
    return _container.get("report_generator")


def get_search_engine(registry=None):
    if registry is not None:
        from tracker.search import SearchEngine
        return SearchEngine(registry)
    return _container.get("search_engine")


def get_analyzer(registry=None):
    if registry is not None:
        from tracker.ai.analyzer import LicenceAnalyzer
        return LicenceAnalyzer(registry)
    return _container.get("analyzer")


def get_licence_manager():
    return _container.get("licence_manager")


def get_certificate_manager():
    return _container.get("certificate_manager")


def get_certificate_monitor():
    return _container.get("certificate_monitor")


def get_domain_registry():
    return _container.get("domain_registry")


def get_dns_service():
    return _container.get("dns_service")


def get_settings_store():
    return _container.get("settings_store")


def get_acme_service():
    return _container.get("acme_service")


def get_azure_dns_service():
    return _container.get("azure_dns_service")


def get_azure_resource_scanner():
    return _container.get("azure_resource_scanner")


def get_zone_transfer_service():
    return _container.get("zone_transfer_service")


def get_chain_validator():
    return _container.get("chain_validator")


def get_ocsp_checker():
    return _container.get("ocsp_checker")


def get_notification_dispatcher():
    return _container.get("notification_dispatcher")


def get_audit_log():
    return _container.get("audit_log")


def get_user_store():
    return _container.get("user_store")


def get_ssl_notification_tracker():
    return _container.get("ssl_notification_tracker")


def get_cert_checks_store():
    return _container.get("cert_checks_store")


def get_azure_scan_store():
    return _container.get("azure_scan_store")
