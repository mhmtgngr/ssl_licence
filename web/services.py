"""Backend service initialization for the web dashboard."""

import os
from pathlib import Path

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


def get_registry():
    from tracker.registry import ProductRegistry
    return ProductRegistry(REGISTRY_PATH)


def get_alert_engine(registry=None):
    from tracker.alert_engine import AlertEngine
    if registry is None:
        registry = get_registry()
    domain_registry = get_domain_registry()
    engine = AlertEngine(
        registry,
        history_path=str(_DATA_DIR / "alerts_history.json"),
        domain_registry=domain_registry,
    )
    engine.evaluate_all()
    return engine


def get_report_generator(registry=None, alert_engine=None):
    from tracker.reports import ReportGenerator
    if registry is None:
        registry = get_registry()
    if alert_engine is None:
        alert_engine = get_alert_engine(registry)
    return ReportGenerator(registry, alert_engine)


def get_search_engine(registry=None):
    from tracker.search import SearchEngine
    if registry is None:
        registry = get_registry()
    return SearchEngine(registry)


def get_analyzer(registry=None):
    from tracker.ai.analyzer import LicenceAnalyzer
    if registry is None:
        registry = get_registry()
    return LicenceAnalyzer(registry)


def get_licence_manager():
    from licence.manager import LicenceManager
    from config.settings import LICENCE_SIGNING_SECRET
    return LicenceManager(LICENCE_SIGNING_SECRET, LICENCE_STORAGE)


def get_certificate_manager():
    from sslcert.certificate import CertificateManager
    return CertificateManager(SSLCERT_BASE_DIR)


def get_certificate_monitor():
    from sslcert.monitor import CertificateMonitor
    return CertificateMonitor()


def get_domain_registry():
    from tracker.domain_registry import DomainRegistry
    return DomainRegistry(DOMAIN_REGISTRY_PATH)


def get_dns_service():
    from sslcert.dns_discovery import DnsService
    return DnsService()


def get_settings_store():
    from web.settings_store import SettingsStore
    return SettingsStore(SETTINGS_PATH)


def get_acme_service():
    from sslcert.acme_service import AcmeService
    from config.settings import ACME_EMAIL, LETSENCRYPT_DIR, CERTBOT_STAGING
    store = get_settings_store()
    acme = store.get_section("acme")
    azure_dns = get_azure_dns_service()
    return AcmeService(
        letsencrypt_dir=str(LETSENCRYPT_DIR),
        email=acme.get("email") or ACME_EMAIL,
        staging=acme.get("staging", CERTBOT_STAGING),
        azure_dns_service=azure_dns if azure_dns.is_configured() else None,
    )


def get_azure_dns_service():
    from sslcert.azure_dns import AzureDnsService
    from config.settings import (
        AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP,
        AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    )
    store = get_settings_store()
    azure = store.get_section("azure_dns")
    return AzureDnsService(
        subscription_id=azure.get("subscription_id") or AZURE_SUBSCRIPTION_ID,
        resource_group=azure.get("resource_group") or AZURE_RESOURCE_GROUP,
        tenant_id=azure.get("tenant_id") or AZURE_TENANT_ID,
        client_id=azure.get("client_id") or AZURE_CLIENT_ID,
        client_secret=azure.get("client_secret") or AZURE_CLIENT_SECRET,
    )


def get_azure_resource_scanner():
    from sslcert.azure_resources import AzureResourceScanner
    from config.settings import (
        AZURE_SUBSCRIPTION_ID,
        AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET,
    )
    store = get_settings_store()
    azure = store.get_section("azure_dns")
    return AzureResourceScanner(
        subscription_id=azure.get("subscription_id") or AZURE_SUBSCRIPTION_ID,
        tenant_id=azure.get("tenant_id") or AZURE_TENANT_ID,
        client_id=azure.get("client_id") or AZURE_CLIENT_ID,
        client_secret=azure.get("client_secret") or AZURE_CLIENT_SECRET,
    )


def get_zone_transfer_service():
    from sslcert.zone_transfer import ZoneTransferService
    return ZoneTransferService()


def get_chain_validator():
    from sslcert.chain_validator import CertificateChainValidator
    return CertificateChainValidator()


def get_ocsp_checker():
    from sslcert.ocsp_checker import OCSPChecker
    return OCSPChecker()


def get_notification_dispatcher():
    """Return a NotificationDispatcher configured from the settings store."""
    from tracker.notifications.dispatcher import NotificationDispatcher
    store = get_settings_store()
    return NotificationDispatcher(store)


def get_audit_log():
    from tracker.audit import AuditLog
    return AuditLog(AUDIT_LOG_PATH)


def get_user_store():
    from tracker.user import UserStore
    return UserStore(USERS_PATH)


def get_ssl_notification_tracker():
    from tracker.ssl_notifier import SslNotificationTracker
    return SslNotificationTracker(SSL_NOTIFICATIONS_PATH)


def get_cert_checks_store():
    """Return the CertCheckStore for persisting certificate check results."""
    return CertCheckStore(CERT_CHECKS_PATH)


class AzureScanStore:
    """Persist Azure resource scan results to JSON."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def save(self, bindings: list, summary: dict) -> None:
        import json
        from datetime import datetime, timezone
        data = {
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "bindings": [
                {
                    "resource_type": b.resource_type,
                    "resource_name": b.resource_name,
                    "resource_group": b.resource_group,
                    "subscription_id": b.subscription_id,
                    "subscription_name": b.subscription_name,
                    "resource_id": b.resource_id,
                    "hostname": b.hostname,
                    "hostname_type": b.hostname_type,
                    "ssl_enabled": b.ssl_enabled,
                    "ssl_thumbprint": b.ssl_thumbprint,
                    "ssl_subject": b.ssl_subject,
                    "ssl_expiry": b.ssl_expiry.isoformat() if b.ssl_expiry else None,
                    "ssl_state": b.ssl_state,
                    "tracked": b.tracked,
                    "tracked_domain_id": b.tracked_domain_id,
                }
                for b in bindings
            ],
        }
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def load(self) -> dict | None:
        import json
        if not self._path.exists():
            return None
        try:
            return json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def load_bindings(self) -> list:
        """Load raw binding dicts from cache."""
        data = self.load()
        if not data:
            return []
        return data.get("bindings", [])

    def get_bindings_for_hostname(self, hostname: str) -> list[dict]:
        """Return cached bindings matching a specific hostname."""
        bindings = self.load_bindings()
        h = hostname.lower()
        return [b for b in bindings if b.get("hostname", "").lower() == h]


def get_azure_scan_store():
    return AzureScanStore(AZURE_SCAN_PATH)


class CertCheckStore:
    """Simple JSON-file store for certificate check history."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> list[dict]:
        import json
        if self._path.exists():
            return json.loads(self._path.read_text())
        return []

    def _save(self, data: list[dict]) -> None:
        import json
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def add(self, entry: dict) -> None:
        data = self._load()
        data.insert(0, entry)
        self._save(data)

    def list_all(self) -> list[dict]:
        return self._load()

    def clear(self) -> None:
        self._save([])
