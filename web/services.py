"""Backend service initialization for the web dashboard."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = str(PROJECT_ROOT / "data" / "products" / "registry.json")
LICENCE_STORAGE = str(PROJECT_ROOT / "data" / "licences.json")
CERT_CHECKS_PATH = PROJECT_ROOT / "data" / "cert_checks.json"
SSLCERT_BASE_DIR = str(PROJECT_ROOT / "sslcert")
DOMAIN_REGISTRY_PATH = str(PROJECT_ROOT / "data" / "domains" / "registry.json")
LETSENCRYPT_DIR = str(PROJECT_ROOT / "data" / "letsencrypt")


def get_registry():
    from tracker.registry import ProductRegistry
    return ProductRegistry(REGISTRY_PATH)


def get_alert_engine(registry=None):
    from tracker.alert_engine import AlertEngine
    if registry is None:
        registry = get_registry()
    engine = AlertEngine(
        registry,
        history_path=str(PROJECT_ROOT / "data" / "alerts_history.json"),
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


def get_acme_service():
    from sslcert.acme_service import AcmeService
    from config.settings import ACME_EMAIL, LETSENCRYPT_DIR, CERTBOT_STAGING
    return AcmeService(
        letsencrypt_dir=str(LETSENCRYPT_DIR),
        email=ACME_EMAIL,
        staging=CERTBOT_STAGING,
    )


def get_cert_checks_store():
    """Return the CertCheckStore for persisting certificate check results."""
    return CertCheckStore(CERT_CHECKS_PATH)


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
