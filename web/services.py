"""Backend service initialization for the web dashboard."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = str(PROJECT_ROOT / "data" / "products" / "registry.json")
LICENCE_STORAGE = str(PROJECT_ROOT / "data" / "licences.json")
SSLCERT_BASE_DIR = str(PROJECT_ROOT / "sslcert")


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
