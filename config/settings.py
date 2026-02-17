"""Project-wide settings and defaults."""

import os
from pathlib import Path

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SSL_DIR = PROJECT_ROOT / "ssl"
LICENCE_DIR = PROJECT_ROOT / "licence"

# SSL defaults
SSL_CERTS_DIR = SSL_DIR / "certs"
SSL_KEYS_DIR = SSL_DIR / "keys"
SSL_CSR_DIR = SSL_DIR / "csr"
DEFAULT_KEY_SIZE = 2048
DEFAULT_CERT_VALIDITY_DAYS = 365

# Licence defaults
LICENCE_STORAGE_PATH = PROJECT_ROOT / "data" / "licences.json"
LICENCE_SIGNING_SECRET = os.environ.get("LICENCE_SECRET", "change-me-in-production")

# Monitoring
CERT_EXPIRY_WARNING_DAYS = 30
MONITOR_CHECK_INTERVAL_HOURS = 24

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
