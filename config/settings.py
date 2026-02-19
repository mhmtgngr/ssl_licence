"""Project-wide settings and defaults."""

import os
from pathlib import Path

# Base paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SSL_DIR = PROJECT_ROOT / "sslcert"
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

# Let's Encrypt / ACME
ACME_EMAIL = os.environ.get("ACME_EMAIL", "")
LETSENCRYPT_DIR = PROJECT_ROOT / "data" / "letsencrypt"
CERTBOT_STAGING = os.environ.get("CERTBOT_STAGING", "false").lower() == "true"

# Azure DNS integration
AZURE_SUBSCRIPTION_ID = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
AZURE_RESOURCE_GROUP = os.environ.get("AZURE_RESOURCE_GROUP", "")
AZURE_TENANT_ID = os.environ.get("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID = os.environ.get("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET", "")

# Notification channels (env var fallbacks for settings store)
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "")
NOTIFY_EMAIL_TO = os.environ.get("NOTIFY_EMAIL_TO", "")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
NOTIFY_WEBHOOK_URL = os.environ.get("NOTIFY_WEBHOOK_URL", "")

# Settings store (runtime configuration)
SETTINGS_PATH = PROJECT_ROOT / "data" / "settings.json"

# Scheduler
SCHEDULER_ENABLED = os.environ.get("SCHEDULER_ENABLED", "true").lower() == "true"
AZURE_SCAN_INTERVAL_HOURS = int(os.environ.get("AZURE_SCAN_INTERVAL_HOURS", "24"))

# Logging
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
