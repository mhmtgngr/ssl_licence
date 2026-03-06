"""Backward-compatible re-export — canonical module is ``utils.safe_io``."""

from utils.safe_io import (  # noqa: F401
    atomic_write_json,
    retry_with_backoff,
    validate_hostname,
    validate_port,
    validate_webhook_url,
)
