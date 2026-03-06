"""Safe I/O utilities: atomic writes, retry with backoff, input validation."""

import json
import logging
import os
import re
import tempfile
import time
from functools import wraps
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Hostname validation: RFC 952 / RFC 1123
_HOSTNAME_RE = re.compile(
    r"^(?!\-)([a-zA-Z0-9\-\*]{1,63}\.)*[a-zA-Z]{2,63}$"
)


def atomic_write_json(path: Path, data: Any, indent: int = 2) -> None:
    """Write JSON to a file atomically using temp file + rename.

    Creates a temporary file in the same directory, writes data,
    then atomically renames it over the target path. This prevents
    partial writes on crash.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=indent, default=str)

    fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=f".{path.stem}_",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(path))
    except Exception:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def retry_with_backoff(
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 10.0,
    exceptions: tuple = (OSError, ConnectionError, TimeoutError),
):
    """Decorator that retries a function with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts.
        base_delay: Initial delay in seconds.
        max_delay: Maximum delay between retries.
        exceptions: Tuple of exception types to catch and retry.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exc = e
                    if attempt < max_retries:
                        delay = min(base_delay * (2 ** attempt), max_delay)
                        logger.warning(
                            "%s attempt %d/%d failed: %s (retrying in %.1fs)",
                            func.__name__, attempt + 1, max_retries + 1,
                            e, delay,
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            "%s failed after %d attempts: %s",
                            func.__name__, max_retries + 1, e,
                        )
            raise last_exc
        return wrapper
    return decorator


def validate_port(port: Any, default: int = 443) -> int:
    """Validate and return a port number in range 1-65535.

    Returns default if the value is invalid.
    """
    try:
        port = int(port)
        if 1 <= port <= 65535:
            return port
    except (TypeError, ValueError):
        pass
    return default


def validate_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname or wildcard domain.

    Allows standard hostnames and wildcard patterns like *.example.com.
    """
    if not hostname or len(hostname) > 253:
        return False
    # Allow wildcard prefix
    check = hostname
    if check.startswith("*."):
        check = "a" + check[1:]
    return bool(_HOSTNAME_RE.match(check))
