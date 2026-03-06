"""Central notification dispatcher — pluggable channel registry pattern."""

import json
import logging
import os
from typing import Callable, Optional

from tracker.alert_engine import Alert, AlertLevel, AlertType
from tracker.notifications.notifier import (
    ConsoleNotifier,
    EmailNotifier,
    FileNotifier,
    Notifier,
    SlackNotifier,
    WebhookNotifier,
)

logger = logging.getLogger(__name__)

# Type alias for channel factory functions:
# (settings_store) -> Notifier | None
ChannelFactory = Callable[[object], Optional[Notifier]]


def _build_console(store) -> Notifier:
    """Console channel — always active."""
    return ConsoleNotifier()


def _build_file(store) -> Notifier:
    """File channel — always active."""
    cfg = store.get_section("notify_file")
    log_path = cfg.get("log_path") or "data/alerts.log"
    return FileNotifier(log_path=log_path)


def _build_email(store) -> Optional[Notifier]:
    """Email channel — enabled when configured."""
    cfg = store.get_section("notify_email")
    if not cfg.get("enabled", False):
        return None
    smtp_host = cfg.get("smtp_host") or os.environ.get("SMTP_HOST", "")
    to_addrs_raw = cfg.get("to_addrs") or os.environ.get("NOTIFY_EMAIL_TO", "")
    if not smtp_host or not to_addrs_raw:
        return None
    if isinstance(to_addrs_raw, str):
        to_addrs = [a.strip() for a in to_addrs_raw.split(",") if a.strip()]
    else:
        to_addrs = list(to_addrs_raw)
    return EmailNotifier(
        smtp_host=smtp_host,
        smtp_port=int(cfg.get("smtp_port") or os.environ.get("SMTP_PORT", "587")),
        username=cfg.get("username") or os.environ.get("SMTP_USERNAME", ""),
        password=cfg.get("password") or os.environ.get("SMTP_PASSWORD", ""),
        from_addr=cfg.get("from_addr") or os.environ.get("SMTP_FROM", ""),
        to_addrs=to_addrs,
        use_tls=cfg.get("use_tls", True),
    )


def _build_slack(store) -> Optional[Notifier]:
    """Slack channel — enabled when configured."""
    cfg = store.get_section("notify_slack")
    if not cfg.get("enabled", False):
        return None
    webhook_url = cfg.get("webhook_url") or os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        return None
    return SlackNotifier(webhook_url=webhook_url)


def _build_webhook(store) -> Optional[Notifier]:
    """Generic webhook channel — enabled when configured."""
    cfg = store.get_section("notify_webhook")
    if not cfg.get("enabled", False):
        return None
    url = cfg.get("url") or os.environ.get("NOTIFY_WEBHOOK_URL", "")
    if not url:
        return None
    headers = None
    raw_headers = cfg.get("headers")
    if raw_headers:
        try:
            parsed = json.loads(raw_headers)
            headers = parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, TypeError):
            pass
    return WebhookNotifier(url=url, headers=headers)


# Default channel registry — maps channel name to its factory function.
# Add new channels by registering a factory via ``register_channel()``.
_DEFAULT_CHANNELS: dict[str, ChannelFactory] = {
    "console": _build_console,
    "file": _build_file,
    "email": _build_email,
    "slack": _build_slack,
    "webhook": _build_webhook,
}


class NotificationDispatcher:
    """Pluggable notification dispatcher with a channel registry.

    Channels are registered as factory functions that receive the settings
    store and return a ``Notifier`` instance (or ``None`` to skip).
    New channels can be added at runtime via ``register_channel()``.

    Usage::

        dispatcher = NotificationDispatcher(settings_store)
        dispatcher.register_channel("teams", my_teams_factory)
        dispatcher.dispatch(alerts)
    """

    def __init__(self, settings_store):
        self._store = settings_store
        self._channels: dict[str, ChannelFactory] = dict(_DEFAULT_CHANNELS)

    def register_channel(self, name: str, factory: ChannelFactory) -> None:
        """Register a new notification channel.

        Args:
            name: Channel identifier (e.g. "teams", "pagerduty").
            factory: Callable that takes a settings store and returns a Notifier
                     or None if the channel is not configured.
        """
        self._channels[name] = factory

    def unregister_channel(self, name: str) -> bool:
        """Remove a registered channel. Returns True if it existed."""
        return self._channels.pop(name, None) is not None

    @property
    def registered_channels(self) -> list[str]:
        """List all registered channel names."""
        return list(self._channels.keys())

    # ── Public API ───────────────────────────────────────────────

    def dispatch(
        self,
        alerts: list[Alert],
        only_unacknowledged: bool = True,
    ) -> dict[str, bool]:
        """Send alerts through all enabled channels.

        Returns a dict mapping channel name to success/failure boolean.
        """
        if only_unacknowledged:
            alerts = [a for a in alerts if not a.acknowledged]

        if not alerts:
            logger.info("No alerts to dispatch (all acknowledged or empty).")
            return {}

        results: dict[str, bool] = {}

        for name, factory in self._channels.items():
            try:
                notifier = factory(self._store)
                if notifier is None:
                    continue
                success = notifier.send(alerts)
                results[name] = bool(success)
            except Exception as exc:
                logger.error("%s notifier failed: %s", name, exc)
                results[name] = False

        logger.info("Notification dispatch results: %s", results)
        return results

    def test_channel(self, channel: str) -> tuple[bool, str]:
        """Send a synthetic test alert through a single channel.

        Returns ``(success, message)`` tuple.
        """
        from datetime import datetime, timezone

        test_alert = Alert(
            product_id="test-000",
            product_name="Test Alert",
            vendor="System",
            alert_type=AlertType.SSL_EXPIRY,
            alert_level=AlertLevel.INFO,
            days_remaining=99,
            target_date=datetime.now(timezone.utc),
            message="This is a test notification from SSL Licence Manager.",
            source_type="test",
        )
        test_alerts = [test_alert]

        factory = self._channels.get(channel)
        if factory is None:
            return False, f"Unknown channel: {channel}"

        try:
            notifier = factory(self._store)
            if notifier is None:
                return False, f"{channel.title()} not configured or disabled."
            ok = notifier.send(test_alerts)
            if ok:
                return True, f"Test {channel} notification sent."
            detail = getattr(notifier, "last_error", "") or "Unknown error"
            return False, f"{channel.title()} send failed: {detail}"
        except Exception as exc:
            return False, f"Test failed: {exc}"
