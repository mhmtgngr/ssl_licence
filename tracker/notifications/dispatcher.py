"""Central notification dispatcher — reads config, builds notifiers, dispatches."""

import json
import logging
import os
from typing import Optional

from tracker.alert_engine import Alert, AlertLevel, AlertType
from tracker.notifications.notifier import (
    ConsoleNotifier,
    EmailNotifier,
    FileNotifier,
    SlackNotifier,
    WebhookNotifier,
)

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """Read notification channel configs from settings store and dispatch alerts.

    Each channel can be independently enabled/disabled.  Console and File
    notifiers are always active; Email, Slack, and Webhook are gated by an
    ``enabled`` flag in their respective settings sections.

    Usage::

        dispatcher = get_notification_dispatcher()   # via web.services
        dispatcher.dispatch(alerts)
    """

    def __init__(self, settings_store):
        self._store = settings_store

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

        # Console — always on
        try:
            ConsoleNotifier().send(alerts)
            results["console"] = True
        except Exception as exc:
            logger.error("ConsoleNotifier failed: %s", exc)
            results["console"] = False

        # File — always on
        try:
            file_cfg = self._store.get_section("notify_file")
            log_path = file_cfg.get("log_path") or "data/alerts.log"
            FileNotifier(log_path=log_path).send(alerts)
            results["file"] = True
        except Exception as exc:
            logger.error("FileNotifier failed: %s", exc)
            results["file"] = False

        # Email
        email_cfg = self._store.get_section("notify_email")
        if self._is_email_enabled(email_cfg):
            try:
                notifier = self._build_email_notifier(email_cfg)
                success = notifier.send(alerts)
                results["email"] = bool(success)
            except Exception as exc:
                logger.error("EmailNotifier failed: %s", exc)
                results["email"] = False

        # Slack
        slack_cfg = self._store.get_section("notify_slack")
        if self._is_slack_enabled(slack_cfg):
            try:
                webhook_url = (
                    slack_cfg.get("webhook_url")
                    or os.environ.get("SLACK_WEBHOOK_URL", "")
                )
                notifier = SlackNotifier(webhook_url=webhook_url)
                success = notifier.send(alerts)
                results["slack"] = bool(success)
            except Exception as exc:
                logger.error("SlackNotifier failed: %s", exc)
                results["slack"] = False

        # Webhook
        webhook_cfg = self._store.get_section("notify_webhook")
        if self._is_webhook_enabled(webhook_cfg):
            try:
                url = (
                    webhook_cfg.get("url")
                    or os.environ.get("NOTIFY_WEBHOOK_URL", "")
                )
                headers = self._parse_headers(webhook_cfg.get("headers"))
                notifier = WebhookNotifier(url=url, headers=headers)
                success = notifier.send(alerts)
                results["webhook"] = bool(success)
            except Exception as exc:
                logger.error("WebhookNotifier failed: %s", exc)
                results["webhook"] = False

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

        try:
            if channel == "email":
                cfg = self._store.get_section("notify_email")
                if not self._is_email_enabled(cfg):
                    return False, "Email not configured or disabled."
                notifier = self._build_email_notifier(cfg)
                ok = notifier.send(test_alerts)
                return bool(ok), "Test email sent." if ok else "Email send failed."

            if channel == "slack":
                cfg = self._store.get_section("notify_slack")
                if not self._is_slack_enabled(cfg):
                    return False, "Slack not configured or disabled."
                webhook_url = (
                    cfg.get("webhook_url")
                    or os.environ.get("SLACK_WEBHOOK_URL", "")
                )
                ok = SlackNotifier(webhook_url=webhook_url).send(test_alerts)
                return bool(ok), "Test Slack message sent." if ok else "Slack send failed."

            if channel == "webhook":
                cfg = self._store.get_section("notify_webhook")
                if not self._is_webhook_enabled(cfg):
                    return False, "Webhook not configured or disabled."
                url = cfg.get("url") or os.environ.get("NOTIFY_WEBHOOK_URL", "")
                headers = self._parse_headers(cfg.get("headers"))
                ok = WebhookNotifier(url=url, headers=headers).send(test_alerts)
                return bool(ok), "Test webhook sent." if ok else "Webhook send failed."

            return False, f"Unknown channel: {channel}"

        except Exception as exc:
            return False, f"Test failed: {exc}"

    # ── Private helpers ──────────────────────────────────────────

    @staticmethod
    def _is_email_enabled(cfg: dict) -> bool:
        if not cfg.get("enabled", False):
            return False
        smtp_host = cfg.get("smtp_host") or os.environ.get("SMTP_HOST", "")
        to_addrs = cfg.get("to_addrs") or os.environ.get("NOTIFY_EMAIL_TO", "")
        return bool(smtp_host and to_addrs)

    @staticmethod
    def _build_email_notifier(cfg: dict) -> EmailNotifier:
        to_addrs_raw = cfg.get("to_addrs") or os.environ.get("NOTIFY_EMAIL_TO", "")
        if isinstance(to_addrs_raw, str):
            to_addrs = [a.strip() for a in to_addrs_raw.split(",") if a.strip()]
        else:
            to_addrs = list(to_addrs_raw)

        return EmailNotifier(
            smtp_host=cfg.get("smtp_host") or os.environ.get("SMTP_HOST", ""),
            smtp_port=int(cfg.get("smtp_port") or os.environ.get("SMTP_PORT", "587")),
            username=cfg.get("username") or os.environ.get("SMTP_USERNAME", ""),
            password=cfg.get("password") or os.environ.get("SMTP_PASSWORD", ""),
            from_addr=cfg.get("from_addr") or os.environ.get("SMTP_FROM", ""),
            to_addrs=to_addrs,
            use_tls=cfg.get("use_tls", True),
        )

    @staticmethod
    def _is_slack_enabled(cfg: dict) -> bool:
        if not cfg.get("enabled", False):
            return False
        webhook_url = cfg.get("webhook_url") or os.environ.get("SLACK_WEBHOOK_URL", "")
        return bool(webhook_url)

    @staticmethod
    def _is_webhook_enabled(cfg: dict) -> bool:
        if not cfg.get("enabled", False):
            return False
        url = cfg.get("url") or os.environ.get("NOTIFY_WEBHOOK_URL", "")
        return bool(url)

    @staticmethod
    def _parse_headers(raw: Optional[str]) -> Optional[dict]:
        if not raw:
            return None
        try:
            headers = json.loads(raw)
            return headers if isinstance(headers, dict) else None
        except (json.JSONDecodeError, TypeError):
            return None
