"""SSL expiry notification tracker with threshold-based email alerts.

Notification rules:
  - One-time email when a domain first drops below 30 days
  - One-time email when a domain first drops below 15 days
  - Daily email for all domains below 15 days

Tracks sent notifications in a JSON file to avoid duplicate one-time alerts.
Resets tracking when a certificate is renewed (days go back above threshold).
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

THRESHOLD_30 = 30
THRESHOLD_15 = 15


class SslNotificationTracker:
    """Track which SSL expiry threshold notifications have been sent."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self, data: dict) -> None:
        self._path.write_text(json.dumps(data, indent=2, default=str))

    def get_state(self, domain_id: str) -> dict:
        """Return notification state for a domain."""
        data = self._load()
        return data.get(domain_id, {})

    def mark_sent(self, domain_id: str, threshold: int) -> None:
        """Record that a threshold notification was sent."""
        data = self._load()
        if domain_id not in data:
            data[domain_id] = {}
        data[domain_id][f"sent_{threshold}d"] = datetime.now(timezone.utc).isoformat()
        self._save(data)

    def mark_daily_sent(self, domain_id: str) -> None:
        """Record that a daily notification was sent today."""
        data = self._load()
        if domain_id not in data:
            data[domain_id] = {}
        data[domain_id]["last_daily"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        self._save(data)

    def was_sent(self, domain_id: str, threshold: int) -> bool:
        """Check if a threshold notification was already sent."""
        state = self.get_state(domain_id)
        return f"sent_{threshold}d" in state

    def was_daily_sent_today(self, domain_id: str) -> bool:
        """Check if a daily notification was already sent today."""
        state = self.get_state(domain_id)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return state.get("last_daily") == today

    def reset(self, domain_id: str) -> None:
        """Reset tracking for a domain (e.g. after certificate renewal)."""
        data = self._load()
        if domain_id in data:
            del data[domain_id]
            self._save(data)


def check_and_notify(domains, tracker, dispatcher, audit_log=None):
    """Evaluate all domains and send threshold-based SSL expiry notifications.

    Args:
        domains: list of Domain objects (already refreshed)
        tracker: SslNotificationTracker instance
        dispatcher: NotificationDispatcher instance
        audit_log: optional AuditLog instance

    Returns:
        dict with counts: {notified_30: N, notified_15: N, daily: N, reset: N}
    """
    from tracker.alert_engine import Alert, AlertLevel, AlertType

    alerts_30 = []  # One-time 30-day threshold
    alerts_15 = []  # One-time 15-day threshold
    alerts_daily = []  # Daily reminders for <15 days
    reset_count = 0

    for domain in domains:
        days = domain.ssl_days_remaining
        if days is None:
            continue

        did = domain.domain_id

        # If cert was renewed and is now above 30 days, reset tracking
        if days > THRESHOLD_30 and (tracker.was_sent(did, 30) or tracker.was_sent(did, 15)):
            tracker.reset(did)
            reset_count += 1
            continue

        # 30-day threshold (one-time)
        if days <= THRESHOLD_30 and not tracker.was_sent(did, 30):
            alerts_30.append(_make_alert(domain, THRESHOLD_30))
            tracker.mark_sent(did, 30)

        # 15-day threshold (one-time)
        if days <= THRESHOLD_15 and not tracker.was_sent(did, 15):
            alerts_15.append(_make_alert(domain, THRESHOLD_15))
            tracker.mark_sent(did, 15)

        # Daily reminders for domains below 15 days
        if days <= THRESHOLD_15 and not tracker.was_daily_sent_today(did):
            alerts_daily.append(_make_alert(domain, 0))
            tracker.mark_daily_sent(did)

    stats = {
        "notified_30": len(alerts_30),
        "notified_15": len(alerts_15),
        "daily": len(alerts_daily),
        "reset": reset_count,
    }

    # Dispatch 30-day threshold alerts
    if alerts_30:
        _dispatch_batch(
            dispatcher, alerts_30,
            subject_prefix="[SSL 30-Day Warning]",
            heading="SSL Certificates Expiring Within 30 Days",
        )
        logger.info("Sent 30-day threshold alerts for %d domain(s)", len(alerts_30))

    # Dispatch 15-day threshold alerts
    if alerts_15:
        _dispatch_batch(
            dispatcher, alerts_15,
            subject_prefix="[SSL 15-Day Warning]",
            heading="SSL Certificates Expiring Within 15 Days",
        )
        logger.info("Sent 15-day threshold alerts for %d domain(s)", len(alerts_15))

    # Dispatch daily reminders
    if alerts_daily:
        _dispatch_batch(
            dispatcher, alerts_daily,
            subject_prefix="[SSL Daily Reminder]",
            heading="SSL Certificates Expiring Soon - Daily Reminder",
        )
        logger.info("Sent daily SSL reminder for %d domain(s)", len(alerts_daily))

    if audit_log and (alerts_30 or alerts_15 or alerts_daily):
        parts = []
        if alerts_30:
            parts.append(f"{len(alerts_30)} at 30d")
        if alerts_15:
            parts.append(f"{len(alerts_15)} at 15d")
        if alerts_daily:
            parts.append(f"{len(alerts_daily)} daily")
        audit_log.log(
            "scheduled_check", "ssl_notifications",
            f"Sent: {', '.join(parts)}",
            user="system",
        )

    return stats


def _make_alert(domain, threshold):
    """Create an Alert object for SSL expiry notification."""
    from tracker.alert_engine import Alert, AlertLevel, AlertType

    days = domain.ssl_days_remaining or 0

    if days <= 7:
        level = AlertLevel.CRITICAL
    elif days <= 15:
        level = AlertLevel.HIGH
    elif days <= 30:
        level = AlertLevel.MEDIUM
    else:
        level = AlertLevel.LOW

    if threshold == 0:
        msg = f"DAILY REMINDER: {domain.hostname} SSL expires in {days} day(s)"
    else:
        msg = f"{domain.hostname} SSL certificate expires in {days} day(s) (crossed {threshold}-day threshold)"

    return Alert(
        product_id=domain.domain_id,
        product_name=domain.hostname,
        vendor=domain.ssl_ca_name or "Unknown CA",
        alert_type=AlertType.SSL_EXPIRY,
        alert_level=level,
        days_remaining=days,
        target_date=domain.ssl_expiry or datetime.now(timezone.utc),
        source_type="domain",
        message=msg,
    )


def _dispatch_batch(dispatcher, alerts, subject_prefix, heading):
    """Send alerts through dispatcher with SSL-specific email formatting.

    Sends a custom-formatted email directly, then dispatches to other
    channels (Slack, webhook, file, console) via the normal dispatcher.
    """
    import os
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    # Build custom email
    store = dispatcher._store
    email_cfg = store.get_section("notify_email")
    email_enabled = (
        email_cfg.get("enabled", False)
        and (email_cfg.get("smtp_host") or os.environ.get("SMTP_HOST", ""))
        and (email_cfg.get("to_addrs") or os.environ.get("NOTIFY_EMAIL_TO", ""))
    )

    if email_enabled:
        try:
            # Build subject
            hostnames = [a.product_name for a in alerts[:3]]
            suffix = f" (+{len(alerts) - 3} more)" if len(alerts) > 3 else ""
            subject = f"{subject_prefix} {', '.join(hostnames)}{suffix}"

            # Build HTML body
            rows = []
            for a in sorted(alerts, key=lambda x: x.days_remaining):
                if a.days_remaining <= 7:
                    color = "#dc3545"
                elif a.days_remaining <= 15:
                    color = "#fd7e14"
                else:
                    color = "#ffc107"
                rows.append(
                    f"<tr>"
                    f"<td style='font-weight:bold;color:{color}'>{a.days_remaining} days</td>"
                    f"<td>{a.product_name}</td>"
                    f"<td>{a.vendor}</td>"
                    f"<td>{a.target_date.strftime('%Y-%m-%d') if a.target_date else '-'}</td>"
                    f"</tr>"
                )

            body = f"""
            <html><body>
            <h2>{heading}</h2>
            <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
            <table border='1' cellpadding='8' cellspacing='0' style='border-collapse:collapse;width:100%'>
            <tr style='background:#f0f0f0'>
              <th>Days Left</th><th>Domain</th><th>CA</th><th>Expiry Date</th>
            </tr>
            {''.join(rows)}
            </table>
            <p>Total: {len(alerts)} domain(s)</p>
            <p style='color:#6c757d;font-size:12px'>SSL Licence Manager - Automated Notification</p>
            </body></html>
            """

            # Send email
            smtp_host = email_cfg.get("smtp_host") or os.environ.get("SMTP_HOST", "")
            smtp_port = int(email_cfg.get("smtp_port") or os.environ.get("SMTP_PORT", "587"))
            username = email_cfg.get("username") or os.environ.get("SMTP_USERNAME", "")
            password = email_cfg.get("password") or os.environ.get("SMTP_PASSWORD", "")
            from_addr = email_cfg.get("from_addr") or os.environ.get("SMTP_FROM", "")
            to_raw = email_cfg.get("to_addrs") or os.environ.get("NOTIFY_EMAIL_TO", "")
            to_addrs = [a.strip() for a in to_raw.split(",") if a.strip()]
            use_tls = email_cfg.get("use_tls", True)

            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = from_addr
            msg["To"] = ", ".join(to_addrs)
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
                if use_tls:
                    server.starttls()
                if username:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())

            logger.info("SSL notification email sent: %s (%d domains)", subject_prefix, len(alerts))
        except Exception:
            logger.exception("Failed to send SSL notification email")

    # Log to file
    try:
        from tracker.notifications.notifier import FileNotifier
        file_cfg = store.get_section("notify_file")
        log_path = file_cfg.get("log_path") or "data/alerts.log"
        FileNotifier(log_path=log_path).send(alerts)
    except Exception:
        logger.exception("Failed to log SSL alerts to file")
