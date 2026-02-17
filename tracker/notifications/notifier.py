"""
Multi-channel notification system for licence alerts.

Supports:
- Console output (default)
- Email (SMTP)
- Webhook (generic HTTP POST)
- Slack (incoming webhook)
- Log file
"""

import json
import logging
import smtplib
import urllib.request
import urllib.error
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

from tracker.alert_engine import Alert, AlertLevel

logger = logging.getLogger(__name__)


class ConsoleNotifier:
    """Print alerts to stdout with color-coded severity."""

    LEVEL_ICONS = {
        AlertLevel.INFO: "   ",
        AlertLevel.LOW: "[*]",
        AlertLevel.MEDIUM: "[!]",
        AlertLevel.HIGH: "[!!]",
        AlertLevel.CRITICAL: "[!!!]",
        AlertLevel.EXPIRED: "[XXX]",
    }

    def send(self, alerts: list[Alert]) -> None:
        """Print alerts to console."""
        if not alerts:
            print("No alerts to display.")
            return

        print(f"\n{'='*70}")
        print(f"  LICENCE & SUPPORT ALERTS — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"{'='*70}\n")

        for alert in alerts:
            icon = self.LEVEL_ICONS.get(alert.alert_level, "   ")
            print(f"  {icon} {alert.alert_level.value.upper():10s} | {alert.message}")
            print(f"       Target date: {alert.target_date.strftime('%Y-%m-%d')}")
            print(f"       Days remaining: {alert.days_remaining}")
            print()

        print(f"{'='*70}")
        print(f"  Total: {len(alerts)} alert(s)")
        print(f"{'='*70}\n")


class EmailNotifier:
    """Send alert digest via SMTP email."""

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int = 587,
        username: str = "",
        password: str = "",
        from_addr: str = "",
        to_addrs: Optional[list[str]] = None,
        use_tls: bool = True,
    ):
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs or []
        self.use_tls = use_tls

    def send(self, alerts: list[Alert]) -> bool:
        """Send alert digest email. Returns True on success."""
        if not alerts or not self.to_addrs:
            return False

        subject = self._build_subject(alerts)
        body = self._build_html_body(alerts)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)
        msg.attach(MIMEText(body, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls()
                if self.username:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, self.to_addrs, msg.as_string())
            logger.info("Alert email sent to %s", self.to_addrs)
            return True
        except smtplib.SMTPException as e:
            logger.error("Failed to send alert email: %s", e)
            return False

    @staticmethod
    def _build_subject(alerts: list[Alert]) -> str:
        critical = sum(
            1 for a in alerts
            if a.alert_level in (AlertLevel.CRITICAL, AlertLevel.EXPIRED)
        )
        if critical:
            return f"[CRITICAL] {critical} urgent licence/support alert(s)"
        return f"Licence Alert Digest: {len(alerts)} item(s) require attention"

    @staticmethod
    def _build_html_body(alerts: list[Alert]) -> str:
        rows = []
        for a in alerts:
            color = {
                "expired": "#dc3545",
                "critical": "#dc3545",
                "high": "#fd7e14",
                "medium": "#ffc107",
                "low": "#17a2b8",
                "info": "#6c757d",
            }.get(a.alert_level.value, "#6c757d")

            rows.append(
                f"<tr>"
                f"<td style='color:{color};font-weight:bold'>{a.alert_level.value.upper()}</td>"
                f"<td>{a.product_name}</td>"
                f"<td>{a.vendor}</td>"
                f"<td>{a.alert_type.value}</td>"
                f"<td>{a.days_remaining} days</td>"
                f"<td>{a.target_date.strftime('%Y-%m-%d')}</td>"
                f"</tr>"
            )

        return f"""
        <html><body>
        <h2>Licence & Support Alert Digest</h2>
        <p>Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
        <table border='1' cellpadding='5' cellspacing='0'>
        <tr style='background:#f0f0f0'>
          <th>Level</th><th>Product</th><th>Vendor</th>
          <th>Type</th><th>Remaining</th><th>Date</th>
        </tr>
        {''.join(rows)}
        </table>
        <p>Total alerts: {len(alerts)}</p>
        </body></html>
        """


class WebhookNotifier:
    """Send alerts to a generic webhook (HTTP POST with JSON)."""

    def __init__(self, url: str, headers: Optional[dict] = None):
        self.url = url
        self.headers = headers or {"Content-Type": "application/json"}

    def send(self, alerts: list[Alert]) -> bool:
        """POST alert data to webhook. Returns True on success."""
        if not alerts:
            return False

        payload = {
            "generated_at": datetime.utcnow().isoformat(),
            "total_alerts": len(alerts),
            "alerts": [a.to_dict() for a in alerts],
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url, data=data, headers=self.headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                logger.info("Webhook sent, status: %s", resp.status)
                return resp.status < 400
        except urllib.error.URLError as e:
            logger.error("Webhook failed: %s", e)
            return False


class SlackNotifier:
    """Send alerts to Slack via incoming webhook."""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, alerts: list[Alert]) -> bool:
        """Post alert summary to Slack channel."""
        if not alerts:
            return False

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Licence Alerts — {len(alerts)} items",
                },
            },
        ]

        for alert in alerts[:20]:
            emoji = {
                "expired": ":red_circle:",
                "critical": ":red_circle:",
                "high": ":large_orange_circle:",
                "medium": ":large_yellow_circle:",
                "low": ":large_blue_circle:",
                "info": ":white_circle:",
            }.get(alert.alert_level.value, ":white_circle:")

            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{emoji} *{alert.alert_level.value.upper()}* — "
                        f"{alert.product_name} ({alert.vendor})\n"
                        f"_{alert.alert_type.value}_ | "
                        f"{alert.days_remaining} days | "
                        f"{alert.target_date.strftime('%Y-%m-%d')}"
                    ),
                },
            })

        payload = json.dumps({"blocks": blocks}).encode()
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status == 200
        except urllib.error.URLError as e:
            logger.error("Slack notification failed: %s", e)
            return False


class FileNotifier:
    """Append alerts to a log file."""

    def __init__(self, log_path: str = "data/alerts.log"):
        self.log_path = Path(log_path)

    def send(self, alerts: list[Alert]) -> None:
        """Append alerts to the log file."""
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [f"\n--- Alert run: {timestamp} ({len(alerts)} alerts) ---\n"]
        for a in alerts:
            lines.append(
                f"[{a.alert_level.value.upper():10s}] "
                f"{a.product_name} ({a.vendor}) — "
                f"{a.alert_type.value} — "
                f"{a.days_remaining} days — "
                f"target: {a.target_date.strftime('%Y-%m-%d')}\n"
            )

        with self.log_path.open("a") as f:
            f.writelines(lines)
