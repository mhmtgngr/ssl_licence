"""Background scheduler for periodic certificate and domain checks."""

import logging

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler(daemon=True)


def init_scheduler(app):
    """Initialize and start the background scheduler."""
    from config.settings import MONITOR_CHECK_INTERVAL_HOURS

    if scheduler.running:
        return

    scheduler.add_job(
        func=_run_scheduled_checks,
        trigger="interval",
        hours=MONITOR_CHECK_INTERVAL_HOURS,
        id="daily_health_check",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started: health check every %d hour(s)",
        MONITOR_CHECK_INTERVAL_HOURS,
    )


def _run_scheduled_checks():
    """Run periodic certificate and domain checks."""
    logger.info("Running scheduled health check...")

    try:
        from web.services import (
            get_domain_registry,
            get_certificate_monitor,
        )
        from web.routes.domains import _update_domain_ssl
        from datetime import datetime, timezone

        registry = get_domain_registry()
        monitor = get_certificate_monitor()
        domains = registry.list_all()
        checked = 0

        for domain in domains:
            try:
                _update_domain_ssl(domain, monitor)
                domain.last_checked = datetime.now(timezone.utc)
                registry.update(
                    domain.domain_id,
                    ssl_issuer=domain.ssl_issuer,
                    ssl_expiry=domain.ssl_expiry,
                    ssl_days_remaining=domain.ssl_days_remaining,
                    ssl_status=domain.ssl_status,
                    status=domain.status,
                    last_checked=domain.last_checked,
                )
                checked += 1
            except Exception:
                logger.exception("Failed to check domain %s", domain.hostname)

        logger.info("Scheduled check complete: %d/%d domains checked", checked, len(domains))
    except Exception:
        logger.exception("Scheduled health check failed")
