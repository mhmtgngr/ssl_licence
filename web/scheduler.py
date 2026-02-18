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
    scheduler.add_job(
        func=_run_auto_renewals,
        trigger="interval",
        hours=12,
        id="le_auto_renewal",
        replace_existing=True,
    )
    scheduler.start()
    logger.info(
        "Scheduler started: health check every %d hour(s), "
        "LE auto-renewal every 12 hour(s)",
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

        # Generate and persist SSL / registration expiry alerts
        try:
            from web.services import get_alert_engine
            engine = get_alert_engine()
            alerts = engine.get_alerts()
            ssl_alerts = [a for a in alerts if a.source_type == "domain"]
            if ssl_alerts:
                engine.save_history()
                logger.info("Generated %d domain alert(s)", len(ssl_alerts))
        except Exception:
            logger.exception("Failed to generate domain alerts")

    except Exception:
        logger.exception("Scheduled health check failed")


# Default: renew when <= 30 days remaining
LE_RENEWAL_THRESHOLD_DAYS = 30


def _run_auto_renewals():
    """Automatically renew Let's Encrypt certificates for domains with auto-renew enabled."""
    logger.info("Running Let's Encrypt auto-renewal check...")

    try:
        from datetime import datetime, timezone
        from web.services import get_domain_registry, get_acme_service

        registry = get_domain_registry()
        acme = get_acme_service()
        domains = registry.list_all()

        candidates = [
            d for d in domains
            if d.le_enabled
            and d.le_auto_renew
            and d.ssl_days_remaining is not None
            and d.ssl_days_remaining <= LE_RENEWAL_THRESHOLD_DAYS
        ]

        if not candidates:
            logger.info("No domains due for auto-renewal")
            return

        renewed = 0
        for domain in candidates:
            try:
                logger.info(
                    "Auto-renewing %s (%d days remaining, challenge=%s)",
                    domain.hostname, domain.ssl_days_remaining,
                    domain.le_challenge_type,
                )
                result = acme.renew_certificate(domain.hostname)

                if result.success:
                    registry.update(
                        domain.domain_id,
                        le_cert_path=result.cert_path,
                        le_key_path=result.key_path,
                        le_last_renewed=datetime.now(timezone.utc),
                    )
                    renewed += 1
                    logger.info("Renewed certificate for %s", domain.hostname)
                else:
                    logger.warning(
                        "Renewal failed for %s: %s", domain.hostname, result.error,
                    )
            except Exception:
                logger.exception("Auto-renewal error for %s", domain.hostname)

        logger.info("Auto-renewal complete: %d/%d renewed", renewed, len(candidates))

    except Exception:
        logger.exception("Let's Encrypt auto-renewal job failed")
