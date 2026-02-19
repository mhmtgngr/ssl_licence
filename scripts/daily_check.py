#!/usr/bin/env python3
"""Daily health check for SSL certificates and licences.

Run via cron or manually:
    python scripts/daily_check.py

Checks:
  - Remote SSL certificates for all previously monitored domains
  - Licence expiry status
  - Product lifecycle alerts (support end, EOL)

Results saved to data/daily_reports/<date>.json and printed to stdout.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import (
    CERT_EXPIRY_WARNING_DAYS, LICENCE_SIGNING_SECRET,
    ACME_EMAIL, LETSENCRYPT_DIR, CERTBOT_STAGING,
)
from sslcert.monitor import CertificateMonitor
from sslcert.dns_discovery import DnsService
from sslcert.acme_service import AcmeService
from licence.manager import LicenceManager
from tracker.registry import ProductRegistry
from tracker.alert_engine import AlertEngine
from tracker.domain import DomainStatus
from tracker.domain_registry import DomainRegistry
from web.settings_store import SettingsStore
from tracker.notifications.dispatcher import NotificationDispatcher

DATA_DIR = PROJECT_ROOT / "data"
CERT_CHECKS_PATH = DATA_DIR / "cert_checks.json"
DAILY_REPORTS_DIR = DATA_DIR / "daily_reports"
REGISTRY_PATH = str(DATA_DIR / "products" / "registry.json")
DOMAIN_REGISTRY_PATH = str(DATA_DIR / "domains" / "registry.json")
LICENCE_STORAGE = str(DATA_DIR / "licences.json")
ALERTS_HISTORY = str(DATA_DIR / "alerts_history.json")
SETTINGS_PATH = str(DATA_DIR / "settings.json")


def get_monitored_domains() -> list[str]:
    """Get unique domains from certificate check history."""
    if not CERT_CHECKS_PATH.exists():
        return []
    checks = json.loads(CERT_CHECKS_PATH.read_text())
    seen = set()
    domains = []
    for c in checks:
        d = c.get("domain", "")
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


def check_certificates(domains: list[str]) -> list[dict]:
    """Check SSL certificates for all domains."""
    monitor = CertificateMonitor()
    results = []
    for domain in domains:
        status = monitor.check_remote(domain)
        entry = {
            "domain": domain,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
        if status:
            entry.update({
                "status": "expired" if status.is_expired else (
                    "warning" if status.days_remaining <= CERT_EXPIRY_WARNING_DAYS else "ok"
                ),
                "issuer": status.issuer,
                "not_after": status.not_after.isoformat(),
                "days_remaining": status.days_remaining,
                "is_expired": status.is_expired,
            })
        else:
            entry.update({"status": "fail", "error": f"Could not connect to {domain}"})
        results.append(entry)
    return results


def check_licences() -> list[dict]:
    """Check all licence expiry statuses."""
    mgr = LicenceManager(LICENCE_SIGNING_SECRET, LICENCE_STORAGE)
    results = []
    now = datetime.now(timezone.utc)
    for lic in mgr.list_all():
        entry = {
            "key": lic["key"][:25] + "...",
            "licence_type": lic.get("licence_type", ""),
            "issued_to": lic.get("issued_to", ""),
            "revoked": lic.get("revoked", False),
        }
        expires_at = lic.get("expires_at")
        if expires_at:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            days_left = (exp_dt - now).days
            entry.update({
                "expires_at": expires_at[:10],
                "days_remaining": days_left,
                "status": "expired" if days_left < 0 else (
                    "warning" if days_left <= 30 else "ok"
                ),
            })
        else:
            entry.update({"expires_at": "perpetual", "days_remaining": None, "status": "ok"})
        results.append(entry)
    return results


def check_products() -> list[dict]:
    """Run alert engine and return critical/high alerts."""
    registry = ProductRegistry(REGISTRY_PATH)
    engine = AlertEngine(registry, history_path=ALERTS_HISTORY)
    engine.evaluate_all()
    engine.save_history()

    alerts = []
    for alert in engine.get_alerts():
        level = alert.alert_level.value
        if level in ("expired", "critical", "high"):
            alerts.append({
                "product": alert.product_name,
                "vendor": alert.vendor,
                "level": level,
                "type": alert.alert_type.value,
                "days_remaining": alert.days_remaining,
                "target_date": alert.target_date.isoformat(),
                "message": alert.message,
            })
    return alerts


def check_tracked_domains() -> list[dict]:
    """Check all tracked domains — SSL and DNS."""
    registry = DomainRegistry(DOMAIN_REGISTRY_PATH)
    monitor = CertificateMonitor()
    dns = DnsService()
    now = datetime.now(timezone.utc)
    results = []

    for domain in registry.list_all():
        if domain.status == DomainStatus.INACTIVE:
            continue

        entry = {
            "hostname": domain.hostname,
            "domain_type": domain.domain_type.value,
            "previous_ip": domain.ip_address,
        }

        # SSL check
        status = monitor.check_remote(domain.hostname)
        if status:
            ssl_status = "expired" if status.is_expired else (
                "warning" if status.days_remaining <= domain.warning_days else "ok"
            )
            entry.update({
                "ssl_status": ssl_status,
                "ssl_days_remaining": status.days_remaining,
                "ssl_expiry": status.not_after.isoformat(),
                "ssl_issuer": status.issuer,
            })
            domain.ssl_issuer = status.issuer
            domain.ssl_expiry = status.not_after
            domain.ssl_days_remaining = status.days_remaining
            domain.ssl_status = ssl_status
            if status.is_expired:
                domain.status = DomainStatus.EXPIRED
            elif status.days_remaining <= domain.warning_days:
                domain.status = DomainStatus.EXPIRING
            else:
                domain.status = DomainStatus.ACTIVE
        else:
            entry.update({"ssl_status": "fail", "ssl_days_remaining": None})
            domain.ssl_status = "fail"
            domain.status = DomainStatus.UNREACHABLE

        # IP check (detect changes)
        new_ip = dns.lookup_ip(domain.hostname)
        entry["current_ip"] = new_ip
        entry["ip_changed"] = bool(domain.ip_address and new_ip and domain.ip_address != new_ip)
        if new_ip:
            domain.ip_address = new_ip

        # WHOIS / registration expiry check
        whois = dns.lookup_whois(domain.hostname)
        if whois:
            domain.registrar = whois.get("registrar", domain.registrar)
            domain.registration_expiry = whois.get("registration_expiry", domain.registration_expiry)
            domain.registration_days_remaining = whois.get("registration_days_remaining", domain.registration_days_remaining)
            domain.domain_created_date = whois.get("domain_created_date", domain.domain_created_date)
            domain.dnssec = whois.get("dnssec", domain.dnssec)
        entry["registration_days_remaining"] = domain.registration_days_remaining

        domain.last_checked = now
        registry.update(
            domain.domain_id,
            ssl_issuer=domain.ssl_issuer,
            ssl_expiry=domain.ssl_expiry,
            ssl_days_remaining=domain.ssl_days_remaining,
            ssl_status=domain.ssl_status,
            status=domain.status,
            ip_address=domain.ip_address,
            registrar=domain.registrar,
            registration_expiry=domain.registration_expiry,
            registration_days_remaining=domain.registration_days_remaining,
            domain_created_date=domain.domain_created_date,
            dnssec=domain.dnssec,
            last_checked=domain.last_checked,
        )
        results.append(entry)

    return results


def check_letsencrypt_renewals() -> list[dict]:
    """Auto-renew Let's Encrypt certificates within 30 days of expiry."""
    registry = DomainRegistry(DOMAIN_REGISTRY_PATH)
    acme = AcmeService(
        letsencrypt_dir=str(LETSENCRYPT_DIR),
        email=ACME_EMAIL,
        staging=CERTBOT_STAGING,
    )
    now = datetime.now(timezone.utc)
    results = []

    for domain in registry.list_all():
        if not domain.le_enabled or not domain.le_auto_renew:
            continue

        needs_renewal = False
        if domain.ssl_expiry:
            days_left = (domain.ssl_expiry - now).days
            needs_renewal = days_left <= 30
        else:
            needs_renewal = True

        if not needs_renewal:
            results.append({
                "hostname": domain.hostname,
                "action": "skip",
                "message": f"Still valid ({domain.ssl_days_remaining}d remaining)",
            })
            continue

        result = acme.renew_certificate(domain.hostname)
        entry = {
            "hostname": domain.hostname,
            "action": "renew",
            "success": result.success,
            "message": result.message,
        }
        if result.success:
            registry.update(
                domain.domain_id,
                le_cert_path=result.cert_path,
                le_key_path=result.key_path,
                le_last_renewed=now,
            )
            entry["renewed_at"] = now.isoformat()
        else:
            entry["error"] = result.error

        results.append(entry)

    return results


def save_cert_checks(results: list[dict]) -> None:
    """Append certificate check results to the cert_checks store."""
    existing = []
    if CERT_CHECKS_PATH.exists():
        existing = json.loads(CERT_CHECKS_PATH.read_text())
    existing = results + existing
    CERT_CHECKS_PATH.write_text(json.dumps(existing, indent=2, default=str))


def main():
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    print(f"=== Daily Health Check — {date_str} ===\n")

    # 1. Certificate checks
    domains = get_monitored_domains()
    print(f"[Certificates] Checking {len(domains)} domain(s)...")
    cert_results = check_certificates(domains)
    if cert_results:
        save_cert_checks(cert_results)

    cert_issues = [r for r in cert_results if r["status"] != "ok"]
    for r in cert_results:
        icon = "OK" if r["status"] == "ok" else "WARNING" if r["status"] == "warning" else "FAIL"
        days = f"{r.get('days_remaining', '?')}d" if r["status"] != "fail" else r.get("error", "")
        print(f"  [{icon:7s}] {r['domain']:30s} {days}")

    # 2. Licence checks
    print(f"\n[Licences] Checking licences...")
    licence_results = check_licences()
    lic_issues = [l for l in licence_results if l["status"] != "ok"]
    for l in licence_results:
        icon = "OK" if l["status"] == "ok" else "WARNING" if l["status"] == "warning" else "EXPIRED"
        days = f"{l['days_remaining']}d" if l["days_remaining"] is not None else "perpetual"
        print(f"  [{icon:7s}] {l['issued_to']:30s} {l['licence_type']:15s} {days}")

    # 3. Tracked domain checks
    print(f"\n[Domains] Checking tracked domains...")
    domain_results = check_tracked_domains()
    domain_issues = [d for d in domain_results if d.get("ssl_status") != "ok"]
    ip_changes = [d for d in domain_results if d.get("ip_changed")]
    for d in domain_results:
        ssl = d.get("ssl_status", "?")
        icon = "OK" if ssl == "ok" else "WARNING" if ssl == "warning" else "FAIL"
        days = f"{d.get('ssl_days_remaining', '?')}d" if d.get("ssl_days_remaining") is not None else ""
        ip_note = " [IP CHANGED]" if d.get("ip_changed") else ""
        print(f"  [{icon:7s}] {d['hostname']:30s} {days}{ip_note}")
    if not domain_results:
        print("  No tracked domains.")

    # 3.5. Let's Encrypt auto-renewal
    print(f"\n[Let's Encrypt] Checking auto-renewals...")
    le_results = check_letsencrypt_renewals()
    le_renewed = [r for r in le_results if r.get("action") == "renew" and r.get("success")]
    le_failed = [r for r in le_results if r.get("action") == "renew" and not r.get("success")]
    for r in le_results:
        if r["action"] == "skip":
            print(f"  [SKIP   ] {r['hostname']:30s} {r['message']}")
        elif r.get("success"):
            print(f"  [RENEWED] {r['hostname']:30s} {r['message']}")
        else:
            print(f"  [FAIL   ] {r['hostname']:30s} {r.get('error', '')}")
    if not le_results:
        print("  No domains with auto-renewal enabled.")

    # 4. Product alerts
    print(f"\n[Products] Evaluating alerts...")
    product_alerts = check_products()
    for a in product_alerts:
        print(f"  [{a['level'].upper():8s}] {a['product']:30s} {a['message']}")
    if not product_alerts:
        print("  No critical/high alerts.")

    # 5. Summary
    report = {
        "date": date_str,
        "checked_at": now.isoformat(),
        "certificates": {
            "total": len(cert_results),
            "ok": len([r for r in cert_results if r["status"] == "ok"]),
            "warning": len([r for r in cert_results if r["status"] == "warning"]),
            "expired": len([r for r in cert_results if r["status"] == "expired"]),
            "failed": len([r for r in cert_results if r["status"] == "fail"]),
            "details": cert_results,
        },
        "licences": {
            "total": len(licence_results),
            "ok": len([l for l in licence_results if l["status"] == "ok"]),
            "warning": len([l for l in licence_results if l["status"] == "warning"]),
            "expired": len([l for l in licence_results if l["status"] == "expired"]),
            "details": licence_results,
        },
        "domains": {
            "total": len(domain_results),
            "ok": len([d for d in domain_results if d.get("ssl_status") == "ok"]),
            "warning": len([d for d in domain_results if d.get("ssl_status") == "warning"]),
            "expired": len([d for d in domain_results if d.get("ssl_status") == "expired"]),
            "failed": len([d for d in domain_results if d.get("ssl_status") == "fail"]),
            "ip_changed": len(ip_changes),
            "registration_expiring": len([d for d in domain_results if d.get("registration_days_remaining") is not None and d["registration_days_remaining"] < 90]),
            "details": domain_results,
        },
        "letsencrypt": {
            "total": len(le_results),
            "renewed": len(le_renewed),
            "failed": len(le_failed),
            "skipped": len([r for r in le_results if r["action"] == "skip"]),
            "details": le_results,
        },
        "product_alerts": {
            "total": len(product_alerts),
            "details": product_alerts,
        },
    }

    # Save daily report
    DAILY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DAILY_REPORTS_DIR / f"{date_str}.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))

    # 6. Send notifications for unacknowledged alerts
    try:
        store = SettingsStore(SETTINGS_PATH)
        dispatcher = NotificationDispatcher(store)
        domain_registry = DomainRegistry(DOMAIN_REGISTRY_PATH)
        engine = AlertEngine(
            ProductRegistry(REGISTRY_PATH),
            history_path=ALERTS_HISTORY,
            domain_registry=domain_registry,
        )
        engine.evaluate_all()
        all_alert_objects = engine.get_unacknowledged()
        if all_alert_objects:
            results = dispatcher.dispatch(all_alert_objects, only_unacknowledged=False)
            print(f"\n[Notifications] Dispatched to {len(results)} channel(s): "
                  + ", ".join(f"{k}={'OK' if v else 'FAIL'}" for k, v in results.items()))
        else:
            print("\n[Notifications] No unacknowledged alerts to dispatch.")
    except Exception as e:
        print(f"\n[Notifications] Dispatch failed: {e}")

    # Print summary
    total_issues = len(cert_issues) + len(lic_issues) + len(domain_issues) + len(product_alerts) + len(le_failed)
    print(f"\n{'='*50}")
    print(f"  Certificates: {report['certificates']['ok']}/{report['certificates']['total']} OK")
    print(f"  Domains:      {report['domains']['ok']}/{report['domains']['total']} OK" +
          (f" ({report['domains']['ip_changed']} IP changed)" if report['domains']['ip_changed'] else ""))
    print(f"  Let's Encrypt: {report['letsencrypt']['renewed']} renewed, {report['letsencrypt']['failed']} failed, {report['letsencrypt']['skipped']} skipped")
    print(f"  Licences:     {report['licences']['ok']}/{report['licences']['total']} OK")
    print(f"  Alerts:       {report['product_alerts']['total']} critical/high")
    print(f"  Total issues: {total_issues}")
    print(f"  Report saved: {report_path}")
    print(f"{'='*50}")

    # Exit with non-zero if there are issues (useful for cron alerting)
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
