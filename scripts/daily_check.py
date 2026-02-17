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

from config.settings import CERT_EXPIRY_WARNING_DAYS, LICENCE_SIGNING_SECRET
from sslcert.monitor import CertificateMonitor
from licence.manager import LicenceManager
from tracker.registry import ProductRegistry
from tracker.alert_engine import AlertEngine

DATA_DIR = PROJECT_ROOT / "data"
CERT_CHECKS_PATH = DATA_DIR / "cert_checks.json"
DAILY_REPORTS_DIR = DATA_DIR / "daily_reports"
REGISTRY_PATH = str(DATA_DIR / "products" / "registry.json")
LICENCE_STORAGE = str(DATA_DIR / "licences.json")
ALERTS_HISTORY = str(DATA_DIR / "alerts_history.json")


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

    # 3. Product alerts
    print(f"\n[Products] Evaluating alerts...")
    product_alerts = check_products()
    for a in product_alerts:
        print(f"  [{a['level'].upper():8s}] {a['product']:30s} {a['message']}")
    if not product_alerts:
        print("  No critical/high alerts.")

    # 4. Summary
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
        "product_alerts": {
            "total": len(product_alerts),
            "details": product_alerts,
        },
    }

    # Save daily report
    DAILY_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    report_path = DAILY_REPORTS_DIR / f"{date_str}.json"
    report_path.write_text(json.dumps(report, indent=2, default=str))

    # Print summary
    total_issues = len(cert_issues) + len(lic_issues) + len(product_alerts)
    print(f"\n{'='*50}")
    print(f"  Certificates: {report['certificates']['ok']}/{report['certificates']['total']} OK")
    print(f"  Licences:     {report['licences']['ok']}/{report['licences']['total']} OK")
    print(f"  Alerts:       {report['product_alerts']['total']} critical/high")
    print(f"  Total issues: {total_issues}")
    print(f"  Report saved: {report_path}")
    print(f"{'='*50}")

    # Exit with non-zero if there are issues (useful for cron alerting)
    sys.exit(1 if total_issues > 0 else 0)


if __name__ == "__main__":
    main()
