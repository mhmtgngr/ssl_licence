#!/usr/bin/env python3
"""Script to check SSL certificate expiry for domains."""

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sslcert.monitor import CertificateMonitor
from config.settings import CERT_EXPIRY_WARNING_DAYS


def main():
    parser = argparse.ArgumentParser(
        description="Check SSL certificate expiry for domains"
    )
    parser.add_argument("domains", nargs="+", help="Domains to check")
    parser.add_argument(
        "--warn-days",
        type=int,
        default=CERT_EXPIRY_WARNING_DAYS,
        help="Warning threshold in days",
    )
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument(
        "--output", help="Save report to file (implies --json)"
    )

    args = parser.parse_args()
    monitor = CertificateMonitor()

    statuses = monitor.check_multiple(args.domains)

    if args.output:
        monitor.export_report(statuses, args.output)
        print(f"Report saved to {args.output}")
        return

    for status in statuses:
        indicator = "EXPIRED" if status.is_expired else "OK"
        if not status.is_expired and status.days_remaining <= args.warn_days:
            indicator = "WARNING"

        print(f"[{indicator}] {status.domain}")
        print(f"  Issuer:  {status.issuer}")
        print(f"  Expiry:  {status.not_after.isoformat()}")
        print(f"  Days remaining: {status.days_remaining}")
        print()

    failed = [d for d in args.domains if d not in {s.domain for s in statuses}]
    if failed:
        print(f"Failed to check: {', '.join(failed)}")


if __name__ == "__main__":
    main()
