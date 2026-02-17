#!/usr/bin/env python3
"""
SSL & Licence Management Tool - Main Entry Point.

Usage:
    python main.py ssl generate <name> --cn <domain> [options]
    python main.py ssl list
    python main.py ssl check <domain> [domains...]
    python main.py licence issue <issued_to> [options]
    python main.py licence validate <key>
    python main.py licence list
    python main.py licence revoke <key>
"""

import argparse
import sys

from config.settings import LICENCE_SIGNING_SECRET, LICENCE_STORAGE_PATH
from ssl.certificate import CertificateManager, CertificateInfo
from ssl.monitor import CertificateMonitor
from licence.manager import LicenceManager


def cmd_ssl_generate(args):
    """Generate a self-signed SSL certificate."""
    info = CertificateInfo(
        common_name=args.cn,
        organization=args.org or "",
        country=args.country,
        valid_days=args.days,
        san_domains=args.san or [],
    )
    manager = CertificateManager()
    cert_path = manager.generate_self_signed(args.name, info)
    print(f"Certificate: {cert_path}")
    print(f"Key: {manager.keys_dir / f'{args.name}.key'}")


def cmd_ssl_list(args):
    """List all managed certificates."""
    manager = CertificateManager()
    certs = manager.list_certificates()
    if not certs:
        print("No certificates found.")
        return
    for cert in certs:
        print(f"  {cert['name']:20s}  expires: {cert['expiry']}")


def cmd_ssl_check(args):
    """Check certificate expiry for remote domains."""
    monitor = CertificateMonitor()
    statuses = monitor.check_multiple(args.domains)
    for s in statuses:
        tag = "EXPIRED" if s.is_expired else "OK"
        if not s.is_expired and s.days_remaining <= 30:
            tag = "WARNING"
        print(f"[{tag:7s}] {s.domain:30s} {s.days_remaining:4d} days remaining")
    failed = set(args.domains) - {s.domain for s in statuses}
    for d in failed:
        print(f"[FAIL   ] {d:30s} could not connect")


def cmd_licence_issue(args):
    """Issue a new licence."""
    mgr = LicenceManager(LICENCE_SIGNING_SECRET, str(LICENCE_STORAGE_PATH))
    lic = mgr.issue(
        licence_type=args.type,
        issued_to=args.issued_to,
        valid_days=args.days,
        features=args.features,
        max_users=args.max_users,
    )
    print(f"Key:     {lic.key}")
    print(f"Type:    {lic.licence_type}")
    print(f"To:      {lic.issued_to}")
    expires = lic.expires_at.isoformat() if lic.expires_at else "perpetual"
    print(f"Expires: {expires}")


def cmd_licence_validate(args):
    """Validate a licence key."""
    mgr = LicenceManager(LICENCE_SIGNING_SECRET, str(LICENCE_STORAGE_PATH))
    result = mgr.validate(args.key)
    if result.is_valid:
        print(f"VALID - type: {result.licence_type}")
    else:
        print(f"INVALID - {result.error}")


def cmd_licence_list(args):
    """List all licences."""
    mgr = LicenceManager(LICENCE_SIGNING_SECRET, str(LICENCE_STORAGE_PATH))
    licences = mgr.list_all()
    if not licences:
        print("No licences found.")
        return
    for lic in licences:
        status = "revoked" if lic.get("revoked") else "active"
        print(f"  {lic['key']:40s}  {lic['licence_type']:15s}  [{status}]")


def cmd_licence_revoke(args):
    """Revoke a licence."""
    mgr = LicenceManager(LICENCE_SIGNING_SECRET, str(LICENCE_STORAGE_PATH))
    if mgr.revoke(args.key):
        print(f"Licence revoked: {args.key}")
    else:
        print(f"Licence not found: {args.key}")


def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description="SSL & Licence Management Tool"
    )
    subparsers = parser.add_subparsers(dest="module", help="Module")

    # --- SSL commands ---
    ssl_parser = subparsers.add_parser("ssl", help="SSL certificate management")
    ssl_sub = ssl_parser.add_subparsers(dest="action")

    gen = ssl_sub.add_parser("generate", help="Generate self-signed certificate")
    gen.add_argument("name", help="Certificate name")
    gen.add_argument("--cn", required=True, help="Common Name (domain)")
    gen.add_argument("--org", help="Organization")
    gen.add_argument("--country", default="US", help="Country code")
    gen.add_argument("--days", type=int, default=365, help="Validity days")
    gen.add_argument("--san", nargs="*", help="Subject Alternative Names")
    gen.set_defaults(func=cmd_ssl_generate)

    lst = ssl_sub.add_parser("list", help="List certificates")
    lst.set_defaults(func=cmd_ssl_list)

    chk = ssl_sub.add_parser("check", help="Check domain certificates")
    chk.add_argument("domains", nargs="+", help="Domains to check")
    chk.set_defaults(func=cmd_ssl_check)

    # --- Licence commands ---
    lic_parser = subparsers.add_parser("licence", help="Licence management")
    lic_sub = lic_parser.add_subparsers(dest="action")

    issue = lic_sub.add_parser("issue", help="Issue a new licence")
    issue.add_argument("issued_to", help="Licensee name")
    issue.add_argument(
        "--type",
        choices=["trial", "standard", "professional", "enterprise"],
        default="standard",
    )
    issue.add_argument("--days", type=int, help="Validity days")
    issue.add_argument("--features", nargs="*", help="Features")
    issue.add_argument("--max-users", type=int, default=1, help="Max users")
    issue.set_defaults(func=cmd_licence_issue)

    val = lic_sub.add_parser("validate", help="Validate a licence key")
    val.add_argument("key", help="Licence key")
    val.set_defaults(func=cmd_licence_validate)

    lst2 = lic_sub.add_parser("list", help="List all licences")
    lst2.set_defaults(func=cmd_licence_list)

    rev = lic_sub.add_parser("revoke", help="Revoke a licence")
    rev.add_argument("key", help="Licence key to revoke")
    rev.set_defaults(func=cmd_licence_revoke)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)

    if not hasattr(args, "func"):
        parser.parse_args([args.module, "--help"])
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
