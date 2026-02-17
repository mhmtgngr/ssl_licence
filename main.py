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
    python main.py tracker add <name> --vendor <v> --version <v> --category <c> [options]
    python main.py tracker list [--category <c>] [--vendor <v>]
    python main.py tracker alerts [--level critical]
    python main.py tracker search <query>
    python main.py tracker dashboard
    python main.py tracker report [--type expiry|compliance|cost] [--output file.json]
    python main.py tracker analyze
    python main.py tracker catalogue microsoft|cloud|network
"""

import argparse
import json
import sys
from datetime import datetime

from config.settings import LICENCE_SIGNING_SECRET, LICENCE_STORAGE_PATH
from sslcert.certificate import CertificateManager, CertificateInfo
from sslcert.monitor import CertificateMonitor
from licence.manager import LicenceManager
from tracker.product import Product, ProductCategory, LicenceType
from tracker.registry import ProductRegistry
from tracker.alert_engine import AlertEngine, AlertLevel
from tracker.search import SearchEngine
from tracker.reports import ReportGenerator
from tracker.ai.analyzer import LicenceAnalyzer
from tracker.notifications.notifier import ConsoleNotifier, FileNotifier


# ============================================================
# SSL Commands
# ============================================================

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


# ============================================================
# Licence Commands
# ============================================================

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


# ============================================================
# Tracker Commands
# ============================================================

REGISTRY_PATH = "data/products/registry.json"


def _get_registry():
    return ProductRegistry(REGISTRY_PATH)


def _get_alert_engine(registry):
    return AlertEngine(registry)


def cmd_tracker_add(args):
    """Add a product to the tracker."""
    registry = _get_registry()

    product = Product(
        name=args.name,
        vendor=args.vendor,
        version=args.version,
        category=ProductCategory(args.category),
        licence_type=LicenceType(args.licence_type) if args.licence_type else LicenceType.SUBSCRIPTION,
        licence_key=args.licence_key or "",
        licence_quantity=args.quantity or 1,
        licence_expiry=_parse_date(args.expiry),
        mainstream_support_end=_parse_date(args.support_end),
        extended_support_end=_parse_date(args.extended_end),
        end_of_life=_parse_date(args.eol),
        annual_cost=args.cost or 0.0,
        environment=args.env or "production",
        department=args.department or "",
        owner=args.owner or "",
        notes=args.notes or "",
        tags=args.tags or [],
    )

    registry.add(product)
    print(f"Product added: {product.name} ({product.vendor} {product.version})")
    print(f"  ID: {product.product_id}")
    print(f"  Category: {product.category.value}")
    if product.licence_expiry:
        print(f"  Licence Expiry: {product.licence_expiry.strftime('%Y-%m-%d')}")
    if product.mainstream_support_end:
        print(f"  Support End: {product.mainstream_support_end.strftime('%Y-%m-%d')}")


def cmd_tracker_list(args):
    """List tracked products."""
    registry = _get_registry()

    if args.category:
        products = registry.by_category(ProductCategory(args.category))
    elif args.vendor:
        products = registry.by_vendor(args.vendor)
    elif args.status:
        from tracker.product import SupportStatus
        products = registry.by_status(SupportStatus(args.status))
    else:
        products = registry.list_all()

    if not products:
        print("No products found.")
        return

    print(f"\n{'Name':30s} {'Vendor':20s} {'Version':10s} {'Category':18s} {'Status':15s} {'Expiry':12s}")
    print("-" * 110)
    for p in products:
        expiry = "N/A"
        if p.licence_expiry:
            days = p.days_until_licence_expiry()
            expiry = f"{days}d" if days is not None else "N/A"
        print(
            f"{p.name:30s} {p.vendor:20s} {p.version:10s} "
            f"{p.category.value:18s} {p.support_status().value:15s} {expiry:12s}"
        )
    print(f"\nTotal: {len(products)} product(s)")


def cmd_tracker_alerts(args):
    """Show alerts for tracked products."""
    registry = _get_registry()
    engine = _get_alert_engine(registry)
    all_alerts = engine.evaluate_all()

    if args.level:
        level = AlertLevel(args.level)
        all_alerts = engine.get_alerts(level=level)

    if args.vendor:
        all_alerts = [a for a in all_alerts if args.vendor.lower() in a.vendor.lower()]

    notifier = ConsoleNotifier()
    notifier.send(all_alerts)

    # Also log to file
    file_notifier = FileNotifier()
    file_notifier.send(all_alerts)


def cmd_tracker_search(args):
    """Search products."""
    registry = _get_registry()
    search = SearchEngine(registry)

    category = ProductCategory(args.category) if args.category else None
    results = search.search(
        query=args.query,
        category=category,
        vendor=args.vendor,
        sort_by=args.sort or "relevance",
    )

    if not results:
        print("No results found.")
        return

    print(f"\nSearch results for: '{args.query}'\n")
    for r in results:
        p = r.product
        print(f"  [{r.score:.1f}] {p.name} ({p.vendor} {p.version}) — {p.category.value}")
        if r.matched_fields:
            print(f"         matched: {', '.join(r.matched_fields)}")
    print(f"\n{len(results)} result(s)")


def cmd_tracker_dashboard(args):
    """Show tracking dashboard."""
    registry = _get_registry()
    engine = _get_alert_engine(registry)
    engine.evaluate_all()
    report_gen = ReportGenerator(registry, engine)
    print(report_gen.format_text_summary())


def cmd_tracker_report(args):
    """Generate reports."""
    registry = _get_registry()
    engine = _get_alert_engine(registry)
    engine.evaluate_all()
    report_gen = ReportGenerator(registry, engine)

    report_type = args.report_type or "expiry"

    if report_type == "expiry":
        report = report_gen.expiry_report(days_ahead=args.days or 180)
    elif report_type == "compliance":
        report = report_gen.compliance_report()
    elif report_type == "cost":
        report = report_gen.cost_report()
    elif report_type == "dashboard":
        report = report_gen.dashboard_report()
    else:
        print(f"Unknown report type: {report_type}")
        return

    if args.output:
        report_gen.export_json(report, args.output)
        print(f"Report saved to: {args.output}")
    else:
        print(json.dumps(report, indent=2, default=str))


def cmd_tracker_analyze(args):
    """Run AI-powered analysis."""
    registry = _get_registry()
    analyzer = LicenceAnalyzer(registry)

    if args.risk:
        assessments = analyzer.risk_assessment()
        print("\nRisk Assessment")
        print("=" * 60)
        for a in assessments:
            print(f"\n  [{a.risk_score:4.1f}/10] {a.product_name}")
            for f in a.risk_factors:
                print(f"    - {f}")
            if a.mitigation:
                print(f"    Mitigation:")
                for m in a.mitigation:
                    print(f"      > {m}")
    elif args.upgrade:
        plans = analyzer.upgrade_plan()
        print("\nUpgrade Plan")
        print("=" * 60)
        for p in plans:
            print(f"\n  {p['product_name']} ({p['vendor']}) v{p['current_version']}")
            print(f"    Status: {p['current_status']}")
            print(f"    Urgency: {p['urgency_score']}/10")
            print(f"    Action: {p['recommended_action']}")
            print(f"    Target: {p['suggested_target']}")
    elif args.cost:
        recs = analyzer.cost_optimization()
        print("\nCost Optimization")
        print("=" * 60)
        for r in recs:
            print(f"\n  [{r.priority.upper()}] {r.title}")
            print(f"    {r.description}")
            print(f"    Action: {r.suggested_action}")
    else:
        report = analyzer.generate_full_report()
        if args.output:
            from pathlib import Path
            Path(args.output).write_text(json.dumps(report, indent=2, default=str))
            print(f"AI analysis saved to: {args.output}")
        else:
            s = report["summary"]
            print("\nAI Analysis Summary")
            print("=" * 60)
            print(f"  Recommendations:  {s['total_recommendations']}")
            print(f"  Critical:         {s['critical_recommendations']}")
            print(f"  High-risk items:  {s['high_risk_products']}")
            print(f"  Upgrade needed:   {s['upgrade_candidates']}")
            print(f"  Cost savings:     {s['cost_optimizations']}")

            if report["recommendations"]:
                print("\nTop Recommendations:")
                for r in report["recommendations"][:5]:
                    print(f"  [{r['priority'].upper():8s}] {r['title']}")
                    print(f"             {r['action']}")


def cmd_tracker_catalogue(args):
    """Show built-in product catalogues."""
    if args.catalogue == "microsoft":
        from tracker.products.microsoft import list_microsoft_products
        products = list_microsoft_products()
        print(f"\nMicrosoft Product Lifecycle ({len(products)} entries)")
        print("=" * 80)
        for p in products:
            ms_end = p.get("mainstream_support_end", "N/A")
            ext_end = p.get("extended_support_end", "N/A")
            notes = p.get("notes", "")
            print(f"  {p['product']:25s} {p['version']:10s}  MS:{ms_end:12s}  EXT:{ext_end:12s}  {notes}")

    elif args.catalogue == "cloud":
        from tracker.products.cloud import list_cloud_services
        services = list_cloud_services()
        print(f"\nCloud Services ({len(services)} entries)")
        print("=" * 60)
        for s in services:
            print(f"  {s['provider']:8s}  {s['service']:25s}  {s['category']}")

    elif args.catalogue == "network":
        from tracker.products.network import list_network_products
        products = list_network_products()
        print(f"\nNetwork Products ({len(products)} entries)")
        print("=" * 80)
        for p in products:
            eos = p.get("end_of_support", "N/A")
            print(f"  {p['vendor']:22s} {p['product']:20s} {p['version']:10s}  EOS:{eos}")

    else:
        print(f"Unknown catalogue: {args.catalogue}")
        print("Available: microsoft, cloud, network")


# ============================================================
# Helpers
# ============================================================

def _parse_date(date_str: str) -> datetime | None:
    """Parse a date string (YYYY-MM-DD) or return None."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        try:
            return datetime.fromisoformat(date_str)
        except ValueError:
            return None


# ============================================================
# Parser
# ============================================================

def build_parser():
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        description="SSL, Licence & Product Tracking Management Tool"
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

    # --- Tracker commands ---
    trk_parser = subparsers.add_parser("tracker", help="Product licence & support tracker")
    trk_sub = trk_parser.add_subparsers(dest="action")

    # tracker add
    add = trk_sub.add_parser("add", help="Add a product to track")
    add.add_argument("name", help="Product name")
    add.add_argument("--vendor", required=True, help="Vendor name")
    add.add_argument("--version", required=True, help="Version")
    add.add_argument(
        "--category", required=True,
        choices=[c.value for c in ProductCategory],
        help="Product category",
    )
    add.add_argument("--licence-type", choices=[t.value for t in LicenceType])
    add.add_argument("--licence-key", help="Licence key")
    add.add_argument("--quantity", type=int, help="Licence quantity")
    add.add_argument("--expiry", help="Licence expiry date (YYYY-MM-DD)")
    add.add_argument("--support-end", help="Mainstream support end (YYYY-MM-DD)")
    add.add_argument("--extended-end", help="Extended support end (YYYY-MM-DD)")
    add.add_argument("--eol", help="End of life date (YYYY-MM-DD)")
    add.add_argument("--cost", type=float, help="Annual cost")
    add.add_argument("--env", help="Environment (production/staging/dev)")
    add.add_argument("--department", help="Department")
    add.add_argument("--owner", help="Owner name")
    add.add_argument("--notes", help="Notes")
    add.add_argument("--tags", nargs="*", help="Tags")
    add.set_defaults(func=cmd_tracker_add)

    # tracker list
    tl = trk_sub.add_parser("list", help="List tracked products")
    tl.add_argument("--category", choices=[c.value for c in ProductCategory])
    tl.add_argument("--vendor", help="Filter by vendor")
    tl.add_argument("--status", choices=["active", "extended", "end_of_support", "end_of_life"])
    tl.set_defaults(func=cmd_tracker_list)

    # tracker alerts
    ta = trk_sub.add_parser("alerts", help="Show licence/support alerts")
    ta.add_argument("--level", choices=[l.value for l in AlertLevel])
    ta.add_argument("--vendor", help="Filter by vendor")
    ta.set_defaults(func=cmd_tracker_alerts)

    # tracker search
    ts = trk_sub.add_parser("search", help="Search products")
    ts.add_argument("query", help="Search query")
    ts.add_argument("--category", choices=[c.value for c in ProductCategory])
    ts.add_argument("--vendor", help="Filter by vendor")
    ts.add_argument("--sort", choices=["relevance", "expiry_asc", "expiry_desc", "name", "vendor"])
    ts.set_defaults(func=cmd_tracker_search)

    # tracker dashboard
    td = trk_sub.add_parser("dashboard", help="Show tracking dashboard")
    td.set_defaults(func=cmd_tracker_dashboard)

    # tracker report
    tr = trk_sub.add_parser("report", help="Generate reports")
    tr.add_argument("--type", dest="report_type", choices=["expiry", "compliance", "cost", "dashboard"])
    tr.add_argument("--days", type=int, help="Days ahead for expiry report")
    tr.add_argument("--output", help="Output file path")
    tr.set_defaults(func=cmd_tracker_report)

    # tracker analyze
    tz = trk_sub.add_parser("analyze", help="AI-powered analysis")
    tz.add_argument("--risk", action="store_true", help="Risk assessment")
    tz.add_argument("--upgrade", action="store_true", help="Upgrade plan")
    tz.add_argument("--cost", action="store_true", help="Cost optimization")
    tz.add_argument("--output", help="Save full report to file")
    tz.set_defaults(func=cmd_tracker_analyze)

    # tracker catalogue
    tc = trk_sub.add_parser("catalogue", help="Browse product catalogues")
    tc.add_argument("catalogue", choices=["microsoft", "cloud", "network"])
    tc.set_defaults(func=cmd_tracker_catalogue)

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
