"""DNS discovery service — IP, NS, SOA, reverse DNS, hosting detection, subdomain discovery."""

import socket
import subprocess
from typing import Optional

from tracker.domain import TWO_PART_TLDS


def _get_root_domain(domain: str) -> str:
    """Extract root domain, handling two-part TLDs like .com.tr, .co.uk."""
    parts = domain.split(".")
    suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
    if suffix in TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


# Common subdomain prefixes to probe during discovery
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "api", "cdn", "dev", "staging", "test",
    "admin", "portal", "app", "blog", "shop", "store", "support",
    "docs", "wiki", "git", "gitlab", "jenkins", "ci", "vpn",
    "remote", "webmail", "smtp", "imap", "pop", "ns1", "ns2",
    "mx", "relay", "gateway", "proxy", "lb", "login", "sso",
    "auth", "id", "accounts", "dashboard", "monitor", "status",
    "grafana", "prometheus", "kibana", "elastic", "db", "mysql",
    "postgres", "redis", "mongo", "minio", "s3", "backup",
    "media", "static", "assets", "images", "files", "download",
    "upload", "video", "stream", "ws", "socket", "realtime",
    "m", "mobile", "demo", "sandbox", "beta", "alpha", "legacy",
    "old", "new", "v2", "intranet", "internal", "exchange",
    "autodiscover", "lyncdiscover", "sip", "meet", "teams",
    "owa", "cpanel", "whm", "plesk", "panel",
]

# Known hosting provider patterns (matched against reverse DNS and IP ranges)
HOSTING_PROVIDERS = [
    ("amazonaws.com", "AWS"),
    ("compute.amazonaws.com", "AWS EC2"),
    ("elb.amazonaws.com", "AWS ELB"),
    ("cloudfront.net", "AWS CloudFront"),
    ("s3.amazonaws.com", "AWS S3"),
    ("googleusercontent.com", "Google Cloud"),
    ("google.com", "Google"),
    ("1e100.net", "Google"),
    ("azure", "Microsoft Azure"),
    ("azurewebsites.net", "Azure App Service"),
    ("cloudapp.azure.com", "Azure VM"),
    ("cloudflare", "Cloudflare"),
    ("hetzner", "Hetzner"),
    ("ovh.", "OVH"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode/Akamai"),
    ("akamai", "Akamai"),
    ("fastly", "Fastly"),
    ("vultr.com", "Vultr"),
    ("contabo", "Contabo"),
    ("ionos", "IONOS"),
    ("godaddy", "GoDaddy"),
    ("hostgator", "HostGator"),
    ("bluehost", "Bluehost"),
    ("siteground", "SiteGround"),
    ("wpengine", "WP Engine"),
    ("netlify", "Netlify"),
    ("vercel", "Vercel"),
    ("herokuapp.com", "Heroku"),
    ("render.com", "Render"),
    ("railway.app", "Railway"),
    ("fly.dev", "Fly.io"),
    ("github.io", "GitHub Pages"),
    ("gitlab.io", "GitLab Pages"),
    ("pages.dev", "Cloudflare Pages"),
    ("turk.net", "Turk.net"),
    ("turktelekom", "Turk Telekom"),
    ("superonline", "Superonline"),
    ("doruk.net", "Doruk"),
    ("radore", "Radore"),
    ("medianova", "Medianova"),
]


def _run_whois(domain: str, timeout: int = 30) -> str:
    """Run a whois command and return stdout."""
    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _run_dig(args: list[str], timeout: int = 10) -> str:
    """Run a dig command and return stdout."""
    try:
        result = subprocess.run(
            ["dig"] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


class DnsService:
    """DNS lookup service for domain information gathering."""

    def lookup_ip(self, hostname: str) -> str:
        """Resolve hostname to IP address using socket."""
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            if results:
                return results[0][4][0]
        except (socket.gaierror, OSError):
            pass
        return ""

    def lookup_nameservers(self, domain: str) -> list[str]:
        """Get NS records for a domain using dig."""
        output = _run_dig(["NS", domain, "+short"])
        if not output:
            return []
        return [
            line.rstrip(".")
            for line in output.splitlines()
            if line.strip() and not line.startswith(";")
        ]

    def lookup_soa(self, domain: str) -> dict:
        """Get SOA record for a domain.

        Returns dict with: primary_ns, admin_email, serial, refresh, retry, expire, minimum_ttl
        """
        output = _run_dig(["SOA", domain, "+short"])
        if not output:
            return {}

        # SOA format: primary_ns admin_email serial refresh retry expire minimum
        parts = output.split()
        if len(parts) < 7:
            return {}

        return {
            "primary_ns": parts[0].rstrip("."),
            "admin_email": parts[1].rstrip(".").replace(".", "@", 1),
            "serial": int(parts[2]) if parts[2].isdigit() else 0,
            "refresh": int(parts[3]) if parts[3].isdigit() else 0,
            "retry": int(parts[4]) if parts[4].isdigit() else 0,
            "expire": int(parts[5]) if parts[5].isdigit() else 0,
            "minimum_ttl": int(parts[6]) if parts[6].isdigit() else 0,
        }

    def lookup_reverse_dns(self, ip: str) -> str:
        """Get PTR record (reverse DNS) for an IP address."""
        if not ip:
            return ""
        output = _run_dig(["-x", ip, "+short"])
        if output:
            return output.splitlines()[0].rstrip(".")
        return ""

    def detect_hosting_provider(self, ip: str, reverse_dns: str) -> str:
        """Detect hosting provider from IP and reverse DNS."""
        check_str = (reverse_dns + " " + ip).lower()
        for pattern, provider in HOSTING_PROVIDERS:
            if pattern.lower() in check_str:
                return provider
        return ""

    def lookup_whois(self, domain: str) -> dict:
        """Get WHOIS registration data for a domain.

        Returns dict with: registrar, registration_expiry, domain_created_date,
        registration_days_remaining, dnssec
        """
        from datetime import datetime, timezone

        # Always query the root domain
        root_domain = _get_root_domain(domain)

        output = _run_whois(root_domain)
        if not output:
            return {}

        result = {}
        for line in output.splitlines():
            line_lower = line.strip().lower()

            # Registrar — standard format
            if line_lower.startswith("registrar:"):
                val = line.split(":", 1)[1].strip()
                if val and not result.get("registrar"):
                    result["registrar"] = val

            # Registrar — Turkish WHOIS format (Organization Name)
            if "organization name" in line_lower and ":" in line:
                val = line.split(":", 1)[1].strip()
                if val and not result.get("registrar"):
                    result["registrar"] = val

            # Expiry date — multiple possible field names
            if any(key in line_lower for key in [
                "registry expiry date:", "registrar registration expiration date:",
                "expiration date:", "expires on", "expiry date:", "paid-till:",
                "expire date:", "renewal date:",
            ]):
                val = line.split(":", 1)[1].strip().rstrip(".") if ":" in line else ""
                parsed = self._parse_whois_date(val)
                if parsed and not result.get("registration_expiry"):
                    result["registration_expiry"] = parsed

            # Creation date
            if any(key in line_lower for key in [
                "creation date:", "created:", "created on", "registration date:",
                "created date:", "domain name commencement date:",
            ]):
                val = line.split(":", 1)[1].strip().rstrip(".") if ":" in line else ""
                parsed = self._parse_whois_date(val)
                if parsed and not result.get("domain_created_date"):
                    result["domain_created_date"] = parsed

            # DNSSEC
            if line_lower.startswith("dnssec:"):
                val = line.split(":", 1)[1].strip()
                if val:
                    result["dnssec"] = val.lower()

        # Calculate days remaining
        if result.get("registration_expiry"):
            now = datetime.now(timezone.utc)
            expiry = result["registration_expiry"]
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            result["registration_days_remaining"] = (expiry - now).days

        return result

    @staticmethod
    def _parse_whois_date(date_str: str) -> Optional["datetime"]:
        """Try multiple date formats common in WHOIS output."""
        from datetime import datetime, timezone

        date_str = date_str.strip()
        if not date_str:
            return None

        formats = [
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d",
            "%Y-%b-%d",              # Turkish WHOIS: 2022-Sep-14
            "%d-%b-%Y",
            "%d.%m.%Y",
            "%d/%m/%Y",
            "%Y/%m/%d",
            "%b %d %Y",
            "%d-%b-%Y %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S %Z",
            "%Y-%m-%d %H:%M:%S%z",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        return None

    def discover_subdomains(self, domain: str) -> list[dict]:
        """Discover subdomains by probing common prefixes.

        Returns list of dicts: {subdomain, ip, resolvable}
        """
        results = []
        for prefix in COMMON_SUBDOMAINS:
            fqdn = f"{prefix}.{domain}"
            ip = self.lookup_ip(fqdn)
            results.append({
                "subdomain": fqdn,
                "ip": ip,
                "resolvable": bool(ip),
            })
        return results

    def full_lookup(self, hostname: str) -> dict:
        """Run all DNS lookups for a hostname and return consolidated results."""
        # Determine root domain for NS/SOA lookups
        root_domain = _get_root_domain(hostname)

        ip = self.lookup_ip(hostname)
        nameservers = self.lookup_nameservers(root_domain)
        soa = self.lookup_soa(root_domain)
        reverse_dns = self.lookup_reverse_dns(ip)
        hosting = self.detect_hosting_provider(ip, reverse_dns)
        whois = self.lookup_whois(root_domain)

        return {
            "ip_address": ip,
            "nameservers": nameservers,
            "soa_primary_ns": soa.get("primary_ns", ""),
            "soa_admin_email": soa.get("admin_email", ""),
            "soa_serial": soa.get("serial", 0),
            "soa_refresh": soa.get("refresh", 0),
            "soa_retry": soa.get("retry", 0),
            "soa_expire": soa.get("expire", 0),
            "soa_minimum_ttl": soa.get("minimum_ttl", 0),
            "reverse_dns": reverse_dns,
            "hosting_provider": hosting,
            "registrar": whois.get("registrar", ""),
            "registration_expiry": whois.get("registration_expiry"),
            "registration_days_remaining": whois.get("registration_days_remaining"),
            "domain_created_date": whois.get("domain_created_date"),
            "dnssec": whois.get("dnssec", ""),
        }
