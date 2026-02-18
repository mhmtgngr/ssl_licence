"""Domain data model for DNS, SSL, SOA, and hosting tracking."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# Known two-part public suffixes (ccSLDs) for correct domain classification
TWO_PART_TLDS = {
    "com.tr", "org.tr", "net.tr", "gov.tr", "edu.tr", "gen.tr",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "org.au", "gov.au", "net.au", "edu.au",
    "com.br", "org.br", "gov.br", "net.br",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "org.in", "gov.in", "net.in", "ac.in",
    "co.za", "org.za", "gov.za", "net.za", "ac.za",
    "co.nz", "org.nz", "net.nz", "govt.nz", "ac.nz",
    "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr",
    "com.mx", "org.mx", "gob.mx", "net.mx", "edu.mx",
    "com.cn", "org.cn", "gov.cn", "net.cn", "edu.cn",
    "com.tw", "org.tw", "gov.tw", "net.tw", "edu.tw",
    "co.il", "org.il", "gov.il", "ac.il", "net.il",
    "com.ar", "org.ar", "gov.ar", "net.ar", "edu.ar",
    "com.pl", "org.pl", "gov.pl", "net.pl", "edu.pl",
    "co.id", "or.id", "go.id", "ac.id", "web.id",
    "com.my", "org.my", "gov.my", "net.my", "edu.my",
    "com.sg", "org.sg", "gov.sg", "net.sg", "edu.sg",
    "com.hk", "org.hk", "gov.hk", "net.hk", "edu.hk",
}


class DomainType(str, Enum):
    """Classification of domain entry."""

    ROOT = "root"
    SUBDOMAIN = "subdomain"
    WILDCARD = "wildcard"


class CertificateType(str, Enum):
    """SSL certificate type classification."""

    SINGLE = "single"              # Standard single-domain certificate
    WILDCARD = "wildcard"          # Wildcard certificate (*.example.com)
    SAN = "san"                    # SAN / multi-domain certificate
    UNKNOWN = "unknown"            # Not yet determined


class DomainStatus(str, Enum):
    """Current status of a tracked domain."""

    ACTIVE = "active"
    EXPIRING = "expiring"          # SSL cert expiring within warning threshold
    EXPIRED = "expired"            # SSL cert expired
    UNREACHABLE = "unreachable"    # Cannot connect / DNS fails
    INACTIVE = "inactive"          # Manually disabled


@dataclass
class Domain:
    """A tracked domain with SSL, DNS, SOA, and hosting information."""

    # Identity
    hostname: str
    parent_domain: str = ""
    domain_type: DomainType = DomainType.ROOT
    status: DomainStatus = DomainStatus.ACTIVE

    # SSL info (populated on check)
    ssl_issuer: str = ""
    ssl_expiry: Optional[datetime] = None
    ssl_days_remaining: Optional[int] = None
    ssl_status: str = ""             # ok/warning/expired/fail
    ssl_certificate_type: CertificateType = CertificateType.UNKNOWN
    ssl_san_domains: list[str] = field(default_factory=list)
    ssl_ca_name: str = ""                # Friendly CA name (Let's Encrypt, Sectigo, etc.)

    # DNS info
    ip_address: str = ""
    nameservers: list[str] = field(default_factory=list)

    # SOA record fields
    soa_primary_ns: str = ""
    soa_admin_email: str = ""
    soa_serial: int = 0
    soa_refresh: int = 0
    soa_retry: int = 0
    soa_expire: int = 0
    soa_minimum_ttl: int = 0

    # Hosting info
    reverse_dns: str = ""
    hosting_provider: str = ""

    # Registration / WHOIS info
    registrar: str = ""
    registration_expiry: Optional[datetime] = None
    registration_days_remaining: Optional[int] = None
    domain_created_date: Optional[datetime] = None
    dnssec: str = ""

    # Let's Encrypt
    le_enabled: bool = False
    le_cert_path: str = ""
    le_key_path: str = ""
    le_last_renewed: Optional[datetime] = None
    le_auto_renew: bool = False
    le_challenge_type: str = "http"  # "http" or "dns"

    # Metadata
    domain_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    notes: str = ""
    tags: list[str] = field(default_factory=list)
    warning_days: int = 30
    auto_discovered: bool = False
    last_checked: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def classify(self) -> None:
        """Auto-classify domain type and detect parent domain."""
        hostname = self.hostname.strip().lower()
        self.hostname = hostname

        if hostname.startswith("*."):
            self.domain_type = DomainType.WILDCARD
            self.parent_domain = hostname[2:]
            return

        parts = hostname.split(".")
        suffix = ".".join(parts[-2:]) if len(parts) >= 2 else ""
        is_ccsld = suffix in TWO_PART_TLDS
        effective_parts = len(parts) - 1 if is_ccsld else len(parts)

        if len(parts) > 2 and effective_parts > 2:
            self.domain_type = DomainType.SUBDOMAIN
            self.parent_domain = ".".join(parts[-3:]) if is_ccsld else ".".join(parts[-2:])
        else:
            self.domain_type = DomainType.ROOT
            self.parent_domain = hostname

    def to_dict(self) -> dict:
        """Serialize domain to dictionary."""
        def fmt_dt(dt):
            return dt.isoformat() if dt else None

        return {
            "domain_id": self.domain_id,
            "hostname": self.hostname,
            "parent_domain": self.parent_domain,
            "domain_type": self.domain_type.value,
            "status": self.status.value,
            "ssl_issuer": self.ssl_issuer,
            "ssl_expiry": fmt_dt(self.ssl_expiry),
            "ssl_days_remaining": self.ssl_days_remaining,
            "ssl_status": self.ssl_status,
            "ssl_certificate_type": self.ssl_certificate_type.value,
            "ssl_san_domains": self.ssl_san_domains,
            "ssl_ca_name": self.ssl_ca_name,
            "ip_address": self.ip_address,
            "nameservers": self.nameservers,
            "soa_primary_ns": self.soa_primary_ns,
            "soa_admin_email": self.soa_admin_email,
            "soa_serial": self.soa_serial,
            "soa_refresh": self.soa_refresh,
            "soa_retry": self.soa_retry,
            "soa_expire": self.soa_expire,
            "soa_minimum_ttl": self.soa_minimum_ttl,
            "reverse_dns": self.reverse_dns,
            "hosting_provider": self.hosting_provider,
            "registrar": self.registrar,
            "registration_expiry": fmt_dt(self.registration_expiry),
            "registration_days_remaining": self.registration_days_remaining,
            "domain_created_date": fmt_dt(self.domain_created_date),
            "dnssec": self.dnssec,
            "le_enabled": self.le_enabled,
            "le_cert_path": self.le_cert_path,
            "le_key_path": self.le_key_path,
            "le_last_renewed": fmt_dt(self.le_last_renewed),
            "le_auto_renew": self.le_auto_renew,
            "le_challenge_type": self.le_challenge_type,
            "notes": self.notes,
            "tags": self.tags,
            "warning_days": self.warning_days,
            "auto_discovered": self.auto_discovered,
            "last_checked": fmt_dt(self.last_checked),
            "created_at": fmt_dt(self.created_at),
            "updated_at": fmt_dt(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Domain":
        """Deserialize domain from dictionary."""
        def parse_dt(val):
            if not val:
                return None
            return datetime.fromisoformat(val)

        return cls(
            domain_id=data.get("domain_id", uuid.uuid4().hex[:12]),
            hostname=data["hostname"],
            parent_domain=data.get("parent_domain", ""),
            domain_type=DomainType(data.get("domain_type", "root")),
            status=DomainStatus(data.get("status", "active")),
            ssl_issuer=data.get("ssl_issuer", ""),
            ssl_expiry=parse_dt(data.get("ssl_expiry")),
            ssl_days_remaining=data.get("ssl_days_remaining"),
            ssl_status=data.get("ssl_status", ""),
            ssl_certificate_type=CertificateType(data.get("ssl_certificate_type", "unknown")),
            ssl_san_domains=data.get("ssl_san_domains", []),
            ssl_ca_name=data.get("ssl_ca_name", ""),
            ip_address=data.get("ip_address", ""),
            nameservers=data.get("nameservers", []),
            soa_primary_ns=data.get("soa_primary_ns", ""),
            soa_admin_email=data.get("soa_admin_email", ""),
            soa_serial=data.get("soa_serial", 0),
            soa_refresh=data.get("soa_refresh", 0),
            soa_retry=data.get("soa_retry", 0),
            soa_expire=data.get("soa_expire", 0),
            soa_minimum_ttl=data.get("soa_minimum_ttl", 0),
            reverse_dns=data.get("reverse_dns", ""),
            hosting_provider=data.get("hosting_provider", ""),
            registrar=data.get("registrar", ""),
            registration_expiry=parse_dt(data.get("registration_expiry")),
            registration_days_remaining=data.get("registration_days_remaining"),
            domain_created_date=parse_dt(data.get("domain_created_date")),
            dnssec=data.get("dnssec", ""),
            le_enabled=data.get("le_enabled", False),
            le_cert_path=data.get("le_cert_path", ""),
            le_key_path=data.get("le_key_path", ""),
            le_last_renewed=parse_dt(data.get("le_last_renewed")),
            le_auto_renew=data.get("le_auto_renew", False),
            le_challenge_type=data.get("le_challenge_type", "http"),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            warning_days=data.get("warning_days", 30),
            auto_discovered=data.get("auto_discovered", False),
            last_checked=parse_dt(data.get("last_checked")),
            created_at=parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            updated_at=parse_dt(data.get("updated_at")) or datetime.now(timezone.utc),
        )
