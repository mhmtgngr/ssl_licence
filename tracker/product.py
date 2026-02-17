"""Core product data model for licence and support tracking."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ProductCategory(str, Enum):
    """Categories of trackable products."""

    MICROSOFT = "microsoft"
    CLOUD_PLATFORM = "cloud_platform"
    LOAD_BALANCER = "load_balancer"
    NETWORK_EQUIPMENT = "network_equipment"
    DATABASE = "database"
    OPERATING_SYSTEM = "operating_system"
    SECURITY = "security"
    VIRTUALIZATION = "virtualization"
    CONTAINER = "container"
    MIDDLEWARE = "middleware"
    SSL_CERTIFICATE = "ssl_certificate"
    SOFTWARE_LICENCE = "software_licence"
    SAAS = "saas"
    OTHER = "other"


class SupportStatus(str, Enum):
    """Lifecycle status of a product."""

    ACTIVE = "active"                        # Fully supported
    MAINSTREAM_END = "mainstream_end"         # Mainstream support ended
    EXTENDED = "extended"                     # In extended support phase
    END_OF_SUPPORT = "end_of_support"        # Support has ended
    END_OF_LIFE = "end_of_life"              # Product is fully retired
    UNKNOWN = "unknown"


class LicenceType(str, Enum):
    """Types of licences / subscriptions."""

    PERPETUAL = "perpetual"
    SUBSCRIPTION = "subscription"
    VOLUME = "volume"
    OEM = "oem"
    TRIAL = "trial"
    OPEN_SOURCE = "open_source"
    ENTERPRISE_AGREEMENT = "enterprise_agreement"
    CSP = "csp"                              # Cloud Solution Provider
    PAY_AS_YOU_GO = "pay_as_you_go"


@dataclass
class Product:
    """A tracked product with licence and support lifecycle data."""

    # Identity
    name: str
    vendor: str
    version: str
    category: ProductCategory

    # Licence info
    licence_type: LicenceType = LicenceType.SUBSCRIPTION
    licence_key: str = ""
    licence_quantity: int = 1

    # Important dates
    purchase_date: Optional[datetime] = None
    licence_start: Optional[datetime] = None
    licence_expiry: Optional[datetime] = None
    mainstream_support_end: Optional[datetime] = None
    extended_support_end: Optional[datetime] = None
    end_of_life: Optional[datetime] = None

    # Costs
    annual_cost: float = 0.0
    currency: str = "USD"

    # Metadata
    product_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    environment: str = "production"          # production, staging, dev, dr
    department: str = ""
    owner: str = ""
    notes: str = ""
    tags: list[str] = field(default_factory=list)

    # State
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def support_status(self) -> SupportStatus:
        """Determine current support lifecycle status."""
        now = datetime.utcnow()

        if self.end_of_life and now >= self.end_of_life:
            return SupportStatus.END_OF_LIFE

        if self.extended_support_end and now >= self.extended_support_end:
            return SupportStatus.END_OF_SUPPORT

        if self.mainstream_support_end and now >= self.mainstream_support_end:
            if self.extended_support_end:
                return SupportStatus.EXTENDED
            return SupportStatus.END_OF_SUPPORT

        if self.mainstream_support_end or self.licence_expiry:
            return SupportStatus.ACTIVE

        return SupportStatus.UNKNOWN

    def days_until_licence_expiry(self) -> Optional[int]:
        """Days remaining until licence expires."""
        if not self.licence_expiry:
            return None
        return (self.licence_expiry - datetime.utcnow()).days

    def days_until_support_end(self) -> Optional[int]:
        """Days remaining until earliest support end date."""
        now = datetime.utcnow()
        dates = [
            d for d in [
                self.mainstream_support_end,
                self.extended_support_end,
                self.end_of_life,
            ] if d and d > now
        ]
        if not dates:
            return None
        nearest = min(dates)
        return (nearest - now).days

    def is_licence_expired(self) -> bool:
        """Check if the licence has expired."""
        if not self.licence_expiry:
            return False
        return datetime.utcnow() > self.licence_expiry

    def to_dict(self) -> dict:
        """Serialize product to dictionary."""
        def fmt_dt(dt):
            return dt.isoformat() if dt else None

        return {
            "product_id": self.product_id,
            "name": self.name,
            "vendor": self.vendor,
            "version": self.version,
            "category": self.category.value,
            "licence_type": self.licence_type.value,
            "licence_key": self.licence_key,
            "licence_quantity": self.licence_quantity,
            "purchase_date": fmt_dt(self.purchase_date),
            "licence_start": fmt_dt(self.licence_start),
            "licence_expiry": fmt_dt(self.licence_expiry),
            "mainstream_support_end": fmt_dt(self.mainstream_support_end),
            "extended_support_end": fmt_dt(self.extended_support_end),
            "end_of_life": fmt_dt(self.end_of_life),
            "annual_cost": self.annual_cost,
            "currency": self.currency,
            "environment": self.environment,
            "department": self.department,
            "owner": self.owner,
            "notes": self.notes,
            "tags": self.tags,
            "is_active": self.is_active,
            "support_status": self.support_status().value,
            "days_until_licence_expiry": self.days_until_licence_expiry(),
            "days_until_support_end": self.days_until_support_end(),
            "created_at": fmt_dt(self.created_at),
            "updated_at": fmt_dt(self.updated_at),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Product":
        """Deserialize product from dictionary."""
        def parse_dt(val):
            if not val:
                return None
            return datetime.fromisoformat(val)

        return cls(
            product_id=data.get("product_id", uuid.uuid4().hex[:12]),
            name=data["name"],
            vendor=data["vendor"],
            version=data.get("version", ""),
            category=ProductCategory(data["category"]),
            licence_type=LicenceType(data.get("licence_type", "subscription")),
            licence_key=data.get("licence_key", ""),
            licence_quantity=data.get("licence_quantity", 1),
            purchase_date=parse_dt(data.get("purchase_date")),
            licence_start=parse_dt(data.get("licence_start")),
            licence_expiry=parse_dt(data.get("licence_expiry")),
            mainstream_support_end=parse_dt(data.get("mainstream_support_end")),
            extended_support_end=parse_dt(data.get("extended_support_end")),
            end_of_life=parse_dt(data.get("end_of_life")),
            annual_cost=data.get("annual_cost", 0.0),
            currency=data.get("currency", "USD"),
            environment=data.get("environment", "production"),
            department=data.get("department", ""),
            owner=data.get("owner", ""),
            notes=data.get("notes", ""),
            tags=data.get("tags", []),
            is_active=data.get("is_active", True),
            created_at=parse_dt(data.get("created_at")) or datetime.utcnow(),
            updated_at=parse_dt(data.get("updated_at")) or datetime.utcnow(),
        )
