"""Azure DNS zone enumeration service."""

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AzureDnsRecord:
    """A DNS record retrieved from Azure DNS."""

    hostname: str
    record_type: str  # A, AAAA, CNAME
    value: str
    ttl: int = 3600


class AzureDnsService:
    """Enumerate DNS zones and records from Azure DNS."""

    def __init__(self, subscription_id: str = "", resource_group: str = ""):
        self.subscription_id = subscription_id
        self.resource_group = resource_group

    def is_configured(self) -> bool:
        """Check if Azure credentials and subscription are available."""
        if not self.subscription_id:
            return False
        try:
            from azure.identity import DefaultAzureCredential
            DefaultAzureCredential()
            return True
        except Exception:
            return False

    def list_zones(self) -> list[dict]:
        """List all DNS zones in the subscription.

        Returns list of dicts: {name, resource_group, number_of_record_sets}
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.dns import DnsManagementClient
        except ImportError:
            logger.warning("azure-identity / azure-mgmt-dns not installed")
            return []

        credential = DefaultAzureCredential()
        client = DnsManagementClient(credential, self.subscription_id)

        zones = []
        try:
            if self.resource_group:
                for zone in client.zones.list_by_resource_group(self.resource_group):
                    zones.append({
                        "name": zone.name,
                        "resource_group": self.resource_group,
                        "number_of_record_sets": zone.number_of_record_sets or 0,
                    })
            else:
                for zone in client.zones.list():
                    rg = self._extract_resource_group(zone.id)
                    zones.append({
                        "name": zone.name,
                        "resource_group": rg,
                        "number_of_record_sets": zone.number_of_record_sets or 0,
                    })
        except Exception as e:
            logger.error("Failed to list Azure DNS zones: %s", e)

        return zones

    def list_records(self, zone_name: str, resource_group: str) -> list[AzureDnsRecord]:
        """List A, AAAA, and CNAME records in a zone.

        Returns list of AzureDnsRecord with fully qualified hostnames.
        """
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.dns import DnsManagementClient
        except ImportError:
            return []

        credential = DefaultAzureCredential()
        client = DnsManagementClient(credential, self.subscription_id)

        records = []
        try:
            for rs in client.record_sets.list_by_dns_zone(resource_group, zone_name):
                fqdn = rs.fqdn.rstrip(".") if rs.fqdn else ""
                if not fqdn:
                    fqdn = zone_name if rs.name == "@" else f"{rs.name}.{zone_name}"

                if rs.type.endswith("/A") and rs.a_records:
                    for a in rs.a_records:
                        records.append(AzureDnsRecord(
                            hostname=fqdn,
                            record_type="A",
                            value=a.ipv4_address,
                            ttl=rs.ttl or 3600,
                        ))
                elif rs.type.endswith("/AAAA") and rs.aaaa_records:
                    for aaaa in rs.aaaa_records:
                        records.append(AzureDnsRecord(
                            hostname=fqdn,
                            record_type="AAAA",
                            value=aaaa.ipv6_address,
                            ttl=rs.ttl or 3600,
                        ))
                elif rs.type.endswith("/CNAME") and rs.cname_record:
                    records.append(AzureDnsRecord(
                        hostname=fqdn,
                        record_type="CNAME",
                        value=rs.cname_record.cname.rstrip("."),
                        ttl=rs.ttl or 3600,
                    ))
        except Exception as e:
            logger.error("Failed to list records for zone %s: %s", zone_name, e)

        return records

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group name from an Azure resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
