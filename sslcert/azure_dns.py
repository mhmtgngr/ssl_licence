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

    def __init__(
        self,
        subscription_id: str = "",
        resource_group: str = "",
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
    ):
        self.subscription_id = subscription_id
        self.resource_group = resource_group
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_credential(self):
        """Return an Azure credential using service principal or default chain."""
        if self.tenant_id and self.client_id and self.client_secret:
            from azure.identity import ClientSecretCredential
            return ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        from azure.identity import DefaultAzureCredential
        return DefaultAzureCredential()

    def is_configured(self) -> bool:
        """Check if Azure credentials are available.

        A subscription_id is no longer required — subscriptions can be
        auto-discovered via list_subscriptions().
        """
        try:
            self._get_credential()
            return True
        except Exception:
            return False

    def list_subscriptions(self) -> list[dict]:
        """Auto-discover Azure subscriptions accessible by the service principal.

        Returns list of dicts: {subscription_id, display_name, state}
        """
        try:
            from azure.mgmt.subscription import SubscriptionClient
        except ImportError:
            logger.warning("azure-mgmt-subscription not installed")
            return []

        try:
            credential = self._get_credential()
            client = SubscriptionClient(credential)
            subs = []
            for sub in client.subscriptions.list():
                subs.append({
                    "subscription_id": sub.subscription_id,
                    "display_name": sub.display_name,
                    "state": str(sub.state),
                })
            return subs
        except Exception as e:
            logger.error("Failed to list Azure subscriptions: %s", e)
            return []

    def list_zones(self) -> list[dict]:
        """List all DNS zones across one or all subscriptions.

        If subscription_id is set, queries that single subscription.
        Otherwise, auto-discovers all subscriptions.

        Returns list of dicts: {name, resource_group, subscription_id,
        number_of_record_sets}
        """
        try:
            from azure.mgmt.dns import DnsManagementClient
        except ImportError:
            logger.warning("azure-mgmt-dns not installed")
            return []

        subscription_ids = []
        if self.subscription_id:
            subscription_ids = [self.subscription_id]
        else:
            subs = self.list_subscriptions()
            subscription_ids = [s["subscription_id"] for s in subs]

        if not subscription_ids:
            logger.warning("No Azure subscriptions available")
            return []

        credential = self._get_credential()
        zones = []
        for sub_id in subscription_ids:
            try:
                client = DnsManagementClient(credential, sub_id)
                if self.resource_group:
                    for zone in client.zones.list_by_resource_group(self.resource_group):
                        zones.append({
                            "name": zone.name,
                            "resource_group": self.resource_group,
                            "subscription_id": sub_id,
                            "number_of_record_sets": zone.number_of_record_sets or 0,
                        })
                else:
                    for zone in client.zones.list():
                        rg = self._extract_resource_group(zone.id)
                        zones.append({
                            "name": zone.name,
                            "resource_group": rg,
                            "subscription_id": sub_id,
                            "number_of_record_sets": zone.number_of_record_sets or 0,
                        })
            except Exception as e:
                logger.error("Failed to list zones in subscription %s: %s", sub_id, e)

        return zones

    def list_records(
        self, zone_name: str, resource_group: str, subscription_id: str = "",
    ) -> list[AzureDnsRecord]:
        """List A, AAAA, and CNAME records in a zone.

        Returns list of AzureDnsRecord with fully qualified hostnames.
        """
        try:
            from azure.mgmt.dns import DnsManagementClient
        except ImportError:
            return []

        sub_id = subscription_id or self.subscription_id
        if not sub_id:
            logger.error("No subscription_id for list_records")
            return []

        credential = self._get_credential()
        client = DnsManagementClient(credential, sub_id)

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

    # ── TXT record management for ACME DNS-01 challenges ───────────

    def create_txt_record(
        self, zone_name: str, record_name: str, value: str,
        resource_group: str = "", ttl: int = 60, subscription_id: str = "",
    ) -> bool:
        """Create or update a TXT record in an Azure DNS zone.

        Args:
            zone_name: The DNS zone (e.g. "example.com").
            record_name: Relative record name (e.g. "_acme-challenge" or
                         "_acme-challenge.sub").
            value: The TXT record value (ACME validation token).
            resource_group: Azure resource group (falls back to self.resource_group).
            ttl: TTL in seconds (default 60 for fast propagation).

        Returns:
            True on success, False on failure.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
            from azure.mgmt.dns.models import RecordSet, TxtRecord
        except ImportError:
            logger.error("azure-identity / azure-mgmt-dns not installed")
            return False

        rg = resource_group or self.resource_group
        if not rg:
            logger.error("No resource group specified for TXT record creation")
            return False

        try:
            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            sub_id = subscription_id or self.subscription_id
            client = DnsManagementClient(credential, sub_id)
            client.record_sets.create_or_update(
                rg, zone_name, record_name, "TXT",
                RecordSet(ttl=ttl, txt_records=[TxtRecord(value=[value])]),
            )
            logger.info("Created TXT record %s.%s = %s", record_name, zone_name, value)
            return True
        except Exception as e:
            logger.error("Failed to create TXT record %s.%s: %s", record_name, zone_name, e)
            return False

    def delete_txt_record(
        self, zone_name: str, record_name: str, resource_group: str = "",
        subscription_id: str = "",
    ) -> bool:
        """Delete a TXT record from an Azure DNS zone.

        Args:
            zone_name: The DNS zone (e.g. "example.com").
            record_name: Relative record name (e.g. "_acme-challenge").
            resource_group: Azure resource group (falls back to self.resource_group).

        Returns:
            True on success, False on failure.
        """
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.dns import DnsManagementClient
        except ImportError:
            return False

        rg = resource_group or self.resource_group
        if not rg:
            return False

        try:
            credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
            sub_id = subscription_id or self.subscription_id
            client = DnsManagementClient(credential, sub_id)
            client.record_sets.delete(rg, zone_name, record_name, "TXT")
            logger.info("Deleted TXT record %s.%s", record_name, zone_name)
            return True
        except Exception as e:
            logger.error("Failed to delete TXT record %s.%s: %s", record_name, zone_name, e)
            return False

    def find_zone_for_domain(self, domain: str) -> tuple[str, str, str]:
        """Find the Azure DNS zone that manages a given domain.

        Returns (zone_name, resource_group, subscription_id) or
        ("", "", "") if not found.
        """
        zones = self.list_zones()
        # Sort by longest name first so sub.example.com matches before example.com
        zones.sort(key=lambda z: len(z["name"]), reverse=True)
        domain_lower = domain.lower().rstrip(".")
        for zone in zones:
            zn = zone["name"].lower().rstrip(".")
            if domain_lower == zn or domain_lower.endswith("." + zn):
                return (
                    zone["name"],
                    zone["resource_group"],
                    zone.get("subscription_id", self.subscription_id),
                )
        return "", "", ""

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group name from an Azure resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""
