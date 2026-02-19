"""Azure resource scanner — discover resources with custom domain bindings and SSL certificates."""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class AzureResourceBinding:
    """A custom domain/SSL binding found on an Azure resource."""

    # Resource identification
    resource_type: str  # app_service, application_gateway, front_door, cdn, api_management
    resource_name: str
    resource_group: str
    subscription_id: str
    subscription_name: str = ""
    resource_id: str = ""

    # Custom domain info
    hostname: str = ""
    hostname_type: str = ""

    # SSL certificate info
    ssl_enabled: bool = False
    ssl_thumbprint: str = ""
    ssl_subject: str = ""
    ssl_expiry: Optional[datetime] = None
    ssl_state: str = ""

    # Domain registry match
    tracked: bool = False
    tracked_domain_id: str = ""

    def resource_type_display(self) -> str:
        """Human-readable resource type."""
        return {
            "app_service": "App Service",
            "application_gateway": "Application Gateway",
            "front_door": "Front Door",
            "cdn": "CDN Profile",
            "api_management": "API Management",
        }.get(self.resource_type, self.resource_type)


class AzureResourceScanner:
    """Scan Azure subscriptions for resources with custom domain bindings."""

    def __init__(
        self,
        subscription_id: str = "",
        tenant_id: str = "",
        client_id: str = "",
        client_secret: str = "",
    ):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret

    def _get_credential(self):
        """Return Azure credential (same pattern as AzureDnsService)."""
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
        try:
            self._get_credential()
            return True
        except Exception:
            return False

    def _get_subscription_ids(self) -> list[dict]:
        """Return list of subscriptions to scan."""
        if self.subscription_id:
            return [{"subscription_id": self.subscription_id, "display_name": ""}]
        try:
            from azure.mgmt.subscription import SubscriptionClient
            credential = self._get_credential()
            client = SubscriptionClient(credential)
            return [
                {"subscription_id": s.subscription_id, "display_name": s.display_name}
                for s in client.subscriptions.list()
            ]
        except Exception as e:
            logger.error("Failed to list subscriptions: %s", e)
            return []

    def scan_all(self, resource_types: Optional[list[str]] = None) -> list[AzureResourceBinding]:
        """Scan all subscriptions for custom domain bindings.

        Args:
            resource_types: Types to scan. None = all supported.
        """
        all_types = [
            "app_service", "application_gateway", "front_door",
            "cdn", "api_management",
        ]
        types_to_scan = resource_types or all_types

        subscriptions = self._get_subscription_ids()
        if not subscriptions:
            logger.warning("No Azure subscriptions available for scanning")
            return []

        credential = self._get_credential()
        results: list[AzureResourceBinding] = []

        scanner_map = {
            "app_service": self._scan_app_services,
            "application_gateway": self._scan_app_gateways,
            "front_door": self._scan_front_doors,
            "cdn": self._scan_cdn_profiles,
            "api_management": self._scan_api_management,
        }

        for sub in subscriptions:
            sub_id = sub["subscription_id"]
            sub_name = sub.get("display_name", "")

            for rtype in types_to_scan:
                scanner = scanner_map.get(rtype)
                if scanner:
                    try:
                        bindings = scanner(credential, sub_id, sub_name)
                        results.extend(bindings)
                    except Exception as e:
                        logger.error("Error scanning %s in %s: %s", rtype, sub_id, e)

        return results

    # ── Per-resource-type scanners ────────────────────────────────

    def _scan_app_services(self, credential, sub_id, sub_name) -> list[AzureResourceBinding]:
        """Scan App Service web apps for custom hostname bindings."""
        from azure.mgmt.web import WebSiteManagementClient
        client = WebSiteManagementClient(credential, sub_id)
        results = []

        for app in client.web_apps.list():
            rg = self._extract_resource_group(app.id)
            try:
                bindings = client.web_apps.list_host_name_bindings(rg, app.name)
                for binding in bindings:
                    # Skip default .azurewebsites.net hostnames
                    if binding.host_name_type and str(binding.host_name_type) == "Managed":
                        continue
                    hostname = binding.name.split("/")[-1] if "/" in binding.name else binding.name
                    results.append(AzureResourceBinding(
                        resource_type="app_service",
                        resource_name=app.name,
                        resource_group=rg,
                        subscription_id=sub_id,
                        subscription_name=sub_name,
                        resource_id=app.id,
                        hostname=hostname,
                        hostname_type=str(binding.host_name_type or ""),
                        ssl_enabled=bool(binding.ssl_state and str(binding.ssl_state) != "Disabled"),
                        ssl_thumbprint=binding.thumbprint or "",
                        ssl_state=str(binding.ssl_state or ""),
                    ))
            except Exception as e:
                logger.warning("Failed to get bindings for app %s: %s", app.name, e)

        return results

    def _scan_app_gateways(self, credential, sub_id, sub_name) -> list[AzureResourceBinding]:
        """Scan Application Gateways for HTTPS listeners with custom hostnames."""
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, sub_id)
        results = []

        for gw in client.application_gateways.list_all():
            rg = self._extract_resource_group(gw.id)
            for listener in (gw.http_listeners or []):
                hostnames = list(listener.host_names or [])
                if listener.host_name and listener.host_name not in hostnames:
                    hostnames.append(listener.host_name)
                if not hostnames:
                    continue

                for hostname in hostnames:
                    results.append(AzureResourceBinding(
                        resource_type="application_gateway",
                        resource_name=gw.name,
                        resource_group=rg,
                        subscription_id=sub_id,
                        subscription_name=sub_name,
                        resource_id=gw.id,
                        hostname=hostname,
                        ssl_enabled=bool(listener.ssl_certificate),
                    ))

        return results

    def _scan_front_doors(self, credential, sub_id, sub_name) -> list[AzureResourceBinding]:
        """Scan Front Door profiles for custom domains."""
        from azure.mgmt.frontdoor import FrontDoorManagementClient
        client = FrontDoorManagementClient(credential, sub_id)
        results = []

        for fd in client.front_doors.list():
            rg = self._extract_resource_group(fd.id)
            for frontend in (fd.frontend_endpoints or []):
                hostname = frontend.host_name or ""
                # Skip default .azurefd.net endpoints
                if hostname.endswith(".azurefd.net"):
                    continue
                https_config = frontend.custom_https_configuration
                ssl_enabled = bool(
                    https_config
                    and str(getattr(https_config, "custom_https_provisioning_state", "")) == "Enabled"
                )
                results.append(AzureResourceBinding(
                    resource_type="front_door",
                    resource_name=fd.name,
                    resource_group=rg,
                    subscription_id=sub_id,
                    subscription_name=sub_name,
                    resource_id=fd.id,
                    hostname=hostname,
                    ssl_enabled=ssl_enabled,
                ))

        return results

    def _scan_cdn_profiles(self, credential, sub_id, sub_name) -> list[AzureResourceBinding]:
        """Scan CDN profiles/endpoints for custom domains."""
        from azure.mgmt.cdn import CdnManagementClient
        client = CdnManagementClient(credential, sub_id)
        results = []

        for profile in client.profiles.list():
            rg = self._extract_resource_group(profile.id)
            try:
                for endpoint in client.endpoints.list_by_profile(rg, profile.name):
                    for custom_domain in client.custom_domains.list_by_endpoint(
                        rg, profile.name, endpoint.name
                    ):
                        results.append(AzureResourceBinding(
                            resource_type="cdn",
                            resource_name=f"{profile.name}/{endpoint.name}",
                            resource_group=rg,
                            subscription_id=sub_id,
                            subscription_name=sub_name,
                            resource_id=custom_domain.id or "",
                            hostname=custom_domain.host_name or "",
                            ssl_enabled=bool(custom_domain.custom_https_parameters),
                        ))
            except Exception as e:
                logger.warning("Failed to scan CDN profile %s: %s", profile.name, e)

        return results

    def _scan_api_management(self, credential, sub_id, sub_name) -> list[AzureResourceBinding]:
        """Scan API Management for custom domain configurations."""
        from azure.mgmt.apimanagement import ApiManagementClient
        client = ApiManagementClient(credential, sub_id)
        results = []

        for service in client.api_management_service.list():
            rg = self._extract_resource_group(service.id)
            for hostname_config in (service.hostname_configurations or []):
                hostname = hostname_config.host_name or ""
                # Skip default .azure-api.net hostnames
                if hostname.endswith(".azure-api.net"):
                    continue
                cert = hostname_config.certificate
                results.append(AzureResourceBinding(
                    resource_type="api_management",
                    resource_name=service.name,
                    resource_group=rg,
                    subscription_id=sub_id,
                    subscription_name=sub_name,
                    resource_id=service.id,
                    hostname=hostname,
                    ssl_enabled=True,  # APIM custom domains always require certs
                    ssl_thumbprint=getattr(cert, "thumbprint", "") if cert else "",
                    ssl_expiry=getattr(cert, "expiry", None) if cert else None,
                ))

        return results

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _extract_resource_group(resource_id: str) -> str:
        """Extract resource group name from an Azure resource ID."""
        parts = resource_id.split("/")
        for i, part in enumerate(parts):
            if part.lower() == "resourcegroups" and i + 1 < len(parts):
                return parts[i + 1]
        return ""


def match_bindings_to_registry(
    bindings: list[AzureResourceBinding],
    registry,
) -> list[AzureResourceBinding]:
    """Cross-reference scan results against tracked domains."""
    all_domains = registry.list_all()

    # Direct hostname lookup
    hostname_map = {d.hostname.lower(): d for d in all_domains}

    # Wildcard matches: *.example.com covers sub.example.com
    wildcard_parents = {}
    for d in all_domains:
        if d.hostname.startswith("*."):
            parent = d.hostname[2:].lower()
            wildcard_parents[parent] = d

    for binding in bindings:
        h = binding.hostname.lower()
        # Direct match
        if h in hostname_map:
            binding.tracked = True
            binding.tracked_domain_id = hostname_map[h].domain_id
        else:
            # Wildcard match
            for parent, domain in wildcard_parents.items():
                if h.endswith("." + parent):
                    binding.tracked = True
                    binding.tracked_domain_id = domain.domain_id
                    break

    return bindings
