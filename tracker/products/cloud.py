"""
Cloud platform and SaaS product lifecycle reference.

Tracks subscription dates, service changes, and version deprecation
for major cloud providers.
"""

CLOUD_SERVICES = {
    "AWS": {
        "EC2": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "RDS": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "EKS": {"type": "pay_as_you_go", "category": "container"},
        "Lambda": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "S3": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "CloudFront": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "Route 53": {"type": "pay_as_you_go", "category": "cloud_platform"},
    },
    "Azure": {
        "Virtual Machines": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "App Service": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "AKS": {"type": "pay_as_you_go", "category": "container"},
        "SQL Database": {"type": "pay_as_you_go", "category": "database"},
        "Cosmos DB": {"type": "pay_as_you_go", "category": "database"},
        "Blob Storage": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "Front Door": {"type": "pay_as_you_go", "category": "load_balancer"},
        "Application Gateway": {"type": "pay_as_you_go", "category": "load_balancer"},
    },
    "GCP": {
        "Compute Engine": {"type": "pay_as_you_go", "category": "cloud_platform"},
        "GKE": {"type": "pay_as_you_go", "category": "container"},
        "Cloud SQL": {"type": "pay_as_you_go", "category": "database"},
        "Cloud Load Balancing": {"type": "pay_as_you_go", "category": "load_balancer"},
        "Cloud Run": {"type": "pay_as_you_go", "category": "cloud_platform"},
    },
}

# Known Kubernetes version deprecation schedule
KUBERNETES_VERSIONS = {
    "1.27": {"release": "2023-04-11", "end_of_life": "2024-06-28"},
    "1.28": {"release": "2023-08-15", "end_of_life": "2024-10-28"},
    "1.29": {"release": "2023-12-13", "end_of_life": "2025-02-28"},
    "1.30": {"release": "2024-04-17", "end_of_life": "2025-06-28"},
    "1.31": {"release": "2024-08-13", "end_of_life": "2025-10-28"},
    "1.32": {"release": "2024-12-11", "end_of_life": "2026-02-28"},
}

# Common SaaS products to track subscriptions
SAAS_PRODUCTS = {
    "Atlassian": {
        "products": ["Jira", "Confluence", "Bitbucket"],
        "licence_types": ["subscription"],
        "category": "saas",
    },
    "Salesforce": {
        "products": ["Sales Cloud", "Service Cloud", "Platform"],
        "licence_types": ["subscription"],
        "category": "saas",
    },
    "ServiceNow": {
        "products": ["ITSM", "ITOM", "SecOps"],
        "licence_types": ["subscription"],
        "category": "saas",
    },
    "Datadog": {
        "products": ["Infrastructure", "APM", "Logs"],
        "licence_types": ["subscription"],
        "category": "saas",
    },
    "PagerDuty": {
        "products": ["Event Intelligence", "Incident Response"],
        "licence_types": ["subscription"],
        "category": "saas",
    },
}


def get_cloud_service_info(provider: str, service: str) -> dict:
    """Look up cloud service metadata."""
    provider_data = CLOUD_SERVICES.get(provider, {})
    return provider_data.get(service, {})


def get_k8s_eol(version: str) -> dict:
    """Get Kubernetes version end-of-life info."""
    return KUBERNETES_VERSIONS.get(version, {})


def list_cloud_services() -> list[dict]:
    """List all tracked cloud services."""
    results = []
    for provider, services in CLOUD_SERVICES.items():
        for service, info in services.items():
            results.append({"provider": provider, "service": service, **info})
    return results
