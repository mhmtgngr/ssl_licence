"""
Network equipment and load balancer product lifecycle reference.

Tracks end-of-support for common network devices:
load balancers, firewalls, switches, routers.
"""

NETWORK_PRODUCTS = {
    "F5": {
        "BIG-IP": {
            "14.x": {
                "end_of_support": "2025-12-31",
                "category": "load_balancer",
            },
            "15.x": {
                "end_of_support": "2027-07-31",
                "category": "load_balancer",
            },
            "16.x": {
                "end_of_support": "2028-07-31",
                "category": "load_balancer",
            },
            "17.x": {
                "end_of_support": "2029-07-31",
                "category": "load_balancer",
            },
        },
    },
    "Citrix (NetScaler)": {
        "ADC": {
            "12.1": {
                "end_of_support": "2025-05-30",
                "category": "load_balancer",
            },
            "13.0": {
                "end_of_support": "2025-07-15",
                "category": "load_balancer",
            },
            "13.1": {
                "end_of_support": "2026-07-15",
                "category": "load_balancer",
            },
            "14.1": {
                "end_of_support": "2028-07-15",
                "category": "load_balancer",
            },
        },
    },
    "HAProxy": {
        "Community": {
            "2.6 LTS": {
                "end_of_support": "2027-04-01",
                "category": "load_balancer",
            },
            "2.8 LTS": {
                "end_of_support": "2028-04-01",
                "category": "load_balancer",
            },
            "3.0 LTS": {
                "end_of_support": "2029-04-01",
                "category": "load_balancer",
            },
        },
    },
    "NGINX": {
        "Plus": {
            "R30": {"end_of_support": "2025-06-30", "category": "load_balancer"},
            "R31": {"end_of_support": "2025-12-31", "category": "load_balancer"},
            "R32": {"end_of_support": "2026-06-30", "category": "load_balancer"},
            "R33": {"end_of_support": "2026-12-31", "category": "load_balancer"},
        },
    },
    "Cisco": {
        "ASA": {
            "9.16": {"end_of_support": "2025-11-01", "category": "security"},
            "9.18": {"end_of_support": "2027-11-01", "category": "security"},
            "9.19": {"end_of_support": "2028-05-01", "category": "security"},
            "9.20": {"end_of_support": "2028-11-01", "category": "security"},
        },
        "Catalyst Switches": {
            "IOS-XE 17.6": {"end_of_support": "2026-04-01", "category": "network_equipment"},
            "IOS-XE 17.9": {"end_of_support": "2027-04-01", "category": "network_equipment"},
            "IOS-XE 17.12": {"end_of_support": "2028-04-01", "category": "network_equipment"},
        },
    },
    "Palo Alto": {
        "PAN-OS": {
            "10.1": {"end_of_support": "2025-03-01", "category": "security"},
            "10.2": {"end_of_support": "2026-04-01", "category": "security"},
            "11.0": {"end_of_support": "2026-11-01", "category": "security"},
            "11.1": {"end_of_support": "2027-11-01", "category": "security"},
        },
    },
    "Fortinet": {
        "FortiOS": {
            "7.0": {"end_of_support": "2026-02-15", "category": "security"},
            "7.2": {"end_of_support": "2027-03-31", "category": "security"},
            "7.4": {"end_of_support": "2028-03-31", "category": "security"},
        },
    },
}


def get_network_product_dates(vendor: str, product: str, version: str) -> dict:
    """Look up lifecycle dates for a network product."""
    return NETWORK_PRODUCTS.get(vendor, {}).get(product, {}).get(version, {})


def list_network_products() -> list[dict]:
    """List all known network products."""
    results = []
    for vendor, products in NETWORK_PRODUCTS.items():
        for product, versions in products.items():
            for version, info in versions.items():
                results.append({
                    "vendor": vendor,
                    "product": product,
                    "version": version,
                    **info,
                })
    return results
