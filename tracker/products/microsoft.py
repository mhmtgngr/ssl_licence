"""
Microsoft product lifecycle catalogue.

Contains known end-of-support and end-of-life dates for Microsoft products.
Data sourced from Microsoft Lifecycle Policy.
"""

# Format: {product_name: {version: {dates}}}
# Dates as ISO strings for easy parsing.

MICROSOFT_LIFECYCLE = {
    "Windows Server": {
        "2012 R2": {
            "mainstream_support_end": "2018-10-09",
            "extended_support_end": "2023-10-10",
            "notes": "ESU available until Oct 2026",
        },
        "2016": {
            "mainstream_support_end": "2022-01-11",
            "extended_support_end": "2027-01-12",
        },
        "2019": {
            "mainstream_support_end": "2024-01-09",
            "extended_support_end": "2029-01-09",
        },
        "2022": {
            "mainstream_support_end": "2026-10-13",
            "extended_support_end": "2031-10-14",
        },
        "2025": {
            "mainstream_support_end": "2029-10-09",
            "extended_support_end": "2034-10-10",
        },
    },
    "SQL Server": {
        "2014": {
            "mainstream_support_end": "2019-07-09",
            "extended_support_end": "2024-07-09",
        },
        "2016": {
            "mainstream_support_end": "2021-07-13",
            "extended_support_end": "2026-07-14",
        },
        "2017": {
            "mainstream_support_end": "2022-10-11",
            "extended_support_end": "2027-10-12",
        },
        "2019": {
            "mainstream_support_end": "2025-01-07",
            "extended_support_end": "2030-01-08",
        },
        "2022": {
            "mainstream_support_end": "2028-01-11",
            "extended_support_end": "2033-01-11",
        },
    },
    "Exchange Server": {
        "2016": {
            "mainstream_support_end": "2020-10-13",
            "extended_support_end": "2025-10-14",
        },
        "2019": {
            "mainstream_support_end": "2024-01-09",
            "extended_support_end": "2025-10-14",
        },
    },
    "Microsoft 365 Apps": {
        "Current": {
            "notes": "Subscription — continuously updated, no fixed end date.",
        },
    },
    "Windows": {
        "10 (22H2)": {
            "mainstream_support_end": "2025-10-14",
            "notes": "Last version of Windows 10",
        },
        "11 (23H2)": {
            "mainstream_support_end": "2025-11-11",
        },
        "11 (24H2)": {
            "mainstream_support_end": "2026-11-10",
        },
    },
    "SharePoint Server": {
        "2016": {
            "mainstream_support_end": "2021-07-13",
            "extended_support_end": "2026-07-14",
        },
        "2019": {
            "mainstream_support_end": "2024-01-09",
            "extended_support_end": "2026-07-14",
        },
        "Subscription Edition": {
            "notes": "Subscription — follows Modern Lifecycle Policy.",
        },
    },
    ".NET": {
        "6.0": {
            "mainstream_support_end": "2024-11-12",
            "notes": "LTS release",
        },
        "8.0": {
            "mainstream_support_end": "2026-11-10",
            "notes": "LTS release",
        },
        "9.0": {
            "mainstream_support_end": "2026-05-12",
            "notes": "STS release",
        },
    },
}


def get_microsoft_product_dates(product_name: str, version: str) -> dict:
    """Look up lifecycle dates for a Microsoft product.

    Args:
        product_name: e.g. "Windows Server", "SQL Server"
        version: e.g. "2019", "2022"

    Returns:
        Dict with date strings, or empty dict if not found.
    """
    product = MICROSOFT_LIFECYCLE.get(product_name, {})
    return product.get(version, {})


def list_microsoft_products() -> list[dict]:
    """List all known Microsoft products and versions."""
    results = []
    for product, versions in MICROSOFT_LIFECYCLE.items():
        for version, dates in versions.items():
            results.append({
                "product": product,
                "version": version,
                **dates,
            })
    return results
