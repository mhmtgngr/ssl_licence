"""ProductCatalog Protocol and CatalogRegistry for pluggable lifecycle data.

Provides a uniform interface for querying product lifecycle information
across different vendors (Microsoft, cloud, network, etc.).
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class ProductCatalog(Protocol):
    """Protocol for product lifecycle catalogs.

    Each catalog provides:
    - ``lookup()`` — find lifecycle info for a specific product/version
    - ``list_all()`` — return all known products
    - ``name`` — human-readable catalog name
    """

    @property
    def name(self) -> str:
        """Human-readable catalog name."""
        ...

    def lookup(self, **kwargs) -> dict:
        """Look up lifecycle dates for a product.

        Keyword arguments vary by catalog type (e.g. product, version,
        vendor, service). Returns an empty dict if not found.
        """
        ...

    def list_all(self) -> list[dict]:
        """List all known products in this catalog."""
        ...


class MicrosoftCatalog:
    """Microsoft product lifecycle catalog."""

    @property
    def name(self) -> str:
        return "Microsoft"

    def lookup(self, **kwargs) -> dict:
        from tracker.products.microsoft import get_microsoft_product_dates
        product = kwargs.get("product", "")
        version = kwargs.get("version", "")
        return get_microsoft_product_dates(product, version)

    def list_all(self) -> list[dict]:
        from tracker.products.microsoft import list_microsoft_products
        return list_microsoft_products()


class CloudCatalog:
    """Cloud platform and SaaS lifecycle catalog."""

    @property
    def name(self) -> str:
        return "Cloud"

    def lookup(self, **kwargs) -> dict:
        from tracker.products.cloud import get_cloud_service_info, get_k8s_eol
        if kwargs.get("k8s_version"):
            return get_k8s_eol(kwargs["k8s_version"])
        provider = kwargs.get("provider", "")
        service = kwargs.get("service", "")
        return get_cloud_service_info(provider, service)

    def list_all(self) -> list[dict]:
        from tracker.products.cloud import list_cloud_services
        return list_cloud_services()


class NetworkCatalog:
    """Network equipment lifecycle catalog."""

    @property
    def name(self) -> str:
        return "Network"

    def lookup(self, **kwargs) -> dict:
        from tracker.products.network import get_network_product_dates
        vendor = kwargs.get("vendor", "")
        product = kwargs.get("product", "")
        version = kwargs.get("version", "")
        return get_network_product_dates(vendor, product, version)

    def list_all(self) -> list[dict]:
        from tracker.products.network import list_network_products
        return list_network_products()


class CatalogRegistry:
    """Central registry of all product catalogs.

    Provides a single point to query across all catalogs or
    register custom catalogs at runtime.

    Usage::

        registry = CatalogRegistry()
        # Built-in catalogs are registered automatically
        results = registry.search_all(product="Windows Server", version="2022")

        # Register a custom catalog
        registry.register(MyCustomCatalog())
    """

    def __init__(self):
        self._catalogs: dict[str, ProductCatalog] = {}
        # Register built-in catalogs
        for catalog in (MicrosoftCatalog(), CloudCatalog(), NetworkCatalog()):
            self.register(catalog)

    def register(self, catalog: ProductCatalog) -> None:
        """Register a catalog. Replaces any existing catalog with same name."""
        self._catalogs[catalog.name] = catalog

    def unregister(self, name: str) -> bool:
        """Remove a catalog. Returns True if it existed."""
        return self._catalogs.pop(name, None) is not None

    def get(self, name: str) -> Optional[ProductCatalog]:
        """Get a catalog by name."""
        return self._catalogs.get(name)

    @property
    def catalog_names(self) -> list[str]:
        """List all registered catalog names."""
        return list(self._catalogs.keys())

    def search_all(self, **kwargs) -> list[dict]:
        """Search across all catalogs and return combined results."""
        results = []
        for catalog in self._catalogs.values():
            result = catalog.lookup(**kwargs)
            if result:
                results.append({"catalog": catalog.name, **result})
        return results

    def list_all_products(self) -> list[dict]:
        """List all products from all catalogs."""
        results = []
        for catalog in self._catalogs.values():
            for item in catalog.list_all():
                results.append({"catalog": catalog.name, **item})
        return results
