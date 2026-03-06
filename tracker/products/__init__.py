"""Product lifecycle catalogs — pluggable reference data for vendor lifecycles.

All catalogs implement the ``ProductCatalog`` Protocol for uniform access.
"""

from tracker.products.catalog import ProductCatalog, CatalogRegistry

__all__ = ["ProductCatalog", "CatalogRegistry"]
