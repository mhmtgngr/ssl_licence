"""
Product Licence Tracker Module.

Comprehensive tracking system for software licences, hardware support
contracts, cloud subscriptions, and end-of-support dates across all
product categories (Microsoft, cloud platforms, network equipment, etc.).

Features:
- Multi-category product tracking
- Configurable alert thresholds (6 months, 3 months, 1 month, 1 week)
- End-of-support / end-of-life monitoring
- AI-powered analysis and recommendations
- Notifications via email, webhook, Slack
- Comprehensive search and reporting
"""

from tracker.product import Product, ProductCategory, SupportStatus
from tracker.registry import ProductRegistry
from tracker.alert_engine import AlertEngine, AlertLevel
from tracker.search import SearchEngine

__all__ = [
    "Product",
    "ProductCategory",
    "SupportStatus",
    "ProductRegistry",
    "AlertEngine",
    "AlertLevel",
    "SearchEngine",
]
