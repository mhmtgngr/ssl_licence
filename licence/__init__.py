"""
Licence Management Module.

Provides functionality for generating, validating, and tracking
software licences.
"""

from licence.generator import LicenceGenerator
from licence.validator import LicenceValidator
from licence.manager import LicenceManager

__all__ = ["LicenceGenerator", "LicenceValidator", "LicenceManager"]
