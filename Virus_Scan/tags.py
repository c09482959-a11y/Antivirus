"""Repository-level tags entrypoint using the public detection API boundary.

The canonical implementation remains owned by ``Virus_Scan.detection``.  This
module preserves the repository-level import surface while avoiding direct
imports from detection implementation internals.
"""
from Virus_Scan.detection.api import tags_contracts as _tags_contracts

__all__ = _tags_contracts.__all__

globals().update({name: getattr(_tags_contracts, name) for name in __all__})
