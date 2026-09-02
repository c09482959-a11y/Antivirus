"""Canonical YARA subsystem initialization boundary."""
from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.yara.init_parts.yara_defaults_init import init_yara_defaults

if TYPE_CHECKING:
    from types import MappingProxyType

def initialize_yara() -> MappingProxyType:
    """Return the immutable YARA startup configuration snapshot."""
    return init_yara_defaults()


__all__ = ("initialize_yara",)
