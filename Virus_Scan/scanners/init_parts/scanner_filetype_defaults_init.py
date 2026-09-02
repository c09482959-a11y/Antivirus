"""scanners package initializer.

Stage 12: subsystem runtime initialization moved here from Virus_Scan.init_runtime.
Functionality remains in this package; main/top_level only orchestrate calls.
"""
from __future__ import annotations

from Virus_Scan.runtime.api import publish_init_values
from Virus_Scan.scanners.filetype_policy import ALL_ROUTABLE_EXTENSIONS as SCANNER_ALL_ROUTABLE_EXTENSIONS
from Virus_Scan.scanners.init_parts.scanner_default_values import scanner_default_init_values


def init_scanner_defaults() -> object:
    """Publish scanner-owned default values through the runtime init registry."""
    _ = SCANNER_ALL_ROUTABLE_EXTENSIONS
    publish_init_values(scanner_default_init_values())
    return publish_init_values(())


__all__ = ("init_scanner_defaults",)
