"""Canonical scanner subsystem initialization."""
from Virus_Scan.runtime.api import init_state_snapshot
from Virus_Scan.scanners.init_parts.scanner_filetype_defaults_init import init_scanner_defaults


def initialize_scanners() -> object:
    """Run scanner initialization in the canonical startup order."""
    init_scanner_defaults()
    return init_state_snapshot()


__all__ = ("initialize_scanners",)
