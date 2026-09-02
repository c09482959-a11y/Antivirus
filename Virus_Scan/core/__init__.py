"""Canonical core subsystem initialization."""

from Virus_Scan.core.init_parts.cache_init import init_caches
from Virus_Scan.core.init_parts.paths_logging_init import init_paths_logging
from Virus_Scan.runtime.init_state import init_state_snapshot


def initialize_core() -> object:
    """Run core initialization in deterministic dependency order."""
    init_paths_logging()
    init_caches()
    return init_state_snapshot()


__all__ = (
    "init_caches",
    "init_paths_logging",
    "initialize_core",
)
