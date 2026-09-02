"""Canonical reporting subsystem initialization."""
from Virus_Scan.runtime.api import init_state_snapshot
from Virus_Scan.reporting.init_parts.reporting_defaults_init import init_reporting_defaults


def initialize_reporting() -> object:
    """Run reporting initialization in the canonical startup order."""
    init_reporting_defaults()
    return init_state_snapshot()


__all__ = ("initialize_reporting",)
