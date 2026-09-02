"""Public detection initialization contract.

The runtime bootstrap enters detection through this bounded API module instead of
importing the detection package implementation surface directly.  The actual
registry initialization remains owned by detection registries; this module only
exposes the narrow startup contract required by runtime initialization.
"""
from Virus_Scan.detection.registries.detection_constants import init_detection_constants


def initialize_detection() -> object:
    """Publish the canonical immutable detection registry snapshot."""
    return init_detection_constants()


__all__ = ("initialize_detection",)
