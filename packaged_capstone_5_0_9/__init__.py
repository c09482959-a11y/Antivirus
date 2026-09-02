"""Repository-packaged Capstone 5.0.9 dependency identity.

Runtime loading is owned exclusively by
``Virus_Scan.scanners.static_program_analysis.native_capstone_runtime``.
"""

CAPSTONE_DISTRIBUTION_VERSION = "5.0.9"
CAPSTONE_BINDING_VERSION = "5.0.7"

__all__ = ("CAPSTONE_BINDING_VERSION", "CAPSTONE_DISTRIBUTION_VERSION")
