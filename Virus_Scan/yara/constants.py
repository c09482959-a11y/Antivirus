"""YARA scoring constants owned by the YARA subsystem.

These are immutable calibration/schema values and must not be imported from
implicit mutable runtime state.
"""

from Virus_Scan.contracts.yara_hits import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    YARA_CALIBRATION_VERSION,
)

YARA_CACHE_DIRNAME = "yara.cache"
YARA_CACHE_MANIFEST = "manifest.json"
YARA_COMPILED_CACHE = "compiled_rules.yarc"
YARA_GROUP_CACHE_DIRNAME = "yara.groups"
YARALIGHT_CACHE_DIRNAME = "yaralight.cache"
YARALIGHT_CACHE_MANIFEST = "manifest.json"
YARALIGHT_COMPILED_CACHE = "compiled_rules.yarc"

__all__ = ("ANALYTICAL_EVIDENCE_SCHEMA_VERSION", "YARALIGHT_CACHE_DIRNAME", "YARALIGHT_CACHE_MANIFEST", "YARALIGHT_COMPILED_CACHE", "YARA_CACHE_DIRNAME", "YARA_CACHE_MANIFEST", "YARA_CALIBRATION_VERSION", "YARA_COMPILED_CACHE", "YARA_GROUP_CACHE_DIRNAME")
