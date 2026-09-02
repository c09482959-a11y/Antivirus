"""Immutable profile raw-observation feature registry."""
from __future__ import annotations

from typing import Final

PROFILE_RAW_FEATURE_SCHEMA_VERSION: Final[str] = "profile_raw_features_v2"
PROFILE_RAW_FEATURE_NAMES: Final[tuple[str, ...]] = (
    "tag_count",
    "tag_entropy",
    "unique_tag_count",
    "scoreable_count",
    "support_only_count",
    "chain_count",
    "os_exec_count",
    "network_count",
    "credential_count",
    "persistence_count",
    "injection_count",
    "evasion_count",
    "entropy_count",
    "renpy_script_count",
    "unity_managed_count",
    "rpgm_node_count",
)

__all__ = (
    "PROFILE_RAW_FEATURE_NAMES",
    "PROFILE_RAW_FEATURE_SCHEMA_VERSION",
)
