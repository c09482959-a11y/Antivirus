"""Scanner-owned immutable filetype policy snapshot exports.

The policy data lives in scanners/config/defaults/filetype_policy.json and is
validated into an immutable snapshot by the scanner config loader. This module
keeps the historic constant names as read-only views of that scanner-owned
snapshot; it does not own mutable policy tables.
"""
from __future__ import annotations

from Virus_Scan.scanners.config.loader import load_filetype_policy_snapshot

_FILETYPE_POLICY = load_filetype_policy_snapshot()

BEHAVIOR_MODEL_VERSION = _FILETYPE_POLICY.behavior_model_version
HIGH_RISK_BUCKETS = _FILETYPE_POLICY.high_risk_buckets
NON_EXECUTION_CAPABILITIES = _FILETYPE_POLICY.non_execution_capabilities
CONTAINER_EXECUTION_CAPABILITIES = _FILETYPE_POLICY.container_execution_capabilities
PASSIVE_ASSET_CATEGORIES = _FILETYPE_POLICY.passive_asset_categories
DANGEROUS_ACTUAL_CATEGORIES = _FILETYPE_POLICY.dangerous_actual_categories
ENGINE_EXTENSION_BUCKET_POLICIES = _FILETYPE_POLICY.engine_extension_bucket_policies
GLOBAL_COMMON_FILETYPE_BUCKETS = _FILETYPE_POLICY.global_common_filetype_buckets
ENGINE_SPECIFIC_FILETYPE_BUCKETS = _FILETYPE_POLICY.engine_specific_filetype_buckets
EXPECTED_MAGIC_TYPES_BY_EXTENSION = _FILETYPE_POLICY.expected_magic_types_by_extension
ROUTABLE_EXTENSIONS_BY_CLAIM = _FILETYPE_POLICY.routable_extensions_by_claim
ALL_ROUTABLE_EXTENSIONS = _FILETYPE_POLICY.all_routable_extensions
MAGIC_TYPE_CATEGORY = _FILETYPE_POLICY.magic_type_category

__all__ = (
    "ALL_ROUTABLE_EXTENSIONS",
    "BEHAVIOR_MODEL_VERSION",
    "CONTAINER_EXECUTION_CAPABILITIES",
    "DANGEROUS_ACTUAL_CATEGORIES",
    "ENGINE_EXTENSION_BUCKET_POLICIES",
    "ENGINE_SPECIFIC_FILETYPE_BUCKETS",
    "EXPECTED_MAGIC_TYPES_BY_EXTENSION",
    "GLOBAL_COMMON_FILETYPE_BUCKETS",
    "HIGH_RISK_BUCKETS",
    "MAGIC_TYPE_CATEGORY",
    "NON_EXECUTION_CAPABILITIES",
    "PASSIVE_ASSET_CATEGORIES",
    "ROUTABLE_EXTENSIONS_BY_CLAIM",
)
