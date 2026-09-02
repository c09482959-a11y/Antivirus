"""Exact Stage2636 scan-cache identity fixtures."""
from __future__ import annotations

from Virus_Scan.contracts.scan_cache_fingerprint import ScanCacheExecutionIdentity


def disabled_scan_cache_identity(*, semantic_seed: str = "a", session_seed: str = "d") -> ScanCacheExecutionIdentity:
    if semantic_seed not in "abcdef0123456789" or session_seed not in "abcdef0123456789":
        raise ValueError("scan_cache_fixture_seed_invalid")
    return ScanCacheExecutionIdentity(
        session_generation_id=session_seed * 64,
        session_state="available",
        yara_state="disabled",
        yara_package_kind="disabled",
        yara_source_digest="",
        yara_compiled_cache_digest="",
        yara_rule_catalog_digest="",
        attack_state="disabled",
        attack_alignment_digest=semantic_seed * 64,
        attack_implementation_manifest_digest="b" * 64,
        attack_policy_digest="c" * 64,
        attack_policy_version="attack_mapping_policy_fixture_v1",
        attack_repository_digest="",
        attack_dataset_version="",
    )


def verified_scan_cache_identity(
    *,
    package_kind: str = "core",
    source_seed: str = "1",
    compiled_seed: str = "2",
    catalog_seed: str = "3",
    alignment_seed: str = "4",
    implementation_seed: str = "5",
    policy_seed: str = "6",
    repository_seed: str = "7",
    dataset_seed: str = "8",
    session_seed: str = "e",
) -> ScanCacheExecutionIdentity:
    return ScanCacheExecutionIdentity(
        session_generation_id=session_seed * 64,
        session_state="available",
        yara_state="verified",
        yara_package_kind=package_kind,
        yara_source_digest=source_seed * 64,
        yara_compiled_cache_digest=compiled_seed * 64,
        yara_rule_catalog_digest=catalog_seed * 64,
        attack_state="available",
        attack_alignment_digest=alignment_seed * 64,
        attack_implementation_manifest_digest=implementation_seed * 64,
        attack_policy_digest=policy_seed * 64,
        attack_policy_version="attack_mapping_policy_fixture_v1",
        attack_repository_digest=repository_seed * 64,
        attack_dataset_version=dataset_seed * 40,
    )


def unavailable_scan_cache_identity(*, session_seed: str = "f") -> ScanCacheExecutionIdentity:
    return ScanCacheExecutionIdentity(
        session_generation_id=session_seed * 64,
        session_state="unavailable",
        yara_state="unavailable",
        yara_package_kind="unavailable",
        yara_source_digest="",
        yara_compiled_cache_digest="",
        yara_rule_catalog_digest="",
        attack_state="unavailable",
        attack_alignment_digest="a" * 64,
        attack_implementation_manifest_digest="b" * 64,
        attack_policy_digest="c" * 64,
        attack_policy_version="attack_mapping_policy_fixture_v1",
        attack_repository_digest="",
        attack_dataset_version="",
    )


__all__ = (
    "disabled_scan_cache_identity",
    "unavailable_scan_cache_identity",
    "verified_scan_cache_identity",
)
