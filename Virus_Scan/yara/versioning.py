"""Immutable version identifiers for the canonical YARA trust pipeline."""

YARA_CONFIG_VERSION = "yara_config_v2"
YARA_RELEASE_CONTRACT_VERSION = "yara_release_contract_v2"
YARA_MANIFEST_GRAMMAR_VERSION = "yara_release_manifest_v2"
YARA_ARCHIVE_POLICY_VERSION = "yara_archive_policy_v2"
YARA_CACHE_SCHEMA_VERSION = "yara_compiled_cache_v3"
YARA_PARTITION_VERSION = "yara_partition_v2"
YARA_COMPILE_POLICY_VERSION = "yara_compile_policy_v1"

__all__ = (
    "YARA_ARCHIVE_POLICY_VERSION",
    "YARA_CACHE_SCHEMA_VERSION",
    "YARA_COMPILE_POLICY_VERSION",
    "YARA_CONFIG_VERSION",
    "YARA_MANIFEST_GRAMMAR_VERSION",
    "YARA_PARTITION_VERSION",
    "YARA_RELEASE_CONTRACT_VERSION",
)
