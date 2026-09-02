"""Immutable scanner filetype and engine policy snapshot contracts."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.config.immutable_policy import (
    freeze_policy_contract_value,
    policy_bool,
    policy_float,
    policy_string_pairs,
    policy_text,
    policy_text_frozenset,
    policy_text_tuple,
)


@dataclass(frozen=True, slots=True)
class FiletypePolicySnapshot:
    behavior_model_version: str
    high_risk_buckets: frozenset[str]
    non_execution_capabilities: frozenset[str]
    container_execution_capabilities: frozenset[str]
    passive_asset_categories: frozenset[str]
    dangerous_actual_categories: frozenset[str]
    engine_extension_bucket_policies: object
    global_common_filetype_buckets: object
    engine_specific_filetype_buckets: object
    expected_magic_types_by_extension: object
    routable_extensions_by_claim: object
    all_routable_extensions: frozenset[str]
    magic_type_category: object
    source: str
    schema: str = "filetype_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "behavior_model_version", policy_text(self.behavior_model_version))
        object.__setattr__(self, "high_risk_buckets", policy_text_frozenset(self.high_risk_buckets))
        object.__setattr__(self, "non_execution_capabilities", policy_text_frozenset(self.non_execution_capabilities))
        object.__setattr__(self, "container_execution_capabilities", policy_text_frozenset(self.container_execution_capabilities))
        object.__setattr__(self, "passive_asset_categories", policy_text_frozenset(self.passive_asset_categories))
        object.__setattr__(self, "dangerous_actual_categories", policy_text_frozenset(self.dangerous_actual_categories))
        object.__setattr__(self, "engine_extension_bucket_policies", freeze_policy_contract_value(self.engine_extension_bucket_policies))
        object.__setattr__(self, "global_common_filetype_buckets", freeze_policy_contract_value(self.global_common_filetype_buckets))
        object.__setattr__(self, "engine_specific_filetype_buckets", freeze_policy_contract_value(self.engine_specific_filetype_buckets))
        object.__setattr__(self, "expected_magic_types_by_extension", freeze_policy_contract_value(self.expected_magic_types_by_extension))
        object.__setattr__(self, "routable_extensions_by_claim", freeze_policy_contract_value(self.routable_extensions_by_claim))
        object.__setattr__(self, "all_routable_extensions", policy_text_frozenset(self.all_routable_extensions))
        object.__setattr__(self, "magic_type_category", freeze_policy_contract_value(self.magic_type_category))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="filetype_policy.v1"))


@dataclass(frozen=True, slots=True)
class EnginePolicySnapshot:
    use_ilspy: bool
    unity_lifecycle_hooks: tuple[str, ...]
    unity_runtime_checks: tuple[tuple[str, str], ...]
    unity_container_asset_extensions: frozenset[str]
    rpgm_encrypted_media_url_markers: tuple[str, ...]
    rpgm_decrypted_media_suspicious_tokens: tuple[str, ...]
    engine_file_context_cues: object
    media_profile_extensions: frozenset[str]
    media_profile_tags: frozenset[str]
    engine_context_runtime_hint_ambiguous_threshold: float
    engine_context_runtime_hint_confidence_threshold: float
    engine_context_runtime_hint_ambiguous_weight: float
    engine_context_runtime_hint_weak_weight: float
    source: str
    schema: str = "engine_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "use_ilspy", policy_bool(self.use_ilspy))
        object.__setattr__(self, "unity_lifecycle_hooks", policy_text_tuple(self.unity_lifecycle_hooks))
        object.__setattr__(self, "unity_runtime_checks", policy_string_pairs(self.unity_runtime_checks))
        object.__setattr__(self, "unity_container_asset_extensions", policy_text_frozenset(self.unity_container_asset_extensions))
        object.__setattr__(self, "rpgm_encrypted_media_url_markers", policy_text_tuple(self.rpgm_encrypted_media_url_markers))
        object.__setattr__(self, "rpgm_decrypted_media_suspicious_tokens", policy_text_tuple(self.rpgm_decrypted_media_suspicious_tokens))
        object.__setattr__(self, "engine_file_context_cues", freeze_policy_contract_value(self.engine_file_context_cues))
        object.__setattr__(self, "media_profile_extensions", policy_text_frozenset(self.media_profile_extensions))
        object.__setattr__(self, "media_profile_tags", policy_text_frozenset(self.media_profile_tags))
        object.__setattr__(self, "engine_context_runtime_hint_ambiguous_threshold", policy_float(self.engine_context_runtime_hint_ambiguous_threshold))
        object.__setattr__(self, "engine_context_runtime_hint_confidence_threshold", policy_float(self.engine_context_runtime_hint_confidence_threshold))
        object.__setattr__(self, "engine_context_runtime_hint_ambiguous_weight", policy_float(self.engine_context_runtime_hint_ambiguous_weight))
        object.__setattr__(self, "engine_context_runtime_hint_weak_weight", policy_float(self.engine_context_runtime_hint_weak_weight))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="engine_policy.v1"))


__all__ = ("EnginePolicySnapshot", "FiletypePolicySnapshot")
