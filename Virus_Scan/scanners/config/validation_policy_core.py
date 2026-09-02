"""Scanner config validators for payload, pickle, raw chunk, text, filetype, and engine policies."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.scanners.config.contracts import (
    EnginePolicySnapshot,
    FiletypePolicySnapshot,
    PayloadPolicySnapshot,
    PicklePolicySnapshot,
    RawChunkPolicySnapshot,
    ScannerConfigError,
    TextPolicySnapshot,
)
from Virus_Scan.scanners.config.validation_helpers import (
    _FloatRequirement,
    _config_failure,
    _require_bool,
    _require_float,
    _require_group_keywords,
    _require_pair_tuple,
    _require_policy_mapping,
)
from Virus_Scan.scanners.config.validation_helpers import _IntRequirement, _StringTupleRequirement, _require_int, _require_str_tuple

def validate_payload_policy(policy: dict[str, object], *, source: str) -> PayloadPolicySnapshot:
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure("payload_policy", source, "payload policy root must be an object"))
    schema_version = policy.get("schema_version")
    if schema_version != 1:
        raise ScannerConfigError(_config_failure("payload_policy", source, "schema_version must equal 1"))
    return PayloadPolicySnapshot(
        max_candidates=_require_int(_IntRequirement(policy, 'max_candidates', (1, 256), source, 'payload_policy')),
        max_text_bytes=_require_int(_IntRequirement(policy, 'max_text_bytes', (1024, 16 * 1024 * 1024), source, 'payload_policy')),
        min_base64_chars=_require_int(_IntRequirement(policy, 'min_base64_chars', (4, 4096), source, 'payload_policy')),
        min_hex_chars=_require_int(_IntRequirement(policy, 'min_hex_chars', (4, 4096), source, 'payload_policy')),
        default_max_depth=_require_int(_IntRequirement(policy, 'default_max_depth', (1, 16), source, 'payload_policy')),
        source=str(Path(source)),
    )

def validate_pickle_policy(policy: dict[str, object], *, source: str) -> PicklePolicySnapshot:
    config_name = "pickle_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "pickle policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return PicklePolicySnapshot(
        fast_escalation_max_bytes=_require_int(_IntRequirement(policy, 'fast_escalation_max_bytes', (1024, 16 * 1024 * 1024), source, config_name)),
        fast_b64_sample_max=_require_int(_IntRequirement(policy, 'fast_b64_sample_max', (1024, 16 * 1024 * 1024), source, config_name)),
        renpy_extensions=_require_str_tuple(_StringTupleRequirement(policy, 'renpy_extensions', (1, 64), source, config_name)),
        decode_max_decoded_bytes=_require_int(_IntRequirement(policy, 'decode_max_decoded_bytes', (1024, 16 * 1024 * 1024), source, config_name)),
        decode_max_file_bytes=_require_int(_IntRequirement(policy, 'decode_max_file_bytes', (1024, 64 * 1024 * 1024), source, config_name)),
        decode_max_objects=_require_int(_IntRequirement(policy, 'decode_max_objects', (1, 4096), source, config_name)),
        decode_max_offsets=_require_int(_IntRequirement(policy, 'decode_max_offsets', (1, 4096), source, config_name)),
        decode_min_payload_bytes=_require_int(_IntRequirement(policy, 'decode_min_payload_bytes', (1, 4096), source, config_name)),
        fragment_min_b64_chars=_require_int(_IntRequirement(policy, 'fragment_min_b64_chars', (4, 4096), source, config_name)),
        literal_join_max=_require_int(_IntRequirement(policy, 'literal_join_max', (1, 128), source, config_name)),
        fast_dangerous_text=_require_str_tuple(_StringTupleRequirement(policy, 'fast_dangerous_text', (1, 256), source, config_name)),
        fast_exec_text=_require_str_tuple(_StringTupleRequirement(policy, 'fast_exec_text', (1, 256), source, config_name)),
        safe_reconstruct_globals=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'safe_reconstruct_globals', (0, 256), source, config_name))),
        safe_reconstruct_prefixes=_require_str_tuple(_StringTupleRequirement(policy, 'safe_reconstruct_prefixes', (0, 256), source, config_name)),
        dangerous_globals=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'dangerous_globals', (0, 256), source, config_name))),
        suspicious_global_parts=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'suspicious_global_parts', (0, 256), source, config_name))),
        decoded_payload_exec_needles=_require_str_tuple(_StringTupleRequirement(policy, 'decoded_payload_exec_needles', (1, 128), source, config_name)),
        decoded_payload_network_needles=_require_str_tuple(_StringTupleRequirement(policy, 'decoded_payload_network_needles', (1, 128), source, config_name)),
        source=str(Path(source)),
    )

def validate_raw_chunk_policy(policy: dict[str, object], *, source: str) -> RawChunkPolicySnapshot:
    config_name = "raw_chunk_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "raw chunk policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return RawChunkPolicySnapshot(
        context_anchors=_require_str_tuple(_StringTupleRequirement(policy, 'context_anchors', (1, 512), source, config_name)),
        decode_anchors=_require_str_tuple(_StringTupleRequirement(policy, 'decode_anchors', (1, 512), source, config_name)),
        source=str(Path(source)),
    )

def validate_text_policy(policy: dict[str, object], *, source: str) -> TextPolicySnapshot:
    config_name = "text_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "text policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return TextPolicySnapshot(
        runtime_strong_attack_context=_require_str_tuple(_StringTupleRequirement(policy, 'runtime_strong_attack_context', (1, 512), source, config_name)),
        broad_unvalidated_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'broad_unvalidated_tags', (1, 512), source, config_name))),
        library_baseline_hard_proof_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'library_baseline_hard_proof_tags', (1, 1024), source, config_name))),
        passive_textual_categories=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'passive_textual_categories', (1, 128), source, config_name))),
        game_engine_context_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'game_engine_context_tags', (1, 256), source, config_name))),
        correlation_group_keywords=_require_group_keywords(policy, "correlation_group_keywords", source=source, config_name=config_name),
        contextual_baseline_min_keep_without_anchor=_require_float(_FloatRequirement(policy, "contextual_baseline_min_keep_without_anchor", (0.0, 1000.0), source, config_name)),
        contextual_baseline_min_keep_with_anchor=_require_float(_FloatRequirement(policy, "contextual_baseline_min_keep_with_anchor", (0.0, 1000.0), source, config_name)),
        contextual_baseline_min_files=_require_int(_IntRequirement(policy, 'contextual_baseline_min_files', (1, 100000), source, config_name)),
        contextual_baseline_common_tag_prob=_require_float(_FloatRequirement(policy, "contextual_baseline_common_tag_prob", (0.0, 1.0), source, config_name)),
        contextual_baseline_max_reduction=_require_float(_FloatRequirement(policy, "contextual_baseline_max_reduction", (0.0, 1000.0), source, config_name)),
        vector_cluster_max_bonus=_require_float(_FloatRequirement(policy, "vector_cluster_max_bonus", (0.0, 1000.0), source, config_name)),
        context_corroboration_max_bonus=_require_float(_FloatRequirement(policy, "context_corroboration_max_bonus", (0.0, 1000.0), source, config_name)),
        combined_context_max_bonus=_require_float(_FloatRequirement(policy, "combined_context_max_bonus", (0.0, 1000.0), source, config_name)),
        min_concrete_tags_for_context_boost=_require_int(_IntRequirement(policy, 'min_concrete_tags_for_context_boost', (0, 1000), source, config_name)),
        min_score_for_context_boost=_require_float(_FloatRequirement(policy, "min_score_for_context_boost", (0.0, 1000.0), source, config_name)),
        api_groups=_require_policy_mapping(policy, "api_groups", source=source, config_name=config_name),
        api_specific_tags=_require_policy_mapping(policy, "api_specific_tags", source=source, config_name=config_name),
        api_group_tags=_require_policy_mapping(policy, "api_group_tags", source=source, config_name=config_name),
        api_group_inferred_tags=_require_policy_mapping(policy, "api_group_inferred_tags", source=source, config_name=config_name),
        spyware_collection_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'spyware_collection_tags', (1, 256), source, config_name))),
        spyware_sensitive_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'spyware_sensitive_tags', (1, 256), source, config_name))),
        spyware_sensitive_text_terms=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'spyware_sensitive_text_terms', (1, 256), source, config_name))),
        spyware_suppressed_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'spyware_suppressed_tags', (1, 256), source, config_name))),
        source=str(Path(source)),
    )

def validate_filetype_policy(policy: dict[str, object], *, source: str) -> FiletypePolicySnapshot:
    config_name = "filetype_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "filetype policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    version = policy.get("behavior_model_version")
    if not isinstance(version, str) or not version:
        raise ScannerConfigError(_config_failure(config_name, source, "behavior_model_version must be a non-empty string"))
    return FiletypePolicySnapshot(
        behavior_model_version=version,
        high_risk_buckets=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'high_risk_buckets', (1, 64), source, config_name))),
        non_execution_capabilities=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'non_execution_capabilities', (1, 64), source, config_name))),
        container_execution_capabilities=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'container_execution_capabilities', (1, 64), source, config_name))),
        passive_asset_categories=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'passive_asset_categories', (1, 128), source, config_name))),
        dangerous_actual_categories=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'dangerous_actual_categories', (1, 128), source, config_name))),
        engine_extension_bucket_policies=_require_policy_mapping(policy, "engine_extension_bucket_policies", source=source, config_name=config_name),
        global_common_filetype_buckets=_require_policy_mapping(policy, "global_common_filetype_buckets", source=source, config_name=config_name),
        engine_specific_filetype_buckets=_require_policy_mapping(policy, "engine_specific_filetype_buckets", source=source, config_name=config_name),
        expected_magic_types_by_extension=_require_policy_mapping(policy, "expected_magic_types_by_extension", source=source, config_name=config_name),
        routable_extensions_by_claim=_require_policy_mapping(policy, "routable_extensions_by_claim", source=source, config_name=config_name),
        all_routable_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'all_routable_extensions', (1, 512), source, config_name))),
        magic_type_category=_require_policy_mapping(policy, "magic_type_category", source=source, config_name=config_name),
        source=str(Path(source)),
    )

def validate_engine_policy(policy: dict[str, object], *, source: str) -> EnginePolicySnapshot:
    config_name = "engine_policy"
    if not isinstance(policy, dict):
        raise ScannerConfigError(_config_failure(config_name, source, "engine policy root must be an object"))
    if policy.get("schema_version") != 1:
        raise ScannerConfigError(_config_failure(config_name, source, "schema_version must equal 1"))
    return EnginePolicySnapshot(
        use_ilspy=_require_bool(policy, "use_ilspy", source=source, config_name=config_name),
        unity_lifecycle_hooks=_require_str_tuple(_StringTupleRequirement(policy, 'unity_lifecycle_hooks', (1, 128), source, config_name)),
        unity_runtime_checks=_require_pair_tuple(policy, "unity_runtime_checks", source=source, config_name=config_name),
        unity_container_asset_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'unity_container_asset_extensions', (1, 64), source, config_name))),
        rpgm_encrypted_media_url_markers=_require_str_tuple(_StringTupleRequirement(policy, 'rpgm_encrypted_media_url_markers', (1, 64), source, config_name)),
        rpgm_decrypted_media_suspicious_tokens=_require_str_tuple(_StringTupleRequirement(policy, 'rpgm_decrypted_media_suspicious_tokens', (1, 256), source, config_name)),
        engine_file_context_cues=_require_policy_mapping(policy, "engine_file_context_cues", source=source, config_name=config_name),
        media_profile_extensions=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'media_profile_extensions', (1, 128), source, config_name))),
        media_profile_tags=frozenset(_require_str_tuple(_StringTupleRequirement(policy, 'media_profile_tags', (1, 128), source, config_name))),
        engine_context_runtime_hint_ambiguous_threshold=_require_float(_FloatRequirement(policy, "engine_context_runtime_hint_ambiguous_threshold", (0.0, 1.0), source, config_name)),
        engine_context_runtime_hint_confidence_threshold=_require_float(_FloatRequirement(policy, "engine_context_runtime_hint_confidence_threshold", (0.0, 1.0), source, config_name)),
        engine_context_runtime_hint_ambiguous_weight=_require_float(_FloatRequirement(policy, "engine_context_runtime_hint_ambiguous_weight", (0.0, 10.0), source, config_name)),
        engine_context_runtime_hint_weak_weight=_require_float(_FloatRequirement(policy, "engine_context_runtime_hint_weak_weight", (0.0, 10.0), source, config_name)),
        source=str(Path(source)),
    )

__all__ = (
    "validate_engine_policy",
    "validate_filetype_policy",
    "validate_payload_policy",
    "validate_pickle_policy",
    "validate_raw_chunk_policy",
    "validate_text_policy",
)
