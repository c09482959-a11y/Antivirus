"""Core immutable scanner policy snapshot contracts."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.scanners.config.immutable_policy import (
    freeze_policy_contract_value,
    policy_float,
    policy_group_keywords,
    policy_int,
    policy_text,
    policy_text_frozenset,
    policy_text_tuple,
)


@dataclass(frozen=True, slots=True)
class PayloadPolicySnapshot:
    max_candidates: int
    max_text_bytes: int
    min_base64_chars: int
    min_hex_chars: int
    default_max_depth: int
    source: str
    schema: str = "payload_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "max_candidates", policy_int(self.max_candidates))
        object.__setattr__(self, "max_text_bytes", policy_int(self.max_text_bytes))
        object.__setattr__(self, "min_base64_chars", policy_int(self.min_base64_chars))
        object.__setattr__(self, "min_hex_chars", policy_int(self.min_hex_chars))
        object.__setattr__(self, "default_max_depth", policy_int(self.default_max_depth))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="payload_policy.v1"))


@dataclass(frozen=True, slots=True)
class PicklePolicySnapshot:
    fast_escalation_max_bytes: int
    fast_b64_sample_max: int
    renpy_extensions: tuple[str, ...]
    decode_max_decoded_bytes: int
    decode_max_file_bytes: int
    decode_max_objects: int
    decode_max_offsets: int
    decode_min_payload_bytes: int
    fragment_min_b64_chars: int
    literal_join_max: int
    fast_dangerous_text: tuple[str, ...]
    fast_exec_text: tuple[str, ...]
    safe_reconstruct_globals: frozenset[str]
    safe_reconstruct_prefixes: tuple[str, ...]
    dangerous_globals: frozenset[str]
    suspicious_global_parts: frozenset[str]
    decoded_payload_exec_needles: tuple[str, ...]
    decoded_payload_network_needles: tuple[str, ...]
    source: str
    schema: str = "pickle_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "fast_escalation_max_bytes", policy_int(self.fast_escalation_max_bytes))
        object.__setattr__(self, "fast_b64_sample_max", policy_int(self.fast_b64_sample_max))
        object.__setattr__(self, "renpy_extensions", policy_text_tuple(self.renpy_extensions))
        object.__setattr__(self, "decode_max_decoded_bytes", policy_int(self.decode_max_decoded_bytes))
        object.__setattr__(self, "decode_max_file_bytes", policy_int(self.decode_max_file_bytes))
        object.__setattr__(self, "decode_max_objects", policy_int(self.decode_max_objects))
        object.__setattr__(self, "decode_max_offsets", policy_int(self.decode_max_offsets))
        object.__setattr__(self, "decode_min_payload_bytes", policy_int(self.decode_min_payload_bytes))
        object.__setattr__(self, "fragment_min_b64_chars", policy_int(self.fragment_min_b64_chars))
        object.__setattr__(self, "literal_join_max", policy_int(self.literal_join_max))
        object.__setattr__(self, "fast_dangerous_text", policy_text_tuple(self.fast_dangerous_text))
        object.__setattr__(self, "fast_exec_text", policy_text_tuple(self.fast_exec_text))
        object.__setattr__(self, "safe_reconstruct_globals", policy_text_frozenset(self.safe_reconstruct_globals))
        object.__setattr__(self, "safe_reconstruct_prefixes", policy_text_tuple(self.safe_reconstruct_prefixes))
        object.__setattr__(self, "dangerous_globals", policy_text_frozenset(self.dangerous_globals))
        object.__setattr__(self, "suspicious_global_parts", policy_text_frozenset(self.suspicious_global_parts))
        object.__setattr__(self, "decoded_payload_exec_needles", policy_text_tuple(self.decoded_payload_exec_needles))
        object.__setattr__(self, "decoded_payload_network_needles", policy_text_tuple(self.decoded_payload_network_needles))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="pickle_policy.v1"))


@dataclass(frozen=True, slots=True)
class RawChunkPolicySnapshot:
    context_anchors: tuple[str, ...]
    decode_anchors: tuple[str, ...]
    source: str
    schema: str = "raw_chunk_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "context_anchors", policy_text_tuple(self.context_anchors))
        object.__setattr__(self, "decode_anchors", policy_text_tuple(self.decode_anchors))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="raw_chunk_policy.v1"))


@dataclass(frozen=True, slots=True)
class TextPolicySnapshot:
    runtime_strong_attack_context: tuple[str, ...]
    broad_unvalidated_tags: frozenset[str]
    library_baseline_hard_proof_tags: frozenset[str]
    passive_textual_categories: frozenset[str]
    game_engine_context_tags: frozenset[str]
    correlation_group_keywords: tuple[tuple[str, tuple[str, ...]], ...]
    contextual_baseline_min_keep_without_anchor: float
    contextual_baseline_min_keep_with_anchor: float
    contextual_baseline_min_files: int
    contextual_baseline_common_tag_prob: float
    contextual_baseline_max_reduction: float
    vector_cluster_max_bonus: float
    context_corroboration_max_bonus: float
    combined_context_max_bonus: float
    min_concrete_tags_for_context_boost: int
    min_score_for_context_boost: float
    api_groups: object
    api_specific_tags: object
    api_group_tags: object
    api_group_inferred_tags: object
    spyware_collection_tags: frozenset[str]
    spyware_sensitive_tags: frozenset[str]
    spyware_sensitive_text_terms: frozenset[str]
    spyware_suppressed_tags: frozenset[str]
    source: str
    schema: str = "text_policy.v1"

    def __post_init__(self) -> None:
        object.__setattr__(self, "runtime_strong_attack_context", policy_text_tuple(self.runtime_strong_attack_context))
        object.__setattr__(self, "broad_unvalidated_tags", policy_text_frozenset(self.broad_unvalidated_tags))
        object.__setattr__(self, "library_baseline_hard_proof_tags", policy_text_frozenset(self.library_baseline_hard_proof_tags))
        object.__setattr__(self, "passive_textual_categories", policy_text_frozenset(self.passive_textual_categories))
        object.__setattr__(self, "game_engine_context_tags", policy_text_frozenset(self.game_engine_context_tags))
        object.__setattr__(self, "correlation_group_keywords", policy_group_keywords(self.correlation_group_keywords))
        object.__setattr__(self, "contextual_baseline_min_keep_without_anchor", policy_float(self.contextual_baseline_min_keep_without_anchor))
        object.__setattr__(self, "contextual_baseline_min_keep_with_anchor", policy_float(self.contextual_baseline_min_keep_with_anchor))
        object.__setattr__(self, "contextual_baseline_min_files", policy_int(self.contextual_baseline_min_files))
        object.__setattr__(self, "contextual_baseline_common_tag_prob", policy_float(self.contextual_baseline_common_tag_prob))
        object.__setattr__(self, "contextual_baseline_max_reduction", policy_float(self.contextual_baseline_max_reduction))
        object.__setattr__(self, "vector_cluster_max_bonus", policy_float(self.vector_cluster_max_bonus))
        object.__setattr__(self, "context_corroboration_max_bonus", policy_float(self.context_corroboration_max_bonus))
        object.__setattr__(self, "combined_context_max_bonus", policy_float(self.combined_context_max_bonus))
        object.__setattr__(self, "min_concrete_tags_for_context_boost", policy_int(self.min_concrete_tags_for_context_boost))
        object.__setattr__(self, "min_score_for_context_boost", policy_float(self.min_score_for_context_boost))
        object.__setattr__(self, "api_groups", freeze_policy_contract_value(self.api_groups))
        object.__setattr__(self, "api_specific_tags", freeze_policy_contract_value(self.api_specific_tags))
        object.__setattr__(self, "api_group_tags", freeze_policy_contract_value(self.api_group_tags))
        object.__setattr__(self, "api_group_inferred_tags", freeze_policy_contract_value(self.api_group_inferred_tags))
        object.__setattr__(self, "spyware_collection_tags", policy_text_frozenset(self.spyware_collection_tags))
        object.__setattr__(self, "spyware_sensitive_tags", policy_text_frozenset(self.spyware_sensitive_tags))
        object.__setattr__(self, "spyware_sensitive_text_terms", policy_text_frozenset(self.spyware_sensitive_text_terms))
        object.__setattr__(self, "spyware_suppressed_tags", policy_text_frozenset(self.spyware_suppressed_tags))
        object.__setattr__(self, "source", policy_text(self.source))
        object.__setattr__(self, "schema", policy_text(self.schema, default="text_policy.v1"))


__all__ = (
    "PayloadPolicySnapshot",
    "PicklePolicySnapshot",
    "RawChunkPolicySnapshot",
    "TextPolicySnapshot",
)
