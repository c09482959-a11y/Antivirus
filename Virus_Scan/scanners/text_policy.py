"""Scanner-owned immutable text policy constants.

This module centralizes the text scanner policy snapshot so Phase 11 text/context/scoring
helpers do not reload or mutate policy tables independently.
"""

from Virus_Scan.scanners.config.loader import load_payload_policy_snapshot, load_text_policy_snapshot

_PAYLOAD_POLICY = load_payload_policy_snapshot()
_TEXT_POLICY = load_text_policy_snapshot()

DECODE_LAYER_MAX_CANDIDATES = _PAYLOAD_POLICY.max_candidates
DECODE_LAYER_MAX_TEXT_BYTES = _PAYLOAD_POLICY.max_text_bytes
DECODE_LAYER_MIN_B64_CHARS = _PAYLOAD_POLICY.min_base64_chars
DECODE_LAYER_MIN_HEX_CHARS = _PAYLOAD_POLICY.min_hex_chars
BROAD_UNVALIDATED_TAGS = _TEXT_POLICY.broad_unvalidated_tags
_RUNTIME_STRONG_ATTACK_CONTEXT = _TEXT_POLICY.runtime_strong_attack_context
_LIBRARY_BASELINE_HARD_PROOF_TAGS = _TEXT_POLICY.library_baseline_hard_proof_tags
PASSIVE_TEXTUAL_CATEGORIES = _TEXT_POLICY.passive_textual_categories
GAME_ENGINE_CONTEXT_TAGS = _TEXT_POLICY.game_engine_context_tags
CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR = _TEXT_POLICY.contextual_baseline_min_keep_without_anchor
CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR = _TEXT_POLICY.contextual_baseline_min_keep_with_anchor
CONTEXTUAL_BASELINE_VERSION = 'contextual_expected_behavior_v1'
CONTEXTUAL_BASELINE_MIN_FILES = _TEXT_POLICY.contextual_baseline_min_files
CONTEXTUAL_BASELINE_COMMON_TAG_PROB = _TEXT_POLICY.contextual_baseline_common_tag_prob
CONTEXTUAL_BASELINE_MAX_REDUCTION = _TEXT_POLICY.contextual_baseline_max_reduction
CONTEXT_AMPLIFIER_VERSION = 'context_confidence_amplifier_v1_capped'
VECTOR_CLUSTER_MAX_BONUS = _TEXT_POLICY.vector_cluster_max_bonus
CONTEXT_CORROBORATION_MAX_BONUS = _TEXT_POLICY.context_corroboration_max_bonus
COMBINED_CONTEXT_MAX_BONUS = _TEXT_POLICY.combined_context_max_bonus
MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST = _TEXT_POLICY.min_concrete_tags_for_context_boost
MIN_SCORE_FOR_CONTEXT_BOOST = _TEXT_POLICY.min_score_for_context_boost
CORRELATION_GROUP_KEYWORDS = _TEXT_POLICY.correlation_group_keywords

API_GROUPS = _TEXT_POLICY.api_groups
API_SPECIFIC_TAGS = _TEXT_POLICY.api_specific_tags
API_GROUP_TAGS = _TEXT_POLICY.api_group_tags
API_GROUP_INFERRED_TAGS = _TEXT_POLICY.api_group_inferred_tags
SPYWARE_COLLECTION_TAGS = _TEXT_POLICY.spyware_collection_tags
SPYWARE_SENSITIVE_TAGS = _TEXT_POLICY.spyware_sensitive_tags
SPYWARE_SENSITIVE_TEXT_TERMS = _TEXT_POLICY.spyware_sensitive_text_terms
SPYWARE_SUPPRESSED_TAGS = _TEXT_POLICY.spyware_suppressed_tags

__all__ = (
    'API_GROUPS',
    'API_GROUP_INFERRED_TAGS',
    'API_GROUP_TAGS',
    'API_SPECIFIC_TAGS',
    'BROAD_UNVALIDATED_TAGS',
    'COMBINED_CONTEXT_MAX_BONUS',
    'CONTEXTUAL_BASELINE_COMMON_TAG_PROB',
    'CONTEXTUAL_BASELINE_MAX_REDUCTION',
    'CONTEXTUAL_BASELINE_MIN_FILES',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR',
    'CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR',
    'CONTEXTUAL_BASELINE_VERSION',
    'CONTEXT_AMPLIFIER_VERSION',
    'CONTEXT_CORROBORATION_MAX_BONUS',
    'CORRELATION_GROUP_KEYWORDS',
    'DECODE_LAYER_MAX_CANDIDATES',
    'DECODE_LAYER_MAX_TEXT_BYTES',
    'DECODE_LAYER_MIN_B64_CHARS',
    'DECODE_LAYER_MIN_HEX_CHARS',
    'GAME_ENGINE_CONTEXT_TAGS',
    'MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST',
    'MIN_SCORE_FOR_CONTEXT_BOOST',
    'PASSIVE_TEXTUAL_CATEGORIES',
    'SPYWARE_COLLECTION_TAGS',
    'SPYWARE_SENSITIVE_TAGS',
    'SPYWARE_SENSITIVE_TEXT_TERMS',
    'SPYWARE_SUPPRESSED_TAGS',
    'VECTOR_CLUSTER_MAX_BONUS',
    '_LIBRARY_BASELINE_HARD_PROOF_TAGS',
    '_PAYLOAD_POLICY',
    '_RUNTIME_STRONG_ATTACK_CONTEXT',
    '_TEXT_POLICY',
)
