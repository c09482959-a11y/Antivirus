"""Canonical public text-scanner surface backed by bounded text modules.

The implementation is decomposed into scanner-owned modules for extraction,
raw chunk scanning, API graphing, behavior predicates, validation gates,
context parsing, scoring, and policy.  This module intentionally contains no
old inline implementation and no duplicate logic; names are bound at module load
time to preserve the established public scanner contract.
"""
from Virus_Scan.scanners import image_jpeg_segments as _image_jpeg_segments
from Virus_Scan.scanners import payload_decode as _payload_decode
from Virus_Scan.scanners import text_api_mapping as _text_api_mapping
from Virus_Scan.scanners import text_api_policy as _text_api_policy
from Virus_Scan.scanners import text_api_timeline as _text_api_timeline
from Virus_Scan.scanners import text_behavior as _text_behavior
from Virus_Scan.scanners import text_context as _text_context
from Virus_Scan.scanners import text_extraction as _text_extraction
from Virus_Scan.scanners import text_policy as _text_policy
from Virus_Scan.scanners import text_spyware_gate as _text_spyware_gate
from Virus_Scan.scanners.text_api_sequence import (
    api_ngrams as _text_api_ngrams,
    build_api_sequence as _text_build_api_sequence,
    extract_api_calls as _text_extract_api_calls,
    extract_api_sequence_from_blob as _text_extract_api_sequence_from_blob,
)
from Virus_Scan.scanners.text_graph_enrichment import (
    TextGraphEnrichmentRequest,
    enrich_with_api_and_graph as _text_enrich_with_api_and_graph,
)
from Virus_Scan.scanners.text_raw_chunks import (
    _global_raw_pe_api_header as _text_global_raw_pe_api_header,
    _global_raw_read_range_text as _text_global_raw_read_range_text,
    _global_raw_read_range_text_result as _text_global_raw_read_range_text_result,
    _global_raw_renpy_chunk as _text_global_raw_renpy_chunk,
    _global_raw_rpgm_js_ast_chunk as _text_global_raw_rpgm_js_ast_chunk,
    _global_raw_should_context_scan as _text_global_raw_should_context_scan,
    _intrastage_contextual_chunk_raw as _text_intrastage_contextual_chunk_raw,
    global_raw_pe_api_header as _text_public_global_raw_pe_api_header,
    global_raw_renpy_chunk as _text_public_global_raw_renpy_chunk,
    global_raw_rpgm_js_ast_chunk as _text_public_global_raw_rpgm_js_ast_chunk,
)
from Virus_Scan.scanners.text_validation_gates import (
    infer_correlation_group as _text_infer_correlation_group,
    library_baseline_hard_proof_status as _text_library_baseline_hard_proof_status,
    library_baseline_has_hard_proof as _text_library_baseline_has_hard_proof,
    reference_url_only_score_cap as _text_reference_url_only_score_cap,
    validate_high_risk_tag as _text_validate_high_risk_tag,
)

build_api_regex = _text_api_policy.build_api_regex
map_api_to_group = _text_api_policy.map_api_to_group
api_ngrams = _text_api_ngrams
build_api_sequence = _text_build_api_sequence
extract_api_calls = _text_extract_api_calls
extract_api_sequence_from_blob = _text_extract_api_sequence_from_blob
api_to_timeline_tag = _text_api_mapping.api_to_timeline_tag
infer_tags_from_api = _text_api_mapping.infer_tags_from_api
primary_behavior_for_tag = _text_api_mapping.primary_behavior_for_tag
gate_spyware_collection_chains = _text_spyware_gate.gate_spyware_collection_chains
build_behavior_timeline = _text_api_timeline.build_behavior_timeline
enrich_with_api_and_graph = _text_enrich_with_api_and_graph


_engine_hint_to_context = _text_context._engine_hint_to_context
_filetype_claim_matches_actual = _text_context._filetype_claim_matches_actual
_game_engine_context = _text_context._game_engine_context


BROAD_UNVALIDATED_TAGS = _text_policy.BROAD_UNVALIDATED_TAGS
COMBINED_CONTEXT_MAX_BONUS = _text_policy.COMBINED_CONTEXT_MAX_BONUS
CONTEXT_AMPLIFIER_VERSION = _text_policy.CONTEXT_AMPLIFIER_VERSION
CONTEXTUAL_BASELINE_COMMON_TAG_PROB = _text_policy.CONTEXTUAL_BASELINE_COMMON_TAG_PROB
CONTEXTUAL_BASELINE_MAX_REDUCTION = _text_policy.CONTEXTUAL_BASELINE_MAX_REDUCTION
CONTEXTUAL_BASELINE_MIN_FILES = _text_policy.CONTEXTUAL_BASELINE_MIN_FILES
CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR = _text_policy.CONTEXTUAL_BASELINE_MIN_KEEP_WITH_ANCHOR
CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR = _text_policy.CONTEXTUAL_BASELINE_MIN_KEEP_WITHOUT_ANCHOR
CONTEXTUAL_BASELINE_VERSION = _text_policy.CONTEXTUAL_BASELINE_VERSION
CORRELATION_GROUP_KEYWORDS = _text_policy.CORRELATION_GROUP_KEYWORDS
DECODE_LAYER_MAX_CANDIDATES = _text_policy.DECODE_LAYER_MAX_CANDIDATES
DECODE_LAYER_MAX_TEXT_BYTES = _text_policy.DECODE_LAYER_MAX_TEXT_BYTES
DECODE_LAYER_MIN_B64_CHARS = _text_policy.DECODE_LAYER_MIN_B64_CHARS
DECODE_LAYER_MIN_HEX_CHARS = _text_policy.DECODE_LAYER_MIN_HEX_CHARS
GAME_ENGINE_CONTEXT_TAGS = _text_policy.GAME_ENGINE_CONTEXT_TAGS
CONTEXT_CORROBORATION_MAX_BONUS = _text_policy.CONTEXT_CORROBORATION_MAX_BONUS
MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST = _text_policy.MIN_CONCRETE_TAGS_FOR_CONTEXT_BOOST
MIN_SCORE_FOR_CONTEXT_BOOST = _text_policy.MIN_SCORE_FOR_CONTEXT_BOOST
PASSIVE_TEXTUAL_CATEGORIES = _text_policy.PASSIVE_TEXTUAL_CATEGORIES
VECTOR_CLUSTER_MAX_BONUS = _text_policy.VECTOR_CLUSTER_MAX_BONUS
_LIBRARY_BASELINE_HARD_PROOF_TAGS = _text_policy._LIBRARY_BASELINE_HARD_PROOF_TAGS
_PAYLOAD_POLICY = _text_policy._PAYLOAD_POLICY
_RUNTIME_STRONG_ATTACK_CONTEXT = _text_policy._RUNTIME_STRONG_ATTACK_CONTEXT
_TEXT_POLICY = _text_policy._TEXT_POLICY

safe_decode_payloads = _payload_decode.safe_decode_payloads
_scan_jpeg_segments = _image_jpeg_segments._scan_jpeg_segments
_behavior_text_bits = _text_behavior._behavior_text_bits
_decode_debug = _text_behavior._decode_debug
_has_command_exec_behavior = _text_behavior._has_command_exec_behavior
_has_confirmed_exfil_proof = _text_behavior._has_confirmed_exfil_proof
_has_dll_hijack_behavior = _text_behavior._has_dll_hijack_behavior
_has_input_collection_behavior = _text_behavior._has_input_collection_behavior
_has_lolbin_script_behavior = _text_behavior._has_lolbin_script_behavior
_has_macro_exec_behavior = _text_behavior._has_macro_exec_behavior
_is_renpy_bytecode_path = _text_behavior._is_renpy_bytecode_path
_is_renpy_tts_wscript_context = _text_behavior._is_renpy_tts_wscript_context
_looks_like_base64_payload = _text_behavior._looks_like_base64_payload
_looks_like_base64_payload_status = _text_behavior._looks_like_base64_payload_status
_renpy_bytecode_path_status = _text_behavior._renpy_bytecode_path_status
_safe_cli_text = _text_extraction._safe_cli_text
_tag_validation_text = _text_extraction._tag_validation_text
_umige_ast_enriched_strings = _text_extraction._umige_ast_enriched_strings
_umige_build_extraction_view = _text_extraction._umige_build_extraction_view
_umige_normalize_obfuscated_text = _text_extraction._umige_normalize_obfuscated_text
_global_raw_pe_api_header = _text_global_raw_pe_api_header
_global_raw_read_range_text = _text_global_raw_read_range_text
_global_raw_read_range_text_result = _text_global_raw_read_range_text_result
_global_raw_renpy_chunk = _text_global_raw_renpy_chunk
_global_raw_rpgm_js_ast_chunk = _text_global_raw_rpgm_js_ast_chunk
_global_raw_should_context_scan = _text_global_raw_should_context_scan
_intrastage_contextual_chunk_raw = _text_intrastage_contextual_chunk_raw
global_raw_pe_api_header = _text_public_global_raw_pe_api_header
global_raw_renpy_chunk = _text_public_global_raw_renpy_chunk
global_raw_rpgm_js_ast_chunk = _text_public_global_raw_rpgm_js_ast_chunk

infer_correlation_group = _text_infer_correlation_group
library_baseline_hard_proof_status = _text_library_baseline_hard_proof_status
library_baseline_has_hard_proof = _text_library_baseline_has_hard_proof
reference_url_only_score_cap = _text_reference_url_only_score_cap
validate_high_risk_tag = _text_validate_high_risk_tag


__all__ = (
    'BROAD_UNVALIDATED_TAGS',
    'TextGraphEnrichmentRequest',
    'COMBINED_CONTEXT_MAX_BONUS',
    'VECTOR_CLUSTER_MAX_BONUS',
    'api_ngrams',
    'api_to_timeline_tag',
    'build_api_regex',
    'build_api_sequence',
    'build_behavior_timeline',
    'enrich_with_api_and_graph',
    'extract_api_calls',
    'extract_api_sequence_from_blob',
    'gate_spyware_collection_chains',
    'global_raw_pe_api_header',
    'global_raw_renpy_chunk',
    'global_raw_rpgm_js_ast_chunk',
    'infer_correlation_group',
    'infer_tags_from_api',
    'library_baseline_hard_proof_status',
    'library_baseline_has_hard_proof',
    'map_api_to_group',
    'primary_behavior_for_tag',
    'reference_url_only_score_cap',
    'safe_decode_payloads',
    'validate_high_risk_tag',
)
