"""Canonical tag expected-behavior mapping owned by detection/tags/heuristics.

This module owns semantic tag interpretation for audit/explainability contracts.
It intentionally depends on bounded tag policy registries instead of importing
score orchestration, so chain imports remain statically acyclic.
"""

from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.tags.heuristics.normalization_runtime import (
    canonical_tag_name,
    normalize_tag_evidence,
)
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float, no_hook_mapping_items, no_hook_text

from Virus_Scan.detection.registries.chain_registry import CHAIN_CONCLUSION_TAGS

TAG_BEHAVIOR_SCOREABLE = frozenset(detection_registry_value("TAG_BEHAVIOR_SCOREABLE", {
    "process_exec", "script_execution", "dynamic_execution", "powershell_exec", "encoded_powershell",
    "cmd_exec", "network_download", "remote_payload_download", "http_upload", "network_exfiltration",
    "token_exfiltration", "network_c2", "backdoor_or_c2", "remote_command_channel",
    "scheduled_task", "registry_persistence", "startup_persistence", "service_create",
    "credential_dump_attempt", "token_secret_access", "memory_write", "write_process_memory",
    "remote_thread_create", "create_remote_thread", "defender_disable",
    "amsi_bypass_attempt", "etw_bypass_attempt", "encoded_payload",
    "embedded_pe_payload",
    "confirmed_embedded_pe_payload", "decoded_pe_payload", "image_payload_confirmed", "archive_dropper",
    "dropper_behavior", "embedded_archive_payload", "macro_office", "office_macro_execution",
    "keylogging_behavior", "input_capture",
}))
TAG_BEHAVIOR_SCOREABLE = TAG_BEHAVIOR_SCOREABLE - CHAIN_CONCLUSION_TAGS
TAG_STRUCTURAL_ONLY = frozenset(detection_registry_value("TAG_STRUCTURAL_ONLY", {
    "extension_mismatch", "asset_extension_magic_mismatch", "extension_magic_type_mismatch",
    "filetype_misclassification", "asset_deep_scan_escalated", "embedded_command_or_url",
    "embedded_pe_signature", "possible_appended_payload", "packer_marker", "packed_or_obfuscated",
    "engine_runtime_library", "runtime_library", "python_runtime_binary", "python_runtime_library",
    "renpy_runtime_library",
}))
TAG_WEAK_CONTEXT_ONLY = frozenset(detection_registry_value("TAG_WEAK_CONTEXT_ONLY", {
    "url_present", "network_url", "asset_resource_fetch", "browser_xhr_fetch", "network_activity",
    "reference_url", "encoded_data_context", "payload_decode_candidate", "encoded_payload_candidate",
    "decoded_payload_observed", "decoded_base64_blob", "compressed_payload_candidate", "high_entropy_packed",
    "very_high_entropy", "renpy", "rpgm", "unity_engine", "unity_asset", "managed_dotnet",
    "node_runtime", "nwjs", "pickle_deserialization_context", "pickle_fast_text_hint",
    "python_bytecode_or_script",
}))
SUPPORT_ONLY_SCORE_TAGS = frozenset(detection_registry_value("SUPPORT_ONLY_SCORE_TAGS", TAG_WEAK_CONTEXT_ONLY | TAG_STRUCTURAL_ONLY))
SUPPORT_ONLY_SCORE_TAGS = SUPPORT_ONLY_SCORE_TAGS - CHAIN_CONCLUSION_TAGS
CONCRETE_SCORE_TAGS = frozenset(detection_registry_value("CONCRETE_SCORE_TAGS", TAG_BEHAVIOR_SCOREABLE)) - CHAIN_CONCLUSION_TAGS
HIGH_RISK_BUCKETS = frozenset(detection_registry_value("HIGH_RISK_BUCKETS", {"os_execution", "credential", "persistence", "injection", "evasion"}))
TAG_ROLE_EXPECTED_BEHAVIOR = detection_registry_value("TAG_ROLE_EXPECTED_BEHAVIOR", {
    "weak_context": "report only; can support chains but cannot score alone",
    "structural": "file/container/runtime structure; can explain why deep scan happened but cannot score alone",
    "behavior": "concrete action/API/command; may score with confidence and rarity gates",
    "chain_projection": "publication-only conclusion; canonical ChainEvidence owns scoring and floors",
    "unknown": "reported for audit, but treated as support-only until mapped",
})


def behavior_mapping_text(value: object) -> object:
    text, reason = no_hook_text(
        value,
        missing_reason="behavior_mapping_text_missing",
        unsupported_reason="behavior_mapping_text_rejected",
    )
    if reason:
        return ""
    return text.strip().lower()


def behavior_mapping_score(tag: object) -> object:
    items = no_hook_mapping_items(detection_registry_value("TAG_RISK_SCORES", {}))
    if items is None:
        return 0.0
    for key, value in items:
        if type(key) is str and key == tag:
            score, _reason = no_hook_finite_float(
                value,
                default=0.0,
                reason="behavior_mapping_score_rejected",
                non_finite_reason="behavior_mapping_score_non_finite",
                allow_exact_text=True,
            )
            return score
    return 0.0



def _behavior_role_from_bucket(tag_text: str) -> str:
    bucket = tag_behavior_bucket(tag_text)
    if bucket in HIGH_RISK_BUCKETS and tag_text not in SUPPORT_ONLY_SCORE_TAGS:
        return "behavior"
    if bucket != "other_behavior":
        return "weak_context" if tag_text in SUPPORT_ONLY_SCORE_TAGS else "behavior"
    return "unknown"



def tag_expected_behavior_class(tag: object) -> object:
    tag_text = behavior_mapping_text(tag)
    if tag_text in CHAIN_CONCLUSION_TAGS:
        role = "chain_projection"
    elif tag_text in TAG_BEHAVIOR_SCOREABLE or tag_text in CONCRETE_SCORE_TAGS:
        role = "behavior"
    elif tag_text in TAG_STRUCTURAL_ONLY:
        role = "structural"
    elif tag_text in TAG_WEAK_CONTEXT_ONLY or tag_text in SUPPORT_ONLY_SCORE_TAGS:
        role = "weak_context"
    else:
        role = _behavior_role_from_bucket(tag_text)
    return role


def tag_expected_behavior_record(record: object) -> object:
    """Project expected behavior from the canonical evidence owner."""
    if type(record) is TagEvidenceRecord:
        tag_text = record.canonical_tag_id
        evidence = record
    else:
        tag_text = canonical_tag_name(behavior_mapping_text(record))
        evidence = None
    role = tag_expected_behavior_class(tag_text)
    bucket = evidence.behavior_bucket if evidence is not None else tag_behavior_bucket(tag_text)
    score = behavior_mapping_score(tag_text)
    mapping = {
        "tag": tag_text,
        "role": role,
        "bucket": bucket,
        "score_policy": TAG_ROLE_EXPECTED_BEHAVIOR.get(role, TAG_ROLE_EXPECTED_BEHAVIOR["unknown"]),
        "risk_score": score,
        "timeline_use": role == "behavior",
        "chain_use": role == "behavior" or bucket in {"network", "entropy_or_packing", "renpy_script_logic"},
        "scoreable_without_chain": role == "behavior",
    }
    if evidence is not None:
        mapping.update({
            "evidence_id": evidence.evidence_id,
            "root_observation_id": evidence.root_observation_id,
            "evidence_kind": evidence.evidence_kind,
            "correlation_group": evidence.correlation_group,
            "attack_phase": evidence.attack_phase,
            "polarity": evidence.polarity,
            "scoreability_class": evidence.scoreability_class,
        })
    return mapping


def tag_expected_behavior_mapping(tag: object) -> object:
    """Public projection generated from one canonical evidence record."""
    text = behavior_mapping_text(tag)
    if not text:
        return tag_expected_behavior_record("")
    bundle = normalize_tag_evidence(
        (text,), source_detector="behavior_mapping", source_stage="expected_behavior",
        derive=False,
    )
    record = next((
        value for value in bundle.records
        if value.evidence_kind in {"normalized", "observed"}
    ), None)
    return tag_expected_behavior_record(record if record is not None else text)


__all__ = (
    "tag_expected_behavior_class",
    "tag_expected_behavior_mapping",
    "tag_expected_behavior_record",
)
