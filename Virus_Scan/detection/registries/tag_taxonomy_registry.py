"""Single immutable semantic-class registry for canonical local tags."""
from __future__ import annotations

from types import MappingProxyType

from Virus_Scan.contracts.tag_taxonomy import (
    TAG_CLASS_ANALYTIC_CANDIDATE,
    TAG_CLASS_ATOMIC_OBSERVATION,
    TAG_CLASS_BEHAVIOR_DERIVATION,
    TAG_CLASS_CONTEXT,
    TAG_CLASS_REPORTING_ONLY,
    TAG_CLASS_UNAVAILABLE,
    TAG_CONTEXT_ONLY_MODALITIES,
    TAG_TAXONOMY_VERSION,
    TagDefinition,
    tag_definition_digest,
)
from Virus_Scan.contracts.tag_vocabulary import DEFAULT_CANONICAL_TAG_ALIASES
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_OPERATION_EXACT_TAG_IDS,
    STATIC_OPERATION_KINDS,
    static_operation_observation_tag,
)
from Virus_Scan.detection.registries.chain_gate_registry_defaults import (
    CONCRETE_SCORE_TAGS,
    TAG_STRUCTURAL_ONLY,
    TAG_WEAK_CONTEXT_ONLY,
)
from Virus_Scan.detection.registries.chain_registry_defaults import (
    CHAIN_CONCLUSION_TAGS,
    CHAIN_RULE_DEFINITIONS,
)
from Virus_Scan.detection.registries.tag_behavior.vocabulary_graph import (
    tag_derivation_manifest,
)
from Virus_Scan.detection.registries.tag_behavior_registry_defaults import (
    TAG_TO_BEHAVIOR,
)

_REPORTING_ONLY = frozenset({
    "bytecode_execution", "credential_dumping", "data_exfiltration",
    "disable_security_tools", "download_execute", "encoded_script",
    "ingress_tool_transfer", "powershell", "remote_service",
})
_BEHAVIOR_DERIVATIONS = frozenset({
    "backdoor_or_c2", "collection", "credential_access", "defense_evasion",
    "dropper_behavior", "exfiltration", "fileless_execution",
    "high_confidence_browser_credential_theft",
    "high_confidence_credential_theft", "high_confidence_delay_encoded_loader",
    "in_memory_execution", "lateral_movement", "network_activity",
    "network_download_execute", "network_exfiltration",
    "payload_decode", "payload_execution", "persistence", "process_exec",
    "process_injection", "ransomware_behavior", "registry_mod",
    "remote_execution", "scheduled_execution", "script_execution",
    "shellcode_exec", "token_exfiltration", "c2_or_remote_command",
})
_EXPLICIT_ATOMIC_OBSERVATIONS = frozenset({
    "bytecode_socket", "bytecode_subprocess", "clr_runtime_present",
    "credential_memory_access", "dotnet", "dotnet_obfuscated_or_packed",
    "dotnet_pe", "dotnet_x64", "firewall_rule_change", "known_bad_hash",
    "payload_decode_confirmed", "rpa_automation_execution",
    "rpa_opcode_exec", "rpa_opcode_execution", "rpa_pickle_usage",
    "vssadmin_delete", "wbadmin_delete", "yara_malware",
})
_EXPLICIT_CONTEXT_TAGS = frozenset({
    "malware_family", "obfuscated_script",
})
_STATIC_OPERATION_TAGS = frozenset({
    *(static_operation_observation_tag(kind) for kind in STATIC_OPERATION_KINDS),
    *STATIC_OPERATION_EXACT_TAG_IDS,
})
_UNAVAILABLE = frozenset({
    "detection_observation_unavailable", "detection_stage_degraded",
    "result_contract_violation", "scan_incomplete", "scanner_degraded",
    "tag_evidence_unavailable", "tag_normalization_failure",
})

_CHAIN_CONTEXT_TERMS = frozenset({
    "cmd", "code_execution", "command_execution", "contextual_learning_blocked",
    "create", "cross_engine_artifact", "decode", "delete", "download",
    "embedded_payload", "engine_mismatch", "failure", "high_confidence_malware",
    "known_malware_family", "malware_metadata_category",
    "malwarebazaar_known_family", "pe_file", "polyglot_artifact",
    "runtime_library_suppression", "save", "suppression",
})


def _chain_leaf_terms() -> frozenset[str]:
    rule_ids = frozenset(str(rule["chain_id"]) for rule in CHAIN_RULE_DEFINITIONS)
    terms: set[str] = set()
    for rule in CHAIN_RULE_DEFINITIONS:
        for step in rule["steps"]:
            terms.update(str(term) for term in step["alternatives"])
        terms.update(str(term) for term in rule["optional_evidence"])
        terms.update(str(term) for term in rule["forbidden_evidence"])
    return frozenset(terms.difference(rule_ids))


_CHAIN_LEAF_TERMS = _chain_leaf_terms()


def _derivation_tags() -> tuple[set[str], set[str]]:
    sources: set[str] = set()
    targets: set[str] = set()
    for row in tag_derivation_manifest()["rules"]:
        sources.add(row[0])
        targets.add(row[1])
    return sources, targets


def _known_canonical_tags() -> tuple[str, ...]:
    sources, targets = _derivation_tags()
    aliases = set(DEFAULT_CANONICAL_TAG_ALIASES.values())
    known = (
        set(TAG_TO_BEHAVIOR) | set(CONCRETE_SCORE_TAGS)
        | set(TAG_WEAK_CONTEXT_ONLY) | set(TAG_STRUCTURAL_ONLY)
        | set(CHAIN_CONCLUSION_TAGS) | set(_CHAIN_LEAF_TERMS) | sources | targets | aliases
        | set(_REPORTING_ONLY) | set(_BEHAVIOR_DERIVATIONS) | set(_UNAVAILABLE)
        | set(_STATIC_OPERATION_TAGS) | set(_EXPLICIT_ATOMIC_OBSERVATIONS)
        | set(_EXPLICIT_CONTEXT_TAGS)
    )
    return tuple(sorted(known))


def _tag_class(tag_id: str) -> str:
    if tag_id in _UNAVAILABLE:
        return TAG_CLASS_UNAVAILABLE
    if (tag_id in TAG_WEAK_CONTEXT_ONLY or tag_id in TAG_STRUCTURAL_ONLY
            or tag_id in _CHAIN_CONTEXT_TERMS or tag_id in _EXPLICIT_CONTEXT_TAGS):
        return TAG_CLASS_CONTEXT
    if tag_id in CHAIN_CONCLUSION_TAGS:
        return TAG_CLASS_ANALYTIC_CANDIDATE
    if tag_id in _REPORTING_ONLY:
        return TAG_CLASS_REPORTING_ONLY
    if tag_id in _BEHAVIOR_DERIVATIONS:
        return TAG_CLASS_BEHAVIOR_DERIVATION
    if tag_id in _STATIC_OPERATION_TAGS or tag_id in _EXPLICIT_ATOMIC_OBSERVATIONS:
        return TAG_CLASS_ATOMIC_OBSERVATION
    if tag_id in CONCRETE_SCORE_TAGS or tag_id in _CHAIN_LEAF_TERMS:
        return TAG_CLASS_ATOMIC_OBSERVATION
    _sources, targets = _derivation_tags()
    if tag_id in targets:
        return TAG_CLASS_BEHAVIOR_DERIVATION
    return TAG_CLASS_REPORTING_ONLY


TAG_DEFINITIONS = tuple(
    TagDefinition(tag_id, _tag_class(tag_id)) for tag_id in _known_canonical_tags()
)
TAG_DEFINITION_BY_ID = MappingProxyType({
    definition.tag_id: definition for definition in TAG_DEFINITIONS
})
TAG_TAXONOMY_DIGEST = tag_definition_digest(TAG_DEFINITIONS)
ATOMIC_OBSERVATION_TAG_IDS = frozenset(
    item.tag_id for item in TAG_DEFINITIONS
    if item.tag_class == TAG_CLASS_ATOMIC_OBSERVATION
)


def tag_definition(tag_id: object) -> TagDefinition | None:
    if type(tag_id) is not str:
        return None
    return TAG_DEFINITION_BY_ID.get(str.__str__(tag_id))


def tag_class_for(tag_id: object) -> str:
    definition = tag_definition(tag_id)
    return "" if definition is None else definition.tag_class


def tag_taxonomy_manifest() -> dict[str, object]:
    counts = {
        tag_class: sum(item.tag_class == tag_class for item in TAG_DEFINITIONS)
        for tag_class in sorted({item.tag_class for item in TAG_DEFINITIONS})
    }
    return {
        "version": TAG_TAXONOMY_VERSION,
        "digest": TAG_TAXONOMY_DIGEST,
        "definition_count": len(TAG_DEFINITIONS),
        "class_counts": counts,
        "context_only_modalities": tuple(sorted(TAG_CONTEXT_ONLY_MODALITIES)),
        "definitions": tuple(item.to_record() for item in TAG_DEFINITIONS),
    }


__all__ = (
    "ATOMIC_OBSERVATION_TAG_IDS", "TAG_DEFINITIONS", "TAG_DEFINITION_BY_ID",
    "TAG_TAXONOMY_DIGEST", "tag_class_for", "tag_definition",
    "tag_taxonomy_manifest",
)
