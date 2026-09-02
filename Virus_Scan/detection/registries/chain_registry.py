"""Validated immutable owner for all chain and explicit-anchor policy."""

from __future__ import annotations

import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.chain_evidence import ChainRule, ChainStep, StaticChainRelationConstraint
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.detection.registries.chain_registry_defaults import (
    CHAIN_CONCLUSION_TAGS,
    CHAIN_FAMILY_ATTACK_PHASES as _CHAIN_FAMILY_ATTACK_PHASES,
    CHAIN_REGISTRY_VERSION,
    CHAIN_ROLE_EXPECTED_BEHAVIOR as _CHAIN_ROLE_EXPECTED_BEHAVIOR,
    CHAIN_RULE_DEFINITIONS,
    CHAIN_RULE_MIGRATION_MANIFEST,
)
from Virus_Scan.detection.registries.context import detection_registry_value


_SAFE_TERM = re.compile(r"^[a-z0-9_.:/() -]{1,128}$")


def _mapping(value: object) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise ValueError("chain_registry_mapping_required")
    return {key: item for key, item in items if type(key) is str}


def _sequence(value: object, *, limit: int = 512) -> tuple[object, ...]:
    if type(value) not in (tuple, list):
        raise ValueError("chain_registry_sequence_required")
    return tuple(value)[:limit]


def _step_from_value(value: object) -> ChainStep:
    data = _mapping(value)
    alternatives = _sequence(data.get("alternatives", ()), limit=32)
    return ChainStep(
        alternatives=tuple(item for item in alternatives if type(item) is str),
        optional=data.get("optional") is True,
        max_gap=data.get("max_gap") if type(data.get("max_gap")) is int else None,
    )


def _static_relation_from_value(value: object) -> StaticChainRelationConstraint:
    data = _mapping(value)
    control_kinds = _sequence(data.get("allowed_control_edge_kinds", ()), limit=32)
    data_kinds = _sequence(data.get("allowed_data_edge_kinds", ()), limit=32)
    source_reachability = _sequence(data.get("source_reachability_states", ()), limit=16)
    target_reachability = _sequence(data.get("target_reachability_states", ()), limit=16)
    source_resolution = _sequence(data.get("source_resolution_states", ()), limit=16)
    target_resolution = _sequence(data.get("target_resolution_states", ()), limit=16)
    relation_resolution = _sequence(data.get("relation_resolution_states", ("resolved",)), limit=16)
    return StaticChainRelationConstraint(
        source_step_index=data.get("source_step_index", -1),
        target_step_index=data.get("target_step_index", -1),
        require_control_flow_path=data.get("require_control_flow_path") is True,
        allowed_control_edge_kinds=tuple(item for item in control_kinds if type(item) is str),
        require_data_flow_path=data.get("require_data_flow_path") is True,
        allowed_data_edge_kinds=tuple(item for item in data_kinds if type(item) is str),
        require_same_value=data.get("require_same_value") is True,
        same_program_entity=data.get("same_program_entity") is True,
        same_resource=data.get("same_resource") is True,
        source_reachability_states=tuple(item for item in source_reachability if type(item) is str),
        target_reachability_states=tuple(item for item in target_reachability if type(item) is str),
        source_resolution_states=tuple(item for item in source_resolution if type(item) is str),
        target_resolution_states=tuple(item for item in target_resolution if type(item) is str),
        relation_resolution_states=tuple(item for item in relation_resolution if type(item) is str),
    )


def _rule_from_value(value: object) -> ChainRule:
    data = _mapping(value)
    steps = tuple(_step_from_value(item) for item in _sequence(data.get("steps", ()), limit=32))
    optional = _sequence(data.get("optional_evidence", ()), limit=64)
    forbidden = _sequence(data.get("forbidden_evidence", ()), limit=64)
    required_platforms = _sequence(data.get("required_platforms", ()), limit=32)
    required_modalities = _sequence(data.get("required_modalities", ()), limit=16)
    required_fields = _sequence(data.get("required_fields", ()), limit=32)
    static_relations = tuple(
        _static_relation_from_value(item)
        for item in _sequence(data.get("static_relations", ()), limit=32)
    )
    return ChainRule(
        chain_id=data.get("chain_id", ""),
        version=data.get("version", ""),
        family=data.get("family", ""),
        match_mode=data.get("match_mode", ""),
        steps=steps,
        minimum_distinct_roots=data.get("minimum_distinct_roots", 1),
        confidence=data.get("confidence", 0.0),
        operational_severity=data.get("operational_severity", 0.0),
        score_points=data.get("score_points", 0.0),
        anchor_floor=data.get("anchor_floor", 0.0),
        optional_evidence=tuple(item for item in optional if type(item) is str),
        forbidden_evidence=tuple(item for item in forbidden if type(item) is str),
        maximum_time_gap=data.get("maximum_time_gap"),
        same_actor=data.get("same_actor", False),
        same_target=data.get("same_target", False),
        same_artifact=data.get("same_artifact", False),
        same_host=data.get("same_host", False),
        same_process=data.get("same_process", False),
        same_connection=data.get("same_connection", False),
        platform_match=data.get("platform_match", False),
        required_platforms=tuple(item for item in required_platforms if type(item) is str),
        required_modalities=tuple(item for item in required_modalities if type(item) is str),
        minimum_direct_observations=data.get("minimum_direct_observations", 0),
        required_fields=tuple(item for item in required_fields if type(item) is str),
        static_relations=static_relations,
        correlation_group=data.get("correlation_group", ""),
        scoreable=data.get("scoreable") is True,
        rationale=data.get("rationale", ""),
    )


def _validate_rule_terms(rule: ChainRule) -> None:
    if rule.version != CHAIN_REGISTRY_VERSION:
        raise ValueError("chain_rule_version_mismatch:" + rule.chain_id)
    optional_count = sum(step.optional for step in rule.steps)
    if optional_count > 8:
        raise ValueError("chain_rule_optional_branch_limit:" + rule.chain_id)
    for step in rule.steps:
        for term in step.alternatives:
            if not _SAFE_TERM.fullmatch(term):
                raise ValueError("chain_rule_term_invalid:" + rule.chain_id + ":" + term)
            if term == rule.chain_id:
                raise ValueError("chain_rule_self_reference:" + rule.chain_id)


def _reference_graph(rules: tuple[ChainRule, ...]) -> dict[str, frozenset[str]]:
    rule_ids = frozenset(rule.chain_id for rule in rules)
    graph: dict[str, frozenset[str]] = {}
    for rule in rules:
        references = {
            term
            for step in rule.steps
            for term in step.alternatives
            if term in rule_ids
        }
        graph[rule.chain_id] = frozenset(references)
    return graph


def _validate_acyclic(rules: tuple[ChainRule, ...]) -> None:
    graph = _reference_graph(rules)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            raise ValueError("chain_registry_cycle:" + node)
        if node in visited:
            return
        visiting.add(node)
        for target in sorted(graph[node]):
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for rule_id in sorted(graph):
        visit(rule_id)


def validate_chain_rules(values: object) -> tuple[ChainRule, ...]:
    """Materialize and reject malformed, duplicate, cyclic, or drifting rules."""
    rules = tuple(_rule_from_value(item) for item in _sequence(values, limit=512))
    if not rules:
        raise ValueError("chain_registry_empty")
    ids = tuple(rule.chain_id for rule in rules)
    if len(ids) != len(set(ids)):
        raise ValueError("chain_registry_duplicate_id")
    for rule in rules:
        _validate_rule_terms(rule)
    _validate_acyclic(rules)
    return tuple(sorted(rules, key=lambda rule: rule.chain_id))


def _registry_payload(rules: tuple[ChainRule, ...]) -> bytes:
    records = tuple(rule.to_record() for rule in rules)
    return json.dumps(records, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


CANONICAL_CHAIN_RULES = validate_chain_rules(CHAIN_RULE_DEFINITIONS)
CHAIN_REGISTRY_DIGEST = hashlib.sha256(_registry_payload(CANONICAL_CHAIN_RULES)).hexdigest()
CHAIN_RULE_INDEX = MappingProxyType({rule.chain_id: rule for rule in CANONICAL_CHAIN_RULES})
CHAIN_ROLE_EXPECTED_BEHAVIOR = MappingProxyType(dict(_CHAIN_ROLE_EXPECTED_BEHAVIOR))
CHAIN_FAMILY_ATTACK_PHASES = MappingProxyType({
    str(family): tuple(phases)
    for family, phases in dict(_CHAIN_FAMILY_ATTACK_PHASES).items()
})


def chain_rules(*, match_modes: frozenset[str] | None = None) -> tuple[ChainRule, ...]:
    if match_modes is None:
        return CANONICAL_CHAIN_RULES
    return tuple(rule for rule in CANONICAL_CHAIN_RULES if rule.match_mode in match_modes)


def chain_rule(chain_id: object) -> ChainRule | None:
    key = str.__str__(chain_id).strip().lower() if type(chain_id) is str else ""
    return CHAIN_RULE_INDEX.get(key)


def chain_registry_manifest() -> dict[str, object]:
    family_counts: dict[str, int] = {}
    mode_counts: dict[str, int] = {}
    scoreable_count = 0
    anchor_floor_count = 0
    for rule in CANONICAL_CHAIN_RULES:
        family_counts[rule.family] = family_counts.get(rule.family, 0) + 1
        mode_counts[rule.match_mode] = mode_counts.get(rule.match_mode, 0) + 1
        scoreable_count += int(rule.scoreable)
        anchor_floor_count += int(rule.anchor_floor > 0.0)
    return {
        "version": CHAIN_REGISTRY_VERSION,
        "digest": CHAIN_REGISTRY_DIGEST,
        "rule_count": len(CANONICAL_CHAIN_RULES),
        "scoreable_rule_count": scoreable_count,
        "anchor_floor_rule_count": anchor_floor_count,
        "family_counts": MappingProxyType(dict(sorted(family_counts.items()))),
        "match_mode_counts": MappingProxyType(dict(sorted(mode_counts.items()))),
        "migration_count": len(CHAIN_RULE_MIGRATION_MANIFEST),
    }


HIGH_CONFIDENCE_ATTACK_ANCHOR_TAGS = frozenset(detection_registry_value("HIGH_CONFIDENCE_ATTACK_ANCHOR_TAGS", ()))
BROAD_UNVALIDATED_TAGS = frozenset(detection_registry_value("BROAD_UNVALIDATED_TAGS", ()))
MAJOR_ATTACK_ANCHOR_TAGS = frozenset(detection_registry_value("MAJOR_ATTACK_ANCHOR_TAGS", ()))
BEHAVIOR_GATED_TAGS = frozenset(detection_registry_value("BEHAVIOR_GATED_TAGS", ()))
REMOTE_PAYLOAD_DOWNLOAD_TERMS = tuple(detection_registry_value("REMOTE_PAYLOAD_DOWNLOAD_TERMS", ()))
REMOTE_PAYLOAD_FILE_TERMS = tuple(detection_registry_value("REMOTE_PAYLOAD_FILE_TERMS", ()))
C2_TASKING_TERMS = tuple(detection_registry_value("C2_TASKING_TERMS", ()))
ARCHIVE_DROPPER_TERMS = tuple(detection_registry_value("ARCHIVE_DROPPER_TERMS", ()))
TAG_WEAK_CONTEXT_ONLY = frozenset(detection_registry_value("TAG_WEAK_CONTEXT_ONLY", ()))
TAG_STRUCTURAL_ONLY = frozenset(detection_registry_value("TAG_STRUCTURAL_ONLY", ()))
TAG_BEHAVIOR_SCOREABLE = frozenset(detection_registry_value("TAG_BEHAVIOR_SCOREABLE", ()))
TAG_RISK_SCORES = MappingProxyType(dict(detection_registry_value("TAG_RISK_SCORES", {})))
CONCRETE_SCORE_TAGS = frozenset(detection_registry_value("CONCRETE_SCORE_TAGS", ()))
SUPPORT_ONLY_SCORE_TAGS = frozenset(detection_registry_value("SUPPORT_ONLY_SCORE_TAGS", ()))
CONTEXTUAL_DANGEROUS_ANCHOR_TAGS = frozenset(detection_registry_value("CONTEXTUAL_DANGEROUS_ANCHOR_TAGS", ()))
HIGH_RISK_BUCKETS = frozenset(detection_registry_value("HIGH_RISK_BUCKETS", ()))
CHAIN_NORMALIZATION_VERSION = str(detection_registry_value("CHAIN_NORMALIZATION_VERSION", ""))
HIGH_GATE_VERSION = str(detection_registry_value("HIGH_GATE_VERSION", ""))
HIGH_GATE_SINGLE_ANCHOR_TAGS = frozenset(detection_registry_value("HIGH_GATE_SINGLE_ANCHOR_TAGS", ()))
HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS = frozenset(detection_registry_value("HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS", ()))
DOTNET_DYNAMIC_LOADER_TAGS = frozenset(detection_registry_value("DOTNET_DYNAMIC_LOADER_TAGS", ()))
DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS = frozenset(detection_registry_value("DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS", ()))
ATTACK_GRAPH = MappingProxyType(dict(detection_registry_value("ATTACK_GRAPH", {})))
API_REGEX = re.compile(detection_registry_value("API_REGEX_PATTERN", r"(?!)"))


__all__ = (
    "API_REGEX", "ARCHIVE_DROPPER_TERMS", "ATTACK_GRAPH", "BEHAVIOR_GATED_TAGS",
    "BROAD_UNVALIDATED_TAGS", "C2_TASKING_TERMS", "CANONICAL_CHAIN_RULES",
    "CHAIN_CONCLUSION_TAGS", "CHAIN_FAMILY_ATTACK_PHASES", "CHAIN_NORMALIZATION_VERSION", "CHAIN_REGISTRY_DIGEST", "CHAIN_REGISTRY_VERSION",
    "CHAIN_ROLE_EXPECTED_BEHAVIOR", "CHAIN_RULE_INDEX", "CHAIN_RULE_MIGRATION_MANIFEST",
    "CONCRETE_SCORE_TAGS", "CONTEXTUAL_DANGEROUS_ANCHOR_TAGS", "DOTNET_DYNAMIC_LOADER_PAYLOAD_TAGS",
    "DOTNET_DYNAMIC_LOADER_TAGS", "HIGH_CONFIDENCE_ATTACK_ANCHOR_TAGS", "HIGH_GATE_SINGLE_ANCHOR_TAGS",
    "HIGH_GATE_VERSION", "HIGH_GATE_WEAK_OR_STRUCTURAL_TAGS", "HIGH_RISK_BUCKETS",
    "MAJOR_ATTACK_ANCHOR_TAGS", "REMOTE_PAYLOAD_DOWNLOAD_TERMS", "REMOTE_PAYLOAD_FILE_TERMS",
    "SUPPORT_ONLY_SCORE_TAGS", "TAG_BEHAVIOR_SCOREABLE",
    "TAG_RISK_SCORES", "TAG_STRUCTURAL_ONLY", "TAG_WEAK_CONTEXT_ONLY",
    "chain_registry_manifest", "chain_rule", "chain_rules", "validate_chain_rules",
)
