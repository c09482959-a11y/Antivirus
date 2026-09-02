"""Canonical deterministic static-relation index for Chain evaluation.

The static-program-analysis contracts remain the sole owners of operation and
flow truth.  This module only indexes those immutable facts for the canonical
Chain matcher; it does not infer new observations and it has no model/context
inputs.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.chain_evidence import (
    ChainEvent,
    MatchedChainStep,
    StaticChainRelationConstraint,
)
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_CONTROL_FLOW_EDGE_KINDS,
    STATIC_DATA_FLOW_EDGE_KINDS,
    StaticFlowEdge,
    StaticOperation,
    StaticProgramAnalysis,
)

STATIC_CHAIN_RELATION_INDEX_VERSION = "stage2636_11020_static_chain_relation_index_v1"


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()


def _analyses(value: object) -> tuple[StaticProgramAnalysis, ...]:
    if value is None:
        return ()
    if type(value) is StaticProgramAnalysis:
        raw = (value,)
    elif type(value) in (tuple, list):
        raw = tuple(value)
    else:
        raise TypeError("static_chain_analysis_sequence_required")
    if len(raw) > 64 or any(type(item) is not StaticProgramAnalysis for item in raw):
        raise TypeError("static_chain_analysis_sequence_invalid")
    return tuple(sorted(raw, key=lambda item: (item.artifact_identity, item.semantic_digest)))


@dataclass(frozen=True, slots=True)
class StaticChainRelationIndex:
    """One immutable lookup over exact static operation/flow facts."""

    analyses: tuple[StaticProgramAnalysis, ...]
    digest: str
    operation_by_key: Mapping[tuple[str, str], StaticOperation]
    analysis_by_operation_key: Mapping[tuple[str, str], StaticProgramAnalysis]
    ambiguous_operation_keys: frozenset[tuple[str, str]]

    def operation_for_event(
        self, event: ChainEvent,
    ) -> tuple[StaticProgramAnalysis, StaticOperation] | None:
        if type(event) is not ChainEvent:
            return None
        operation_id = event.source_location.event_id
        artifact_identity = event.artifact_identity
        if (
            event.source_location.location_type != "static_operation"
            or not operation_id.startswith("sop_")
            or not artifact_identity
        ):
            return None
        key = (artifact_identity, operation_id)
        if key in self.ambiguous_operation_keys:
            return None
        operation = self.operation_by_key.get(key)
        analysis = self.analysis_by_operation_key.get(key)
        if type(operation) is not StaticOperation or type(analysis) is not StaticProgramAnalysis:
            return None
        return analysis, operation

    def dependency_digest(self, has_static_relations: bool) -> str:
        return self.digest if has_static_relations else _digest(())


def build_static_chain_relation_index(value: object = None) -> StaticChainRelationIndex:
    analyses = _analyses(value)
    operations: dict[tuple[str, str], StaticOperation] = {}
    owners: dict[tuple[str, str], StaticProgramAnalysis] = {}
    ambiguous: set[tuple[str, str]] = set()
    for analysis in analyses:
        for operation in analysis.operations:
            key = (analysis.artifact_identity, operation.operation_id)
            prior = operations.get(key)
            if prior is not None and prior != operation:
                ambiguous.add(key)
                operations.pop(key, None)
                owners.pop(key, None)
                continue
            if key not in ambiguous:
                operations[key] = operation
                owners[key] = analysis
    record = {
        "version": STATIC_CHAIN_RELATION_INDEX_VERSION,
        "analyses": tuple(
            {
                "artifact_identity": item.artifact_identity,
                "semantic_digest": item.semantic_digest,
                "operations": tuple(operation.to_record() for operation in item.operations),
                "flow_edges": tuple(edge.to_record() for edge in item.flow_edges),
            }
            for item in analyses
        ),
        "ambiguous_operation_keys": tuple(sorted(ambiguous)),
    }
    return StaticChainRelationIndex(
        analyses=analyses,
        digest=_digest(record),
        operation_by_key=MappingProxyType(dict(sorted(operations.items()))),
        analysis_by_operation_key=MappingProxyType(dict(sorted(owners.items()))),
        ambiguous_operation_keys=frozenset(ambiguous),
    )


def _control_path_exists(
    analysis: StaticProgramAnalysis,
    source: StaticOperation,
    target: StaticOperation,
    constraint: StaticChainRelationConstraint,
) -> bool:
    allowed_kinds = (
        frozenset(constraint.allowed_control_edge_kinds)
        if constraint.allowed_control_edge_kinds
        else STATIC_CONTROL_FLOW_EDGE_KINDS
    )
    allowed_resolution = frozenset(constraint.relation_resolution_states)
    adjacency: dict[str, set[str]] = {}
    for edge in analysis.flow_edges:
        if (
            edge.edge_kind not in allowed_kinds
            or edge.resolution_state not in allowed_resolution
            or edge.integrity_status == "unavailable"
            or not edge.source_operation_id
            or not edge.target_operation_id
        ):
            continue
        adjacency.setdefault(edge.source_operation_id, set()).add(edge.target_operation_id)
    queue = deque((source.operation_id,))
    seen = {source.operation_id}
    while queue:
        current = queue.popleft()
        for successor in sorted(adjacency.get(current, ())):
            if successor == target.operation_id:
                return True
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)
    return False


def _data_flow_path_exists(
    analysis: StaticProgramAnalysis,
    source: StaticOperation,
    target: StaticOperation,
    constraint: StaticChainRelationConstraint,
) -> bool:
    allowed_kinds = (
        frozenset(constraint.allowed_data_edge_kinds)
        if constraint.allowed_data_edge_kinds
        else STATIC_DATA_FLOW_EDGE_KINDS
    )
    allowed_resolution = frozenset(constraint.relation_resolution_states)
    target_values = frozenset(target.input_value_ids)
    if not source.output_value_ids or not target_values:
        return False
    adjacency: dict[str, set[str]] = {}
    direct_targets: dict[str, set[str]] = {}
    for edge in analysis.flow_edges:
        if (
            edge.edge_kind not in allowed_kinds
            or edge.resolution_state not in allowed_resolution
            or edge.integrity_status == "unavailable"
            or not edge.source_value_id
            or not edge.target_value_id
        ):
            continue
        adjacency.setdefault(edge.source_value_id, set()).add(edge.target_value_id)
        if edge.target_operation_id:
            direct_targets.setdefault(edge.source_value_id, set()).add(edge.target_operation_id)
    # A shared value identity is not itself evidence of a data-flow path.
    # `require_same_value` owns that separate invariant.  A data-flow path is
    # satisfied only by at least one admitted StaticFlowEdge rooted in the
    # canonical static analysis.
    queue = deque(sorted(source.output_value_ids))
    seen = set(source.output_value_ids)
    while queue:
        current = queue.popleft()
        if target.operation_id in direct_targets.get(current, ()):
            return True
        for successor in sorted(adjacency.get(current, ())):
            if successor in target_values:
                return True
            if successor not in seen:
                seen.add(successor)
                queue.append(successor)
    return False


def _relation_applies(matched: tuple[MatchedChainStep, ...]) -> bool:
    return any(
        item.event.modality in {"static_control_flow", "static_structure"}
        or item.event.source_location.location_type == "static_operation"
        for item in matched
    )


def static_relation_failures(
    constraint: StaticChainRelationConstraint,
    matched: tuple[MatchedChainStep, ...],
    relation_index: StaticChainRelationIndex | None,
    *,
    relation_ordinal: int,
) -> tuple[str, ...]:
    """Return deterministic unmet-requirement names for one static relation."""
    if not _relation_applies(matched):
        return ()
    prefix = "static_relation:" + str(relation_ordinal) + ":"
    by_step = {item.step_index: item.event for item in matched}
    source_event = by_step.get(constraint.source_step_index)
    target_event = by_step.get(constraint.target_step_index)
    if source_event is None or target_event is None:
        return (prefix + "step_unavailable",)
    if relation_index is None:
        return (prefix + "analysis_unavailable",)
    source_owned = relation_index.operation_for_event(source_event)
    target_owned = relation_index.operation_for_event(target_event)
    if source_owned is None or target_owned is None:
        return (prefix + "operation_unavailable",)
    source_analysis, source = source_owned
    target_analysis, target = target_owned
    if (
        source_analysis.semantic_digest != target_analysis.semantic_digest
        or source_analysis.artifact_identity != target_analysis.artifact_identity
    ):
        return (prefix + "analysis_mismatch",)

    failures: set[str] = set()
    if constraint.source_reachability_states and source.reachability_state not in constraint.source_reachability_states:
        failures.add(prefix + "source_reachability_unsatisfied")
    if constraint.target_reachability_states and target.reachability_state not in constraint.target_reachability_states:
        failures.add(prefix + "target_reachability_unsatisfied")
    if constraint.source_resolution_states and source.resolution_state not in constraint.source_resolution_states:
        failures.add(prefix + "source_resolution_unsatisfied")
    if constraint.target_resolution_states and target.resolution_state not in constraint.target_resolution_states:
        failures.add(prefix + "target_resolution_unsatisfied")
    if constraint.same_program_entity:
        if not source.actor_program_entity or not target.actor_program_entity:
            failures.add(prefix + "program_entity_unavailable")
        elif source.actor_program_entity != target.actor_program_entity:
            failures.add(prefix + "program_entity_mismatch")
    if constraint.same_resource:
        if not source.target_resource_identity or not target.target_resource_identity:
            failures.add(prefix + "resource_unavailable")
        elif source.target_resource_identity != target.target_resource_identity:
            failures.add(prefix + "resource_mismatch")
    if constraint.require_same_value:
        if not (set(source.output_value_ids) & set(target.input_value_ids)):
            failures.add(prefix + "same_value_unsatisfied")
    if constraint.require_control_flow_path and not _control_path_exists(
        source_analysis, source, target, constraint,
    ):
        failures.add(prefix + "control_flow_path_unsatisfied")
    if constraint.require_data_flow_path and not _data_flow_path_exists(
        source_analysis, source, target, constraint,
    ):
        failures.add(prefix + "data_flow_path_unsatisfied")
    return tuple(sorted(failures))


def static_rule_relation_failures(
    constraints: tuple[StaticChainRelationConstraint, ...],
    matched: tuple[MatchedChainStep, ...],
    relation_index: StaticChainRelationIndex | None,
) -> tuple[str, ...]:
    failures = {
        failure
        for ordinal, constraint in enumerate(constraints)
        for failure in static_relation_failures(
            constraint, matched, relation_index, relation_ordinal=ordinal,
        )
    }
    return tuple(sorted(failures))


__all__ = (
    "STATIC_CHAIN_RELATION_INDEX_VERSION",
    "StaticChainRelationIndex",
    "build_static_chain_relation_index",
    "static_relation_failures",
    "static_rule_relation_failures",
)
