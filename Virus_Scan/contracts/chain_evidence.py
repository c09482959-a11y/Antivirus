"""Immutable canonical contracts for chain rules, matches, and publication."""

from __future__ import annotations

from dataclasses import dataclass, field
from math import isfinite
from types import MappingProxyType
from typing import Mapping

from Virus_Scan.contracts.detection_observation import ObservationSourceLocation
from Virus_Scan.contracts.static_program_analysis import (
    STATIC_CONTROL_FLOW_EDGE_KINDS,
    STATIC_DATA_FLOW_EDGE_KINDS,
    STATIC_REACHABILITY_STATES,
    STATIC_RESOLUTION_STATES,
)


CHAIN_EVIDENCE_SCHEMA_VERSION = "stage2636_11020_chain_evidence_v7"
CHAIN_EVIDENCE_GENERATION_SCHEMA_VERSION = "stage2636_11020_chain_evidence_generation_v4"
CHAIN_PHYSICAL_EVENT_SOURCES = frozenset({
    "tag_evidence",
    "timeline_observation",
    "api_observation",
})
CHAIN_ORDER_CLASSES = frozenset({
    "observed_order",
    "causal_link",
    "static_control_flow",
    "synthetic_order",
    "unordered_correlation",
    "partial",
})
CHAIN_DECISION_STATUSES = frozenset({"confirmed", "candidate", "partial", "blocked", "rejected"})
CHAIN_MATCH_MODES = frozenset({"ordered", "anchor", "unordered"})
CHAIN_CORRELATION_FIELDS = frozenset({
    "actor_identity", "target_identity", "artifact_identity", "process_identity",
    "host_identity", "connection_identity", "platform", "modality",
    "observation_id", "source_location", "timestamp", "timing_provenance",
    "integrity_status", "directness",
})


def _text(value: object) -> str:
    return str.__str__(value).strip().lower() if type(value) is str else ""


def _text_tuple(value: object, *, limit: int = 128) -> tuple[str, ...]:
    if type(value) not in (tuple, list, set, frozenset):
        return ()
    items: list[str] = []
    iterable = tuple(value) if type(value) in (tuple, list) else tuple(sorted(value))
    for raw in iterable[:limit]:
        text = _text(raw)
        if text and text not in items:
            items.append(text)
    return tuple(items)


def _bounded_float(value: object, *, minimum: float = 0.0, maximum: float = 1.0) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        return minimum
    numeric = float(value)
    if not isfinite(numeric):
        return minimum
    return max(minimum, min(maximum, numeric))


def _bounded_int(value: object, *, minimum: int = 0, maximum: int = 1_000_000) -> int:
    if type(value) is not int or type(value) is bool:
        return minimum
    return max(minimum, min(maximum, value))


def _required_float(
    value: object,
    *,
    field_name: str,
    minimum: float = 0.0,
    maximum: float = 1.0,
) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise ValueError(f"{field_name}_invalid")
    numeric = float(value)
    if not isfinite(numeric) or numeric < minimum or numeric > maximum:
        raise ValueError(f"{field_name}_invalid")
    return numeric


def _required_int(
    value: object,
    *,
    field_name: str,
    minimum: int = 0,
    maximum: int = 1_000_000,
) -> int:
    if type(value) is not int or type(value) is bool or value < minimum or value > maximum:
        raise ValueError(f"{field_name}_invalid")
    return value


@dataclass(frozen=True)
class ChainStep:
    """One ordered or unordered rule step with deterministic alternatives."""

    alternatives: tuple[str, ...]
    optional: bool = False
    max_gap: int | None = None

    def __post_init__(self) -> None:
        alternatives = _text_tuple(self.alternatives, limit=32)
        if not alternatives:
            raise ValueError("chain_step_alternatives_required")
        gap = self.max_gap
        if gap is not None and (type(gap) is not int or type(gap) is bool or gap < 0 or gap > 512):
            raise ValueError("chain_step_max_gap_invalid")
        object.__setattr__(self, "alternatives", tuple(sorted(alternatives)))
        object.__setattr__(self, "optional", self.optional is True)

    def to_record(self) -> dict[str, object]:
        return {
            "alternatives": self.alternatives,
            "optional": self.optional,
            "max_gap": self.max_gap,
        }


@dataclass(frozen=True)
class StaticChainRelationConstraint:
    """One deterministic static-program relation required between two Chain steps.

    This is policy only.  Satisfaction is owned by the canonical Chain matcher
    over ``StaticProgramAnalysis`` / ``StaticFlowEdge`` facts; model context is
    intentionally absent from the contract.
    """

    source_step_index: int
    target_step_index: int
    require_control_flow_path: bool = False
    allowed_control_edge_kinds: tuple[str, ...] = field(default_factory=tuple)
    require_data_flow_path: bool = False
    allowed_data_edge_kinds: tuple[str, ...] = field(default_factory=tuple)
    require_same_value: bool = False
    same_program_entity: bool = False
    same_resource: bool = False
    source_reachability_states: tuple[str, ...] = field(default_factory=tuple)
    target_reachability_states: tuple[str, ...] = field(default_factory=tuple)
    source_resolution_states: tuple[str, ...] = field(default_factory=tuple)
    target_resolution_states: tuple[str, ...] = field(default_factory=tuple)
    relation_resolution_states: tuple[str, ...] = ("resolved",)

    def __post_init__(self) -> None:
        source = _required_int(
            self.source_step_index, field_name="static_chain_source_step_index",
            minimum=0, maximum=31,
        )
        target = _required_int(
            self.target_step_index, field_name="static_chain_target_step_index",
            minimum=0, maximum=31,
        )
        if source == target:
            raise ValueError("static_chain_relation_step_identity_invalid")
        bool_fields = (
            self.require_control_flow_path, self.require_data_flow_path,
            self.require_same_value, self.same_program_entity, self.same_resource,
        )
        if any(type(value) is not bool for value in bool_fields):
            raise ValueError("static_chain_relation_flag_invalid")
        control_kinds = tuple(sorted(_text_tuple(self.allowed_control_edge_kinds, limit=32)))
        data_kinds = tuple(sorted(_text_tuple(self.allowed_data_edge_kinds, limit=32)))
        if any(kind not in STATIC_CONTROL_FLOW_EDGE_KINDS for kind in control_kinds):
            raise ValueError("static_chain_control_edge_kind_invalid")
        if any(kind not in STATIC_DATA_FLOW_EDGE_KINDS for kind in data_kinds):
            raise ValueError("static_chain_data_edge_kind_invalid")
        if control_kinds and not self.require_control_flow_path:
            raise ValueError("static_chain_control_edge_without_path_requirement")
        if data_kinds and not self.require_data_flow_path:
            raise ValueError("static_chain_data_edge_without_path_requirement")
        source_reachability = tuple(sorted(_text_tuple(self.source_reachability_states, limit=16)))
        target_reachability = tuple(sorted(_text_tuple(self.target_reachability_states, limit=16)))
        source_resolution = tuple(sorted(_text_tuple(self.source_resolution_states, limit=16)))
        target_resolution = tuple(sorted(_text_tuple(self.target_resolution_states, limit=16)))
        relation_resolution = tuple(sorted(_text_tuple(self.relation_resolution_states, limit=16)))
        if any(value not in STATIC_REACHABILITY_STATES for value in (*source_reachability, *target_reachability)):
            raise ValueError("static_chain_reachability_state_invalid")
        if any(value not in STATIC_RESOLUTION_STATES for value in (*source_resolution, *target_resolution, *relation_resolution)):
            raise ValueError("static_chain_resolution_state_invalid")
        if (self.require_control_flow_path or self.require_data_flow_path) and not relation_resolution:
            raise ValueError("static_chain_relation_resolution_required")
        if not any((
            self.require_control_flow_path, self.require_data_flow_path, self.require_same_value,
            self.same_program_entity, self.same_resource, bool(source_reachability),
            bool(target_reachability), bool(source_resolution), bool(target_resolution),
        )):
            raise ValueError("static_chain_relation_requirement_empty")
        object.__setattr__(self, "source_step_index", source)
        object.__setattr__(self, "target_step_index", target)
        object.__setattr__(self, "allowed_control_edge_kinds", control_kinds)
        object.__setattr__(self, "allowed_data_edge_kinds", data_kinds)
        object.__setattr__(self, "source_reachability_states", source_reachability)
        object.__setattr__(self, "target_reachability_states", target_reachability)
        object.__setattr__(self, "source_resolution_states", source_resolution)
        object.__setattr__(self, "target_resolution_states", target_resolution)
        object.__setattr__(self, "relation_resolution_states", relation_resolution)

    def to_record(self) -> dict[str, object]:
        return {
            "source_step_index": self.source_step_index,
            "target_step_index": self.target_step_index,
            "require_control_flow_path": self.require_control_flow_path,
            "allowed_control_edge_kinds": self.allowed_control_edge_kinds,
            "require_data_flow_path": self.require_data_flow_path,
            "allowed_data_edge_kinds": self.allowed_data_edge_kinds,
            "require_same_value": self.require_same_value,
            "same_program_entity": self.same_program_entity,
            "same_resource": self.same_resource,
            "source_reachability_states": self.source_reachability_states,
            "target_reachability_states": self.target_reachability_states,
            "source_resolution_states": self.source_resolution_states,
            "target_resolution_states": self.target_resolution_states,
            "relation_resolution_states": self.relation_resolution_states,
        }


@dataclass(frozen=True)
class ChainRule:
    """One canonical immutable chain or explicit-anchor policy record."""

    chain_id: str
    version: str
    family: str
    match_mode: str
    steps: tuple[ChainStep, ...]
    minimum_distinct_roots: int
    confidence: float
    operational_severity: float
    score_points: float
    anchor_floor: float = 0.0
    optional_evidence: tuple[str, ...] = field(default_factory=tuple)
    forbidden_evidence: tuple[str, ...] = field(default_factory=tuple)
    maximum_time_gap: float | None = None
    same_actor: bool = False
    same_target: bool = False
    same_artifact: bool = False
    same_host: bool = False
    same_process: bool = False
    same_connection: bool = False
    platform_match: bool = False
    required_platforms: tuple[str, ...] = field(default_factory=tuple)
    required_modalities: tuple[str, ...] = field(default_factory=tuple)
    minimum_direct_observations: int = 0
    required_fields: tuple[str, ...] = field(default_factory=tuple)
    static_relations: tuple[StaticChainRelationConstraint, ...] = field(default_factory=tuple)
    correlation_group: str = ""
    scoreable: bool = True
    rationale: str = ""

    def __post_init__(self) -> None:
        chain_id = _text(self.chain_id)
        version = _text(self.version)
        family = _text(self.family)
        match_mode = _text(self.match_mode)
        steps = tuple(step for step in self.steps if type(step) is ChainStep)
        if not chain_id or not version or not family:
            raise ValueError("chain_rule_identity_required")
        if match_mode not in CHAIN_MATCH_MODES:
            raise ValueError("chain_rule_match_mode_invalid")
        if not steps or len(steps) > 32:
            raise ValueError("chain_rule_steps_invalid")
        required_count = sum(not step.optional for step in steps)
        minimum_roots = _required_int(
            self.minimum_distinct_roots,
            field_name="chain_rule_minimum_distinct_roots",
            minimum=1,
            maximum=32,
        )
        if minimum_roots > required_count:
            raise ValueError("chain_rule_distinct_root_requirement_invalid")
        maximum_time_gap = self.maximum_time_gap
        if maximum_time_gap is not None:
            maximum_time_gap = _required_float(
                maximum_time_gap,
                field_name="chain_rule_maximum_time_gap",
                minimum=0.0,
                maximum=86_400.0,
            )
        confidence = _required_float(
            self.confidence, field_name="chain_rule_confidence", minimum=0.0, maximum=1.0,
        )
        severity = _required_float(
            self.operational_severity,
            field_name="chain_rule_operational_severity",
            minimum=0.0,
            maximum=100.0,
        )
        score_points = _required_float(
            self.score_points, field_name="chain_rule_score_points", minimum=0.0, maximum=100.0,
        )
        anchor_floor = _required_float(
            self.anchor_floor, field_name="chain_rule_anchor_floor", minimum=0.0, maximum=100.0,
        )
        correlation_flags = {
            "same_actor": self.same_actor,
            "same_target": self.same_target,
            "same_artifact": self.same_artifact,
            "same_host": self.same_host,
            "same_process": self.same_process,
            "same_connection": self.same_connection,
            "platform_match": self.platform_match,
        }
        if any(type(value) is not bool for value in correlation_flags.values()):
            raise ValueError("chain_rule_correlation_flag_invalid")
        required_platforms = tuple(sorted(_text_tuple(self.required_platforms, limit=32)))
        required_modalities = tuple(sorted(_text_tuple(self.required_modalities, limit=16)))
        minimum_direct = _required_int(
            self.minimum_direct_observations,
            field_name="chain_rule_minimum_direct_observations",
            minimum=0,
            maximum=32,
        )
        if minimum_direct > required_count:
            raise ValueError("chain_rule_minimum_direct_observations_invalid")
        required_fields = tuple(sorted(_text_tuple(self.required_fields, limit=32)))
        if any(field_name not in CHAIN_CORRELATION_FIELDS for field_name in required_fields):
            raise ValueError("chain_rule_required_field_invalid")
        static_relations = tuple(
            item for item in self.static_relations
            if type(item) is StaticChainRelationConstraint
        )
        if len(static_relations) != len(self.static_relations) or len(static_relations) > 32:
            raise ValueError("chain_rule_static_relation_invalid")
        relation_records: set[tuple[object, ...]] = set()
        for relation in static_relations:
            if relation.source_step_index >= len(steps) or relation.target_step_index >= len(steps):
                raise ValueError("chain_rule_static_relation_step_out_of_range")
            if steps[relation.source_step_index].optional or steps[relation.target_step_index].optional:
                raise ValueError("chain_rule_static_relation_optional_step_invalid")
            record_key = tuple(sorted(relation.to_record().items()))
            if record_key in relation_records:
                raise ValueError("chain_rule_static_relation_duplicate")
            relation_records.add(record_key)
        correlation_group = _text(self.correlation_group) or family
        object.__setattr__(self, "chain_id", chain_id)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "family", family)
        object.__setattr__(self, "match_mode", match_mode)
        object.__setattr__(self, "steps", steps)
        object.__setattr__(self, "minimum_distinct_roots", minimum_roots)
        object.__setattr__(self, "confidence", confidence)
        object.__setattr__(self, "operational_severity", severity)
        object.__setattr__(self, "score_points", score_points)
        object.__setattr__(self, "anchor_floor", anchor_floor)
        object.__setattr__(self, "optional_evidence", _text_tuple(self.optional_evidence, limit=64))
        object.__setattr__(self, "forbidden_evidence", _text_tuple(self.forbidden_evidence, limit=64))
        object.__setattr__(self, "maximum_time_gap", maximum_time_gap)
        for field_name, value in correlation_flags.items():
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "required_platforms", required_platforms)
        object.__setattr__(self, "required_modalities", required_modalities)
        object.__setattr__(self, "minimum_direct_observations", minimum_direct)
        object.__setattr__(self, "required_fields", required_fields)
        object.__setattr__(self, "static_relations", static_relations)
        object.__setattr__(self, "correlation_group", correlation_group)
        object.__setattr__(self, "scoreable", self.scoreable is True)
        object.__setattr__(self, "rationale", _text(self.rationale))

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "version": self.version,
            "family": self.family,
            "match_mode": self.match_mode,
            "steps": tuple(step.to_record() for step in self.steps),
            "minimum_distinct_roots": self.minimum_distinct_roots,
            "confidence": self.confidence,
            "operational_severity": self.operational_severity,
            "score_points": self.score_points,
            "anchor_floor": self.anchor_floor,
            "optional_evidence": self.optional_evidence,
            "forbidden_evidence": self.forbidden_evidence,
            "maximum_time_gap": self.maximum_time_gap,
            "same_actor": self.same_actor,
            "same_target": self.same_target,
            "same_artifact": self.same_artifact,
            "same_host": self.same_host,
            "same_process": self.same_process,
            "same_connection": self.same_connection,
            "platform_match": self.platform_match,
            "required_platforms": self.required_platforms,
            "required_modalities": self.required_modalities,
            "minimum_direct_observations": self.minimum_direct_observations,
            "required_fields": self.required_fields,
            "static_relations": tuple(item.to_record() for item in self.static_relations),
            "correlation_group": self.correlation_group,
            "scoreable": self.scoreable,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ChainEvent:
    """One hostile-safe evidence event used by the canonical matcher."""

    evidence_id: str
    root_evidence_id: str
    term: str
    source: str
    ordinal: int
    timestamp: float | None = None
    correlation_group: str = ""
    evidence_kind: str = "observed"
    polarity: str = "positive"
    unavailable_reason: str = ""
    observation_id: str = ""
    modality: str = "unavailable"
    platform: str = ""
    actor_identity: str = ""
    target_identity: str = ""
    artifact_identity: str = ""
    process_identity: str = ""
    host_identity: str = ""
    connection_identity: str = ""
    source_location: ObservationSourceLocation = field(
        default_factory=lambda: ObservationSourceLocation("unavailable")
    )
    timing_provenance: str = "unavailable"
    integrity_status: str = "unavailable"
    directness: str = "unavailable"

    def __post_init__(self) -> None:
        evidence_id = _text(self.evidence_id)
        root = _text(self.root_evidence_id) or evidence_id
        term = _text(self.term)
        source = _text(self.source)
        if not evidence_id or not root or not term or not source:
            raise ValueError("chain_event_identity_required")
        timestamp = self.timestamp
        if timestamp is not None:
            if (
                type(timestamp) not in (int, float)
                or type(timestamp) is bool
                or not isfinite(float(timestamp))
            ):
                raise ValueError("chain_event_timestamp_invalid")
            timestamp = float(timestamp)
        object.__setattr__(self, "evidence_id", evidence_id)
        object.__setattr__(self, "root_evidence_id", root)
        object.__setattr__(self, "term", term)
        object.__setattr__(self, "source", source)
        ordinal = _required_int(
            self.ordinal, field_name="chain_event_ordinal", minimum=0, maximum=1_000_000,
        )
        polarity = _text(self.polarity) or "positive"
        if polarity not in {"positive", "negative", "neutral"}:
            raise ValueError("chain_event_polarity_invalid")
        object.__setattr__(self, "ordinal", ordinal)
        object.__setattr__(self, "timestamp", timestamp)
        object.__setattr__(self, "correlation_group", _text(self.correlation_group))
        object.__setattr__(self, "evidence_kind", _text(self.evidence_kind) or "observed")
        object.__setattr__(self, "polarity", polarity)
        object.__setattr__(self, "unavailable_reason", _text(self.unavailable_reason))
        if type(self.source_location) is not ObservationSourceLocation:
            raise ValueError("chain_event_source_location_invalid")
        object.__setattr__(self, "observation_id", _text(self.observation_id))
        object.__setattr__(self, "modality", _text(self.modality) or "unavailable")
        object.__setattr__(self, "platform", _text(self.platform))
        object.__setattr__(self, "actor_identity", _text(self.actor_identity))
        object.__setattr__(self, "target_identity", _text(self.target_identity))
        object.__setattr__(self, "artifact_identity", _text(self.artifact_identity))
        object.__setattr__(self, "process_identity", _text(self.process_identity))
        object.__setattr__(self, "host_identity", _text(self.host_identity))
        object.__setattr__(self, "connection_identity", _text(self.connection_identity))
        object.__setattr__(self, "timing_provenance", _text(self.timing_provenance) or "unavailable")
        object.__setattr__(self, "integrity_status", _text(self.integrity_status) or "unavailable")
        object.__setattr__(self, "directness", _text(self.directness) or "unavailable")

    @property
    def has_physical_root_authority(self) -> bool:
        """Whether this event is rooted in a canonical physical observation.

        Physical authority is provenance-based, not identifier-shape-based. Raw
        timeline/API mappings always materialize with context-only sources even
        when they supply strings beginning with ``obs_``. Only events projected
        by the canonical TagEvidence owner or exact DetectionObservation inputs
        receive a physical source classification.
        """
        return bool(
            self.source in CHAIN_PHYSICAL_EVENT_SOURCES
            and self.observation_id.startswith("obs_")
            and self.root_evidence_id.startswith("obs_")
            and (
                self.artifact_identity
                or self.actor_identity
                or self.target_identity
                or self.process_identity
                or self.host_identity
                or self.connection_identity
                or self.source_location.identifies_physical_source
            )
        )

    def to_record(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "root_evidence_id": self.root_evidence_id,
            "term": self.term,
            "source": self.source,
            "ordinal": self.ordinal,
            "timestamp": self.timestamp,
            "correlation_group": self.correlation_group,
            "evidence_kind": self.evidence_kind,
            "polarity": self.polarity,
            "unavailable_reason": self.unavailable_reason,
            "observation_id": self.observation_id,
            "modality": self.modality,
            "platform": self.platform,
            "actor_identity": self.actor_identity,
            "target_identity": self.target_identity,
            "artifact_identity": self.artifact_identity,
            "process_identity": self.process_identity,
            "host_identity": self.host_identity,
            "connection_identity": self.connection_identity,
            "source_location": self.source_location.to_record(),
            "timing_provenance": self.timing_provenance,
            "integrity_status": self.integrity_status,
            "directness": self.directness,
        }


@dataclass(frozen=True)
class MatchedChainStep:
    step_index: int
    alternative: str
    event: ChainEvent

    def to_record(self) -> dict[str, object]:
        return {
            "step_index": self.step_index,
            "alternative": self.alternative,
            "event": self.event.to_record(),
        }


@dataclass(frozen=True)
class ChainCandidate:
    chain_id: str
    rule_version: str
    family: str
    order_class: str
    matched_steps: tuple[MatchedChainStep, ...]
    missing_step_indexes: tuple[int, ...]
    confidence: float
    support: float
    correlation_group: str
    blocked_reason: str = ""
    unmet_requirements: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        order_class = _text(self.order_class)
        if order_class not in CHAIN_ORDER_CLASSES:
            raise ValueError("chain_candidate_order_class_invalid")
        object.__setattr__(self, "chain_id", _text(self.chain_id))
        object.__setattr__(self, "rule_version", _text(self.rule_version))
        object.__setattr__(self, "family", _text(self.family))
        object.__setattr__(self, "order_class", order_class)
        object.__setattr__(self, "matched_steps", tuple(step for step in self.matched_steps if type(step) is MatchedChainStep))
        object.__setattr__(self, "missing_step_indexes", tuple(sorted({_bounded_int(index, maximum=64) for index in self.missing_step_indexes})))
        object.__setattr__(self, "confidence", _bounded_float(self.confidence))
        object.__setattr__(self, "support", _bounded_float(self.support))
        object.__setattr__(self, "correlation_group", _text(self.correlation_group) or _text(self.family))
        object.__setattr__(self, "blocked_reason", _text(self.blocked_reason))
        object.__setattr__(self, "unmet_requirements", tuple(sorted(_text_tuple(
            self.unmet_requirements, limit=32,
        ))))

    @property
    def distinct_root_ids(self) -> frozenset[str]:
        return frozenset(step.event.root_evidence_id for step in self.matched_steps)

    @property
    def physically_rooted(self) -> bool:
        """Return whether every matched step has canonical physical provenance.

        Identifier formatting is never authority. The event materialization owner
        must prove provenance from TagEvidence or an exact DetectionObservation;
        ArtifactEvidenceSnapshot then independently proves root membership in the
        final frozen physical evidence set.
        """
        return bool(self.matched_steps) and all(
            step.event.has_physical_root_authority
            for step in self.matched_steps
        )


@dataclass(frozen=True)
class ChainExplanation:
    chain_id: str
    summary: str
    evidence_ids: tuple[str, ...]
    root_evidence_ids: tuple[str, ...]
    rejected_reason: str = ""

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": _text(self.chain_id),
            "summary": _text(self.summary),
            "evidence_ids": _text_tuple(self.evidence_ids),
            "root_evidence_ids": _text_tuple(self.root_evidence_ids),
            "rejected_reason": _text(self.rejected_reason),
        }


@dataclass(frozen=True)
class ChainDecision:
    rule: ChainRule
    candidate: ChainCandidate
    status: str
    scoreable: bool
    score_points: float
    operational_severity: float
    anchor_floor: float
    explanation: ChainExplanation

    def __post_init__(self) -> None:
        if type(self.rule) is not ChainRule:
            raise TypeError("chain_decision_rule_invalid")
        if type(self.candidate) is not ChainCandidate:
            raise TypeError("chain_decision_candidate_invalid")
        if (
            self.rule.chain_id != self.candidate.chain_id
            or self.rule.version != self.candidate.rule_version
            or self.rule.family != self.candidate.family
        ):
            raise ValueError("chain_decision_rule_identity_mismatch")
        status = _text(self.status)
        if status not in CHAIN_DECISION_STATUSES:
            raise ValueError("chain_decision_status_invalid")
        object.__setattr__(self, "status", status)
        scoreable = self.scoreable is True and status in {"confirmed", "candidate"}
        if scoreable and not self.candidate.physically_rooted:
            raise ValueError("chain_decision_scoreable_root_not_physical")
        object.__setattr__(self, "scoreable", scoreable)
        object.__setattr__(self, "score_points", _bounded_float(self.score_points, maximum=100.0))
        object.__setattr__(self, "operational_severity", _bounded_float(self.operational_severity, maximum=100.0))
        object.__setattr__(self, "anchor_floor", _bounded_float(self.anchor_floor, maximum=100.0))

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": self.candidate.chain_id,
            "rule_version": self.candidate.rule_version,
            "family": self.candidate.family,
            "status": self.status,
            "order_class": self.candidate.order_class,
            "matched_steps": tuple(step.to_record() for step in self.candidate.matched_steps),
            "missing_step_indexes": self.candidate.missing_step_indexes,
            "matched_evidence_ids": tuple(step.event.evidence_id for step in self.candidate.matched_steps),
            "root_evidence_ids": tuple(sorted(self.candidate.distinct_root_ids)),
            "confidence": self.candidate.confidence,
            "support": self.candidate.support,
            "scoreable": self.scoreable,
            "score_points": self.score_points,
            "operational_severity": self.operational_severity,
            "anchor_floor": self.anchor_floor,
            "correlation_group": self.candidate.correlation_group,
            "blocked_reason": self.candidate.blocked_reason,
            "unmet_requirements": self.candidate.unmet_requirements,
            "rule": self.rule.to_record(),
            "explanation": self.explanation.to_record(),
        }


@dataclass(frozen=True)
class ChainEvidence:
    """Bounded immutable chain-evaluation result and string projection."""

    registry_version: str
    registry_digest: str
    decisions: tuple[ChainDecision, ...] = field(default_factory=tuple)
    failures: tuple[Mapping[str, object], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        decisions = tuple(decision for decision in self.decisions if type(decision) is ChainDecision)[:256]
        failures = tuple(MappingProxyType(dict(item)) for item in self.failures if type(item) is dict)[:64]
        object.__setattr__(self, "registry_version", _text(self.registry_version))
        object.__setattr__(self, "registry_digest", _text(self.registry_digest))
        object.__setattr__(self, "decisions", decisions)
        object.__setattr__(self, "failures", failures)

    @property
    def confirmed(self) -> tuple[ChainDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.status == "confirmed")

    @property
    def candidates(self) -> tuple[ChainDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.status == "candidate")

    @property
    def partial(self) -> tuple[ChainDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.status == "partial")

    @property
    def blocked(self) -> tuple[ChainDecision, ...]:
        return tuple(decision for decision in self.decisions if decision.status == "blocked")

    @property
    def scoreable_families(self) -> frozenset[str]:
        return frozenset(
            decision.candidate.family
            for decision in self.decisions
            if decision.scoreable
        )

    @property
    def scoreable_root_ids(self) -> frozenset[str]:
        """Return roots consumed by scoreable chain decisions."""
        return frozenset(
            root_id
            for decision in self.decisions
            if decision.scoreable
            for root_id in decision.candidate.distinct_root_ids
        )

    @property
    def hits(self) -> tuple[str, ...]:
        return tuple(decision.candidate.chain_id for decision in self.decisions if decision.status in {"confirmed", "candidate"})

    @property
    def maximum_anchor_floor(self) -> float:
        return max((decision.anchor_floor for decision in self.decisions if decision.scoreable), default=0.0)

    @property
    def total_score_points(self) -> float:
        family_best: dict[str, float] = {}
        for decision in self.decisions:
            if not decision.scoreable:
                continue
            family = decision.candidate.family
            family_best[family] = max(family_best.get(family, 0.0), decision.score_points)
        return min(75.0, sum(family_best.values()))

    def to_record(self, *, decision_limit: int = 128) -> dict[str, object]:
        limit = _bounded_int(decision_limit, maximum=256)
        return {
            "schema_version": CHAIN_EVIDENCE_SCHEMA_VERSION,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "decisions": tuple(decision.to_record() for decision in self.decisions[:limit]),
            "hits": self.hits,
            "confirmed_count": len(self.confirmed),
            "candidate_count": len(self.candidates),
            "partial_count": len(self.partial),
            "blocked_count": len(self.blocked),
            "scoreable_family_count": len(self.scoreable_families),
            "maximum_anchor_floor": self.maximum_anchor_floor,
            "total_score_points": self.total_score_points,
            "degraded": bool(self.failures),
            "failure_evidence": tuple(dict(item) for item in self.failures),
        }


def _sha256_digest(value: object, *, field_name: str) -> str:
    text = _text(value)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(field_name + "_invalid")
    return text


@dataclass(frozen=True)
class ChainRuleOutcome:
    """One rule's exact input identity and optional immutable decision."""

    chain_id: str
    rule_digest: str
    input_digest: str
    decision: ChainDecision | None = None

    def __post_init__(self) -> None:
        chain_id = _text(self.chain_id)
        if not chain_id:
            raise ValueError("chain_rule_outcome_identity_required")
        decision = self.decision
        if decision is not None and type(decision) is not ChainDecision:
            raise TypeError("chain_rule_outcome_decision_invalid")
        if decision is not None and decision.candidate.chain_id != chain_id:
            raise ValueError("chain_rule_outcome_decision_identity_mismatch")
        object.__setattr__(self, "chain_id", chain_id)
        object.__setattr__(self, "rule_digest", _sha256_digest(
            self.rule_digest, field_name="chain_rule_outcome_rule_digest",
        ))
        object.__setattr__(self, "input_digest", _sha256_digest(
            self.input_digest, field_name="chain_rule_outcome_input_digest",
        ))

    def to_record(self) -> dict[str, object]:
        return {
            "chain_id": self.chain_id,
            "decision": None if self.decision is None else self.decision.to_record(),
            "input_digest": self.input_digest,
            "rule_digest": self.rule_digest,
        }


@dataclass(frozen=True)
class ChainEvidenceGeneration:
    """One monotonic evidence generation and its per-rule reuse ledger.

    Runtime/API order and validated static-control-flow order are independent
    provenance domains.  Their identities are never collapsed into one stream.
    """

    generation_id: str
    registry_version: str
    registry_digest: str
    compiled_registry_version: str
    compiled_registry_digest: str
    selected_rule_ids: tuple[str, ...]
    runtime_ordered_event_digest: str
    static_ordered_event_digest: str
    static_relation_digest: str
    correlation_event_digest: str
    runtime_ordered_event_signatures: tuple[str, ...]
    static_ordered_event_signatures: tuple[str, ...]
    correlation_event_signatures: tuple[str, ...]
    outcomes: tuple[ChainRuleOutcome, ...]
    evaluated_rule_ids: tuple[str, ...]
    reused_rule_ids: tuple[str, ...]
    full_recompute_reason: str
    evidence: ChainEvidence

    def __post_init__(self) -> None:
        if type(self.evidence) is not ChainEvidence:
            raise TypeError("chain_evidence_generation_evidence_invalid")
        selected = tuple(sorted(_text_tuple(self.selected_rule_ids, limit=512)))
        outcomes = tuple(item for item in self.outcomes if type(item) is ChainRuleOutcome)
        if len(outcomes) != len(self.outcomes):
            raise TypeError("chain_evidence_generation_outcome_invalid")
        outcome_ids = tuple(item.chain_id for item in outcomes)
        if outcome_ids != selected or len(set(outcome_ids)) != len(outcome_ids):
            raise ValueError("chain_evidence_generation_outcome_coverage_invalid")
        evaluated = tuple(sorted(_text_tuple(self.evaluated_rule_ids, limit=512)))
        reused = tuple(sorted(_text_tuple(self.reused_rule_ids, limit=512)))
        if set(evaluated) & set(reused) or set(evaluated) | set(reused) != set(selected):
            raise ValueError("chain_evidence_generation_rule_ledger_invalid")
        runtime_signatures = tuple(
            _sha256_digest(item, field_name="chain_evidence_generation_event_signature")
            for item in self.runtime_ordered_event_signatures
        )
        static_signatures = tuple(
            _sha256_digest(item, field_name="chain_evidence_generation_event_signature")
            for item in self.static_ordered_event_signatures
        )
        correlation_signatures = tuple(
            _sha256_digest(item, field_name="chain_evidence_generation_event_signature")
            for item in self.correlation_event_signatures
        )
        object.__setattr__(self, "generation_id", _sha256_digest(
            self.generation_id, field_name="chain_evidence_generation_id",
        ))
        object.__setattr__(self, "registry_version", _text(self.registry_version))
        object.__setattr__(self, "registry_digest", _sha256_digest(
            self.registry_digest, field_name="chain_evidence_generation_registry_digest",
        ))
        object.__setattr__(self, "compiled_registry_version", _text(self.compiled_registry_version))
        object.__setattr__(self, "compiled_registry_digest", _sha256_digest(
            self.compiled_registry_digest, field_name="chain_evidence_generation_compiled_digest",
        ))
        object.__setattr__(self, "selected_rule_ids", selected)
        object.__setattr__(self, "runtime_ordered_event_digest", _sha256_digest(
            self.runtime_ordered_event_digest,
            field_name="chain_evidence_generation_runtime_ordered_digest",
        ))
        object.__setattr__(self, "static_ordered_event_digest", _sha256_digest(
            self.static_ordered_event_digest,
            field_name="chain_evidence_generation_static_ordered_digest",
        ))
        object.__setattr__(self, "static_relation_digest", _sha256_digest(
            self.static_relation_digest,
            field_name="chain_evidence_generation_static_relation_digest",
        ))
        object.__setattr__(self, "correlation_event_digest", _sha256_digest(
            self.correlation_event_digest, field_name="chain_evidence_generation_correlation_digest",
        ))
        object.__setattr__(self, "runtime_ordered_event_signatures", runtime_signatures)
        object.__setattr__(self, "static_ordered_event_signatures", static_signatures)
        object.__setattr__(self, "correlation_event_signatures", correlation_signatures)
        object.__setattr__(self, "outcomes", outcomes)
        object.__setattr__(self, "evaluated_rule_ids", evaluated)
        object.__setattr__(self, "reused_rule_ids", reused)
        object.__setattr__(self, "full_recompute_reason", _text(self.full_recompute_reason))

    def to_record(self) -> dict[str, object]:
        return {
            "schema_version": CHAIN_EVIDENCE_GENERATION_SCHEMA_VERSION,
            "compiled_registry_digest": self.compiled_registry_digest,
            "compiled_registry_version": self.compiled_registry_version,
            "correlation_event_digest": self.correlation_event_digest,
            "correlation_event_signatures": self.correlation_event_signatures,
            "evaluated_rule_ids": self.evaluated_rule_ids,
            "evidence": self.evidence.to_record(),
            "full_recompute_reason": self.full_recompute_reason,
            "generation_id": self.generation_id,
            "runtime_ordered_event_digest": self.runtime_ordered_event_digest,
            "runtime_ordered_event_signatures": self.runtime_ordered_event_signatures,
            "static_ordered_event_digest": self.static_ordered_event_digest,
            "static_relation_digest": self.static_relation_digest,
            "static_ordered_event_signatures": self.static_ordered_event_signatures,
            "outcomes": tuple(item.to_record() for item in self.outcomes),
            "registry_digest": self.registry_digest,
            "registry_version": self.registry_version,
            "reused_rule_ids": self.reused_rule_ids,
            "selected_rule_ids": self.selected_rule_ids,
        }


__all__ = (
    "CHAIN_CORRELATION_FIELDS",
    "CHAIN_DECISION_STATUSES",
    "CHAIN_EVIDENCE_SCHEMA_VERSION",
    "CHAIN_EVIDENCE_GENERATION_SCHEMA_VERSION",
    "CHAIN_MATCH_MODES",
    "StaticChainRelationConstraint",
    "CHAIN_ORDER_CLASSES",
    "ChainCandidate",
    "ChainDecision",
    "ChainEvent",
    "ChainEvidence",
    "ChainEvidenceGeneration",
    "ChainExplanation",
    "ChainRule",
    "ChainRuleOutcome",
    "ChainStep",
    "MatchedChainStep",
)
