"""Canonical projection-only Chain findings summary contracts and renderers.

The projector consumes only final immutable ``canonical_chain_evidence`` records
already owned by the scan publication snapshot.  It never imports the Chain
registry, invokes the matcher, reevaluates satisfaction, or changes score/order.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.chain_evidence import (
    CHAIN_DECISION_STATUSES,
    CHAIN_EVIDENCE_SCHEMA_VERSION,
    CHAIN_MATCH_MODES,
    CHAIN_ORDER_CLASSES,
)
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.publication.content_identity import (
    exact_content_sha256,
    final_record_content_sha256,
)

CHAIN_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION = "chain_evidence_summary_row_v2"
CHAIN_FINDING_SUMMARY_ROW_SCHEMA_VERSION = "chain_finding_summary_row_v2"
CHAIN_FINDINGS_SUMMARY_SCHEMA_VERSION = "chain_findings_summary_v2"
_MAX_RECORDS = 200_000
_MAX_ITEMS = 512
_MAX_TEXT = 4096


def _mapping(value: object, reason: str) -> dict[str, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        raise TypeError(reason)
    return {key: item for key, item in items if type(key) is str}


def _mapping_value(value: object, key: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for candidate, item in items:
        if type(candidate) is str and str.__eq__(candidate, key):
            return item
    return default


def _text(value: object, reason: str, *, allow_blank: bool = False, maximum: int = _MAX_TEXT) -> str:
    return exact_bounded_text(value, reason, maximum=maximum, allow_blank=allow_blank)


def _bool(value: object, reason: str) -> bool:
    if type(value) is not bool:
        raise TypeError(reason)
    return value


def _number(value: object, reason: str) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not (number == number and abs(number) != float("inf")):
        raise ValueError(reason)
    return number


def _nonnegative_int(value: object, reason: str) -> int:
    if type(value) is not int or type(value) is bool or value < 0:
        raise TypeError(reason)
    return value


def _sequence(value: object, reason: str, *, limit: int = _MAX_ITEMS) -> tuple[object, ...]:
    values = no_hook_sequence_items(value)
    if len(values) > limit:
        raise ValueError(reason)
    return tuple(values)


def _text_tuple(value: object, reason: str, *, limit: int = _MAX_ITEMS, sorted_unique: bool = False) -> tuple[str, ...]:
    values = tuple(_text(item, reason) for item in _sequence(value, reason, limit=limit))
    if sorted_unique and values != tuple(sorted(set(values))):
        raise ValueError(reason)
    return values


def _int_tuple(value: object, reason: str, *, limit: int = _MAX_ITEMS) -> tuple[int, ...]:
    values = tuple(_nonnegative_int(item, reason) for item in _sequence(value, reason, limit=limit))
    if values != tuple(sorted(set(values))):
        raise ValueError(reason)
    return values


def _rule_steps(rule: Mapping[str, object]) -> tuple[tuple[tuple[str, ...], bool, int | None], ...]:
    rows: list[tuple[tuple[str, ...], bool, int | None]] = []
    for raw in _sequence(_mapping_value(rule, "steps", ()), "chain_summary_rule_steps_invalid", limit=64):
        step = _mapping(raw, "chain_summary_rule_step_invalid")
        alternatives = _text_tuple(
            _mapping_value(step, "alternatives", ()),
            "chain_summary_rule_alternatives_invalid",
            limit=32,
            sorted_unique=True,
        )
        if not alternatives:
            raise ValueError("chain_summary_rule_alternatives_invalid")
        optional = _bool(_mapping_value(step, "optional"), "chain_summary_rule_optional_invalid")
        gap = _mapping_value(step, "max_gap")
        if gap is not None:
            gap = _nonnegative_int(gap, "chain_summary_rule_max_gap_invalid")
        rows.append((alternatives, optional, gap))
    if not rows:
        raise ValueError("chain_summary_rule_steps_invalid")
    return tuple(rows)


def _source_chain_evidence(record: object, record_key: str) -> dict[str, object] | None:
    value = _mapping_value(record, "canonical_chain_evidence")
    if value is None:
        return None
    materialized = no_hook_materialize(
        value,
        max_depth=32,
        max_items=20_000,
        reason_prefix="chain_summary_source",
    )
    if type(materialized) is not dict:
        raise RuntimeError("chain_summary_source_invalid:" + record_key)
    if dict.get(materialized, "schema_version") != CHAIN_EVIDENCE_SCHEMA_VERSION:
        raise RuntimeError("chain_summary_source_schema_invalid:" + record_key)
    decisions = _sequence(dict.get(materialized, "decisions", ()), "chain_summary_decisions_invalid", limit=256)
    failures = _sequence(dict.get(materialized, "failure_evidence", ()), "chain_summary_failures_invalid", limit=64)
    status_counts = {status: 0 for status in CHAIN_DECISION_STATUSES}
    expected_hits: list[str] = []
    for raw in decisions:
        decision = _mapping(raw, "chain_summary_decision_invalid")
        status = dict.get(decision, "status")
        if type(status) is not str or status not in CHAIN_DECISION_STATUSES:
            raise RuntimeError("chain_summary_decision_status_invalid:" + record_key)
        status_counts[status] += 1
        chain_id = dict.get(decision, "chain_id")
        if type(chain_id) is not str or not chain_id:
            raise RuntimeError("chain_summary_decision_identity_invalid:" + record_key)
        if status in {"confirmed", "candidate"}:
            expected_hits.append(chain_id)
    published_counts = {
        "confirmed": dict.get(materialized, "confirmed_count"),
        "candidate": dict.get(materialized, "candidate_count"),
        "partial": dict.get(materialized, "partial_count"),
        "blocked": dict.get(materialized, "blocked_count"),
    }
    if any(published_counts[key] != status_counts[key] for key in published_counts):
        raise RuntimeError("chain_summary_source_count_mismatch:" + record_key)
    if tuple(dict.get(materialized, "hits", ())) != tuple(expected_hits):
        raise RuntimeError("chain_summary_source_hits_mismatch:" + record_key)
    if dict.get(materialized, "degraded") is not bool(failures):
        raise RuntimeError("chain_summary_source_degraded_mismatch:" + record_key)
    return materialized


def _matched_event_fields(decision: Mapping[str, object]) -> dict[str, tuple[str, ...] | tuple[int, ...]]:
    matched_indexes: list[int] = []
    evidence_ids: set[str] = set()
    roots: set[str] = set()
    operations: set[str] = set()
    targets: set[str] = set()
    processes: set[str] = set()
    artifacts: set[str] = set()
    actors: set[str] = set()
    hosts: set[str] = set()
    connections: set[str] = set()
    event_groups: set[str] = set()
    for raw in _sequence(_mapping_value(decision, "matched_steps", ()), "chain_summary_matched_steps_invalid", limit=64):
        step = _mapping(raw, "chain_summary_matched_step_invalid")
        matched_indexes.append(_nonnegative_int(_mapping_value(step, "step_index"), "chain_summary_step_index_invalid"))
        event = _mapping(_mapping_value(step, "event"), "chain_summary_event_invalid")
        for field, output in (
            ("evidence_id", evidence_ids),
            ("root_evidence_id", roots),
            ("target_identity", targets),
            ("process_identity", processes),
            ("artifact_identity", artifacts),
            ("actor_identity", actors),
            ("host_identity", hosts),
            ("connection_identity", connections),
            ("correlation_group", event_groups),
        ):
            value = _mapping_value(event, field, "")
            if type(value) is str and str.__str__(value):
                output.add(str.__str__(value))
        location = _mapping_value(event, "source_location")
        location_items = no_hook_mapping_items(location)
        if location_items is not None:
            location_map = {key: item for key, item in location_items if type(key) is str}
            if dict.get(location_map, "location_type") == "static_operation":
                event_id = dict.get(location_map, "event_id")
                if type(event_id) is str and str.__str__(event_id):
                    operations.add(str.__str__(event_id))
    return {
        "matched_step_indexes": tuple(sorted(set(matched_indexes))),
        "matched_evidence_ids": tuple(sorted(evidence_ids)),
        "root_evidence_ids": tuple(sorted(roots)),
        "operation_ids": tuple(sorted(operations)),
        "target_identities": tuple(sorted(targets)),
        "process_identities": tuple(sorted(processes)),
        "artifact_identities": tuple(sorted(artifacts)),
        "actor_identities": tuple(sorted(actors)),
        "host_identities": tuple(sorted(hosts)),
        "connection_identities": tuple(sorted(connections)),
        "event_correlation_groups": tuple(sorted(event_groups)),
    }


@dataclass(frozen=True, slots=True)
class ChainEvidenceSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    registry_version: str
    registry_digest: str
    source_schema_version: str
    decision_count: int
    failure_count: int
    degraded: bool
    evidence_semantic_digest: str
    schema_version: str = CHAIN_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ChainEvidenceSummaryRow:
            raise TypeError("chain_evidence_summary_owner_invalid")
        if self.schema_version != CHAIN_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION:
            raise ValueError("chain_evidence_summary_schema_invalid")
        if not self.record_keys or self.record_keys != tuple(sorted(set(self.record_keys))):
            raise ValueError("chain_evidence_summary_record_keys_invalid")
        for key in self.record_keys:
            _text(key, "chain_evidence_summary_record_key_invalid")
        exact_content_sha256(self.content_sha256, "chain_evidence_summary_content_sha256_invalid")
        _text(self.registry_version, "chain_evidence_summary_registry_version_invalid")
        _text(self.registry_digest, "chain_evidence_summary_registry_digest_invalid")
        _text(self.source_schema_version, "chain_evidence_summary_source_schema_invalid")
        _nonnegative_int(self.decision_count, "chain_evidence_summary_decision_count_invalid")
        _nonnegative_int(self.failure_count, "chain_evidence_summary_failure_count_invalid")
        _bool(self.degraded, "chain_evidence_summary_degraded_invalid")
        _text(self.evidence_semantic_digest, "chain_evidence_summary_digest_invalid", maximum=64)

    def to_record(self) -> dict[str, object]:
        return {
            "record_keys": self.record_keys,
            "content_sha256": self.content_sha256,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "source_schema_version": self.source_schema_version,
            "decision_count": self.decision_count,
            "failure_count": self.failure_count,
            "degraded": self.degraded,
            "evidence_semantic_digest": self.evidence_semantic_digest,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class ChainFindingSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    registry_version: str
    registry_digest: str
    source_schema_version: str
    chain_id: str
    chain_name: str
    chain_name_source: str
    rule_version: str
    family: str
    decision_status: str
    match_mode: str
    order_provenance: str
    required_steps: tuple[tuple[str, ...], ...]
    optional_steps: tuple[tuple[str, ...], ...]
    optional_evidence: tuple[str, ...]
    forbidden_evidence: tuple[str, ...]
    matched_step_indexes: tuple[int, ...]
    missing_step_indexes: tuple[int, ...]
    unmet_requirements: tuple[str, ...]
    blocked_reason: str
    root_evidence_ids: tuple[str, ...]
    matched_evidence_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    actor_identities: tuple[str, ...]
    target_identities: tuple[str, ...]
    artifact_identities: tuple[str, ...]
    process_identities: tuple[str, ...]
    host_identities: tuple[str, ...]
    connection_identities: tuple[str, ...]
    event_correlation_groups: tuple[str, ...]
    same_actor_required: bool
    same_target_required: bool
    same_artifact_required: bool
    same_host_required: bool
    same_process_required: bool
    same_connection_required: bool
    platform_match_required: bool
    same_resource_required: bool
    resource_requirement_state: str
    same_flow_required: bool
    flow_requirement_state: str
    required_platforms: tuple[str, ...]
    required_modalities: tuple[str, ...]
    required_fields: tuple[str, ...]
    minimum_distinct_roots: int
    minimum_direct_observations: int
    maximum_time_gap: float | None
    confidence: float
    support: float
    scoreable: bool
    score_points: float
    operational_severity: float
    anchor_floor: float
    correlation_group: str
    rule_rationale: str
    rule_semantic_digest: str
    decision_semantic_digest: str
    report_time_reevaluated: bool = False
    evidence_authority: str = "canonical_chain_decision_projection"
    schema_version: str = CHAIN_FINDING_SUMMARY_ROW_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ChainFindingSummaryRow:
            raise TypeError("chain_finding_summary_owner_invalid")
        if self.schema_version != CHAIN_FINDING_SUMMARY_ROW_SCHEMA_VERSION:
            raise ValueError("chain_finding_summary_schema_invalid")
        if self.record_keys != tuple(sorted(set(self.record_keys))) or not self.record_keys:
            raise ValueError("chain_finding_summary_record_keys_invalid")
        exact_content_sha256(self.content_sha256, "chain_finding_summary_content_sha256_invalid")
        for value in (
            self.registry_version, self.registry_digest, self.source_schema_version,
            self.chain_id, self.chain_name, self.chain_name_source, self.rule_version,
            self.family, self.decision_status, self.match_mode, self.order_provenance,
            self.resource_requirement_state, self.flow_requirement_state,
            self.correlation_group, self.evidence_authority,
            self.rule_semantic_digest, self.decision_semantic_digest,
        ):
            _text(value, "chain_finding_summary_text_invalid", maximum=_MAX_TEXT)
        _text(self.blocked_reason, "chain_finding_summary_blocked_reason_invalid", allow_blank=True)
        _text(self.rule_rationale, "chain_finding_summary_rationale_invalid", allow_blank=True)
        for value in (
            self.same_actor_required, self.same_target_required, self.same_artifact_required,
            self.same_host_required, self.same_process_required, self.same_connection_required,
            self.platform_match_required, self.same_resource_required, self.same_flow_required,
            self.scoreable, self.report_time_reevaluated,
        ):
            _bool(value, "chain_finding_summary_bool_invalid")
        if self.report_time_reevaluated:
            raise ValueError("chain_finding_summary_reevaluation_forbidden")
        _nonnegative_int(self.minimum_distinct_roots, "chain_finding_summary_minimum_roots_invalid")
        _nonnegative_int(self.minimum_direct_observations, "chain_finding_summary_minimum_direct_invalid")
        if self.maximum_time_gap is not None:
            _number(self.maximum_time_gap, "chain_finding_summary_time_gap_invalid")
        for value in (self.confidence, self.support, self.score_points, self.operational_severity, self.anchor_floor):
            _number(value, "chain_finding_summary_number_invalid")

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.to_record())

    def to_record(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class ChainFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    source_record_count: int
    evidence_record_count: int
    duplicate_alias_count: int
    source_rows: tuple[ChainEvidenceSummaryRow, ...]
    finding_rows: tuple[ChainFindingSummaryRow, ...]
    schema_version: str = CHAIN_FINDINGS_SUMMARY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not ChainFindingsSummary:
            raise TypeError("chain_findings_summary_owner_invalid")
        if self.schema_version != CHAIN_FINDINGS_SUMMARY_SCHEMA_VERSION:
            raise ValueError("chain_findings_summary_schema_invalid")
        _text(self.scan_id, "chain_findings_summary_scan_id_invalid", maximum=128)
        _text(self.snapshot_semantic_digest, "chain_findings_summary_snapshot_digest_invalid", maximum=64)
        _nonnegative_int(self.source_record_count, "chain_findings_summary_source_count_invalid")
        _nonnegative_int(self.evidence_record_count, "chain_findings_summary_evidence_count_invalid")
        _nonnegative_int(self.duplicate_alias_count, "chain_findings_summary_alias_count_invalid")
        if type(self.source_rows) is not tuple or any(type(row) is not ChainEvidenceSummaryRow for row in self.source_rows):
            raise TypeError("chain_findings_summary_source_rows_invalid")
        if type(self.finding_rows) is not tuple or any(type(row) is not ChainFindingSummaryRow for row in self.finding_rows):
            raise TypeError("chain_findings_summary_finding_rows_invalid")
        if self.evidence_record_count < len(self.source_rows):
            raise ValueError("chain_findings_summary_source_reconciliation_failed")
        if self.duplicate_alias_count != self.evidence_record_count - len(self.source_rows):
            raise ValueError("chain_findings_summary_alias_reconciliation_failed")

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def counts_record(self) -> dict[str, int]:
        statuses: dict[str, int] = {}
        for row in self.finding_rows:
            statuses[row.decision_status] = statuses.get(row.decision_status, 0) + 1
        return {
            "source_record_count": self.source_record_count,
            "evidence_record_count": self.evidence_record_count,
            "unique_evidence_count": len(self.source_rows),
            "duplicate_alias_count": self.duplicate_alias_count,
            "decision_count": len(self.finding_rows),
            "confirmed_count": statuses.get("confirmed", 0),
            "candidate_count": statuses.get("candidate", 0),
            "partial_count": statuses.get("partial", 0),
            "blocked_count": statuses.get("blocked", 0),
            "rejected_count": statuses.get("rejected", 0),
        }

    def core_record(self) -> dict[str, object]:
        return {
            "counts": self.counts_record(),
            "finding_rows": tuple(row.to_record() for row in self.finding_rows),
            "scan_id": self.scan_id,
            "schema_version": self.schema_version,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "source_rows": tuple(row.to_record() for row in self.source_rows),
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record


def _row_from_decision(
    *,
    record_keys: tuple[str, ...],
    content_sha256: str,
    registry_version: str,
    registry_digest: str,
    source_schema_version: str,
    decision: Mapping[str, object],
) -> ChainFindingSummaryRow:
    rule = _mapping(_mapping_value(decision, "rule"), "chain_summary_rule_missing")
    chain_id = _text(_mapping_value(decision, "chain_id"), "chain_summary_chain_id_invalid")
    rule_chain_id = _text(_mapping_value(rule, "chain_id"), "chain_summary_rule_chain_id_invalid")
    rule_version = _text(_mapping_value(decision, "rule_version"), "chain_summary_rule_version_invalid")
    if chain_id != rule_chain_id or rule_version != _mapping_value(rule, "version"):
        raise RuntimeError("chain_summary_rule_identity_mismatch:" + chain_id)
    family = _text(_mapping_value(decision, "family"), "chain_summary_family_invalid")
    if family != _mapping_value(rule, "family"):
        raise RuntimeError("chain_summary_rule_family_mismatch:" + chain_id)
    steps = _rule_steps(rule)
    required_steps = tuple(alternatives for alternatives, optional, _gap in steps if not optional)
    optional_steps = tuple(alternatives for alternatives, optional, _gap in steps if optional)
    event_fields = _matched_event_fields(decision)
    missing = _int_tuple(_mapping_value(decision, "missing_step_indexes", ()), "chain_summary_missing_steps_invalid", limit=64)
    rule_record = no_hook_materialize(rule, max_depth=16, max_items=4096, reason_prefix="chain_summary_rule")
    decision_record = no_hook_materialize(decision, max_depth=24, max_items=10_000, reason_prefix="chain_summary_decision")
    required_fields = _text_tuple(_mapping_value(rule, "required_fields", ()), "chain_summary_required_fields_invalid", limit=64, sorted_unique=True)
    decision_status = _text(_mapping_value(decision, "status"), "chain_summary_status_invalid")
    if decision_status not in CHAIN_DECISION_STATUSES:
        raise RuntimeError("chain_summary_status_invalid:" + chain_id)
    match_mode = _text(_mapping_value(rule, "match_mode"), "chain_summary_match_mode_invalid")
    if match_mode not in CHAIN_MATCH_MODES:
        raise RuntimeError("chain_summary_match_mode_invalid:" + chain_id)
    order_provenance = _text(_mapping_value(decision, "order_class"), "chain_summary_order_invalid")
    if order_provenance not in CHAIN_ORDER_CLASSES:
        raise RuntimeError("chain_summary_order_invalid:" + chain_id)
    return ChainFindingSummaryRow(
        record_keys=record_keys,
        content_sha256=content_sha256,
        registry_version=registry_version,
        registry_digest=registry_digest,
        source_schema_version=source_schema_version,
        chain_id=chain_id,
        chain_name=chain_id,
        chain_name_source="canonical_chain_id",
        rule_version=rule_version,
        family=family,
        decision_status=decision_status,
        match_mode=match_mode,
        order_provenance=order_provenance,
        required_steps=required_steps,
        optional_steps=optional_steps,
        optional_evidence=_text_tuple(_mapping_value(rule, "optional_evidence", ()), "chain_summary_optional_evidence_invalid", limit=64),
        forbidden_evidence=_text_tuple(_mapping_value(rule, "forbidden_evidence", ()), "chain_summary_forbidden_evidence_invalid", limit=64),
        matched_step_indexes=event_fields["matched_step_indexes"],
        missing_step_indexes=missing,
        unmet_requirements=_text_tuple(_mapping_value(decision, "unmet_requirements", ()), "chain_summary_unmet_requirements_invalid", limit=64, sorted_unique=True),
        blocked_reason=_text(_mapping_value(decision, "blocked_reason", ""), "chain_summary_blocked_reason_invalid", allow_blank=True),
        root_evidence_ids=event_fields["root_evidence_ids"],
        matched_evidence_ids=event_fields["matched_evidence_ids"],
        operation_ids=event_fields["operation_ids"],
        actor_identities=event_fields["actor_identities"],
        target_identities=event_fields["target_identities"],
        artifact_identities=event_fields["artifact_identities"],
        process_identities=event_fields["process_identities"],
        host_identities=event_fields["host_identities"],
        connection_identities=event_fields["connection_identities"],
        event_correlation_groups=event_fields["event_correlation_groups"],
        same_actor_required=_bool(_mapping_value(rule, "same_actor"), "chain_summary_same_actor_invalid"),
        same_target_required=_bool(_mapping_value(rule, "same_target"), "chain_summary_same_target_invalid"),
        same_artifact_required=_bool(_mapping_value(rule, "same_artifact"), "chain_summary_same_artifact_invalid"),
        same_host_required=_bool(_mapping_value(rule, "same_host"), "chain_summary_same_host_invalid"),
        same_process_required=_bool(_mapping_value(rule, "same_process"), "chain_summary_same_process_invalid"),
        same_connection_required=_bool(_mapping_value(rule, "same_connection"), "chain_summary_same_connection_invalid"),
        platform_match_required=_bool(_mapping_value(rule, "platform_match"), "chain_summary_platform_match_invalid"),
        same_resource_required=False,
        resource_requirement_state=("represented_by_target_identity" if "target_identity" in required_fields else "not_declared_by_current_chain_rule_contract"),
        same_flow_required=False,
        flow_requirement_state="not_declared_by_current_chain_rule_contract",
        required_platforms=_text_tuple(_mapping_value(rule, "required_platforms", ()), "chain_summary_platforms_invalid", limit=32, sorted_unique=True),
        required_modalities=_text_tuple(_mapping_value(rule, "required_modalities", ()), "chain_summary_modalities_invalid", limit=32, sorted_unique=True),
        required_fields=required_fields,
        minimum_distinct_roots=_nonnegative_int(_mapping_value(rule, "minimum_distinct_roots"), "chain_summary_min_roots_invalid"),
        minimum_direct_observations=_nonnegative_int(_mapping_value(rule, "minimum_direct_observations", 0), "chain_summary_min_direct_invalid"),
        maximum_time_gap=(None if _mapping_value(rule, "maximum_time_gap") is None else _number(_mapping_value(rule, "maximum_time_gap"), "chain_summary_max_gap_invalid")),
        confidence=_number(_mapping_value(decision, "confidence"), "chain_summary_confidence_invalid"),
        support=_number(_mapping_value(decision, "support"), "chain_summary_support_invalid"),
        scoreable=_bool(_mapping_value(decision, "scoreable"), "chain_summary_scoreable_invalid"),
        score_points=_number(_mapping_value(decision, "score_points"), "chain_summary_score_points_invalid"),
        operational_severity=_number(_mapping_value(decision, "operational_severity"), "chain_summary_severity_invalid"),
        anchor_floor=_number(_mapping_value(decision, "anchor_floor"), "chain_summary_anchor_floor_invalid"),
        correlation_group=_text(_mapping_value(decision, "correlation_group"), "chain_summary_correlation_group_invalid"),
        rule_rationale=_text(_mapping_value(rule, "rationale", ""), "chain_summary_rationale_invalid", allow_blank=True),
        rule_semantic_digest=canonical_json_sha256(rule_record),
        decision_semantic_digest=canonical_json_sha256(decision_record),
    )


def build_chain_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
) -> ChainFindingsSummary:
    scan_id_text = _text(scan_id, "chain_findings_summary_scan_id_invalid", maximum=128)
    snapshot_digest = _text(snapshot_semantic_digest, "chain_findings_summary_snapshot_digest_invalid", maximum=64)
    items = no_hook_mapping_items(local_results)
    if items is None or len(items) > _MAX_RECORDS:
        raise TypeError("chain_findings_summary_local_results_invalid")
    source_record_count = len(items)
    evidence_record_count = 0
    source_groups: dict[tuple[str, str], dict[str, object]] = {}
    registry_identity: tuple[str, str] | None = None
    for raw_key, record in items:
        record_key = _text(raw_key, "chain_summary_record_key_invalid")
        evidence = _source_chain_evidence(record, record_key)
        if evidence is None:
            continue
        evidence_record_count += 1
        content_sha256 = final_record_content_sha256(
            record,
            "chain_summary_content_sha256_invalid:" + record_key,
        )
        registry_version = _text(dict.get(evidence, "registry_version"), "chain_summary_registry_version_invalid")
        registry_digest = _text(dict.get(evidence, "registry_digest"), "chain_summary_registry_digest_invalid")
        current_identity = (registry_version, registry_digest)
        if registry_identity is None:
            registry_identity = current_identity
        elif current_identity != registry_identity:
            raise RuntimeError("chain_summary_registry_conflict")
        digest = canonical_json_sha256(evidence)
        source_identity = (content_sha256, digest)
        group = source_groups.get(source_identity)
        if group is None:
            source_groups[source_identity] = {
                "content_sha256": content_sha256,
                "evidence": evidence,
                "record_keys": {record_key},
            }
        else:
            group["record_keys"].add(record_key)

    source_rows: list[ChainEvidenceSummaryRow] = []
    decisions_by_digest: dict[tuple[str, str], dict[str, object]] = {}
    physical_decision_digest: dict[tuple[object, ...], str] = {}
    for (content_sha256, evidence_digest), group in sorted(source_groups.items()):
        evidence = group["evidence"]
        record_keys = tuple(sorted(group["record_keys"]))
        decisions = _sequence(dict.get(evidence, "decisions", ()), "chain_summary_decisions_invalid", limit=256)
        failures = _sequence(dict.get(evidence, "failure_evidence", ()), "chain_summary_failures_invalid", limit=64)
        source_rows.append(ChainEvidenceSummaryRow(
            record_keys=record_keys,
            content_sha256=content_sha256,
            registry_version=_text(dict.get(evidence, "registry_version"), "chain_summary_registry_version_invalid"),
            registry_digest=_text(dict.get(evidence, "registry_digest"), "chain_summary_registry_digest_invalid"),
            source_schema_version=_text(dict.get(evidence, "schema_version"), "chain_summary_source_schema_invalid"),
            decision_count=len(decisions),
            failure_count=len(failures),
            degraded=_bool(dict.get(evidence, "degraded"), "chain_summary_degraded_invalid"),
            evidence_semantic_digest=evidence_digest,
        ))
        for raw_decision in decisions:
            decision = _mapping(raw_decision, "chain_summary_decision_invalid")
            decision_digest = canonical_json_sha256(no_hook_materialize(
                decision, max_depth=24, max_items=10_000, reason_prefix="chain_summary_decision",
            ))
            chain_id = _text(dict.get(decision, "chain_id"), "chain_summary_chain_id_invalid")
            roots = _text_tuple(dict.get(decision, "root_evidence_ids", ()), "chain_summary_root_ids_invalid", sorted_unique=True)
            matched_ids = _text_tuple(dict.get(decision, "matched_evidence_ids", ()), "chain_summary_matched_ids_invalid")
            physical_key = (
                content_sha256,
                _text(dict.get(evidence, "registry_digest"), "chain_summary_registry_digest_invalid"),
                chain_id,
                roots,
                matched_ids,
            )
            prior = physical_decision_digest.get(physical_key)
            if prior is not None and prior != decision_digest:
                raise RuntimeError("chain_summary_physical_decision_conflict:" + chain_id)
            physical_decision_digest[physical_key] = decision_digest
            decision_identity = (content_sha256, decision_digest)
            group_decision = decisions_by_digest.get(decision_identity)
            if group_decision is None:
                decisions_by_digest[decision_identity] = {
                    "content_sha256": content_sha256,
                    "decision": decision,
                    "record_keys": set(record_keys),
                    "registry_version": dict.get(evidence, "registry_version"),
                    "registry_digest": dict.get(evidence, "registry_digest"),
                    "source_schema_version": dict.get(evidence, "schema_version"),
                }
            else:
                group_decision["record_keys"].update(record_keys)

    finding_rows = tuple(sorted((
        _row_from_decision(
            record_keys=tuple(sorted(group["record_keys"])),
            content_sha256=exact_content_sha256(group["content_sha256"], "chain_summary_content_sha256_invalid"),
            registry_version=_text(group["registry_version"], "chain_summary_registry_version_invalid"),
            registry_digest=_text(group["registry_digest"], "chain_summary_registry_digest_invalid"),
            source_schema_version=_text(group["source_schema_version"], "chain_summary_source_schema_invalid"),
            decision=group["decision"],
        )
        for group in decisions_by_digest.values()
    ), key=lambda row: (
        row.content_sha256,
        row.chain_id,
        row.root_evidence_ids,
        row.decision_status,
        row.decision_semantic_digest,
    )))
    return ChainFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=snapshot_digest,
        source_record_count=source_record_count,
        evidence_record_count=evidence_record_count,
        duplicate_alias_count=evidence_record_count - len(source_rows),
        source_rows=tuple(source_rows),
        finding_rows=finding_rows,
    )


def chain_findings_json_bytes(summary: ChainFindingsSummary) -> bytes:
    if type(summary) is not ChainFindingsSummary:
        raise TypeError("chain_findings_summary_required")
    return (json.dumps(summary.to_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def chain_findings_markdown_bytes(summary: ChainFindingsSummary) -> bytes:
    if type(summary) is not ChainFindingsSummary:
        raise TypeError("chain_findings_summary_required")
    counts = summary.counts_record()
    lines = [
        "# Chain Findings Summary",
        "",
        f"- Scan ID: `{summary.scan_id}`",
        f"- Snapshot semantic digest: `{summary.snapshot_semantic_digest}`",
        f"- Summary semantic digest: `{summary.semantic_digest}`",
        f"- Decisions: {counts['decision_count']}",
        f"- Confirmed / candidate / partial / blocked / rejected: {counts['confirmed_count']} / {counts['candidate_count']} / {counts['partial_count']} / {counts['blocked_count']} / {counts['rejected_count']}",
        "- Projection policy: final canonical Chain decisions only; no report-time reevaluation.",
        "",
        "| Content SHA-256 | Chain | Status | Order | Roots | Operations | Score | Requirements |",
        "|---|---|---|---|---:|---:|---:|---|",
    ]
    for row in summary.finding_rows:
        requirements = ", ".join(row.unmet_requirements) or "satisfied/none-recorded"
        lines.append(
            "| " + " | ".join((
                _md(row.content_sha256), _md(row.chain_id), _md(row.decision_status), _md(row.order_provenance),
                str(len(row.root_evidence_ids)), str(len(row.operation_ids)),
                _md(row.score_points), _md(requirements),
            )) + " |"
        )
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def chain_findings_csv_bytes(summary: ChainFindingsSummary) -> bytes:
    if type(summary) is not ChainFindingsSummary:
        raise TypeError("chain_findings_summary_required")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow((
        "content_sha256", "chain_id", "chain_name", "rule_version", "family", "decision_status", "match_mode",
        "order_provenance", "root_evidence_ids", "matched_evidence_ids", "operation_ids",
        "missing_step_indexes", "unmet_requirements", "same_artifact_required",
        "same_target_required", "same_process_required", "same_resource_required",
        "resource_requirement_state", "same_flow_required", "flow_requirement_state",
        "required_fields", "required_platforms", "required_modalities", "confidence", "support",
        "scoreable", "score_points", "operational_severity", "anchor_floor",
        "rule_semantic_digest", "decision_semantic_digest", "record_keys",
    ))
    for row in summary.finding_rows:
        writer.writerow((
            row.content_sha256, row.chain_id, row.chain_name, row.rule_version, row.family, row.decision_status,
            row.match_mode, row.order_provenance, json.dumps(row.root_evidence_ids),
            json.dumps(row.matched_evidence_ids), json.dumps(row.operation_ids),
            json.dumps(row.missing_step_indexes), json.dumps(row.unmet_requirements),
            row.same_artifact_required, row.same_target_required, row.same_process_required,
            row.same_resource_required, row.resource_requirement_state, row.same_flow_required,
            row.flow_requirement_state, json.dumps(row.required_fields), json.dumps(row.required_platforms),
            json.dumps(row.required_modalities), row.confidence, row.support, row.scoreable,
            row.score_points, row.operational_severity, row.anchor_floor, row.rule_semantic_digest,
            row.decision_semantic_digest, json.dumps(row.record_keys),
        ))
    return stream.getvalue().encode("utf-8")


def render_chain_findings_summary(summary: ChainFindingsSummary) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not ChainFindingsSummary:
        raise TypeError("chain_findings_summary_required")
    return (
        ("chain_findings_summary.json", chain_findings_json_bytes(summary)),
        ("chain_findings_summary.md", chain_findings_markdown_bytes(summary)),
        ("chain_findings_summary.csv", chain_findings_csv_bytes(summary)),
    )


__all__ = (
    "CHAIN_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION",
    "CHAIN_FINDING_SUMMARY_ROW_SCHEMA_VERSION",
    "CHAIN_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "ChainEvidenceSummaryRow",
    "ChainFindingSummaryRow",
    "ChainFindingsSummary",
    "build_chain_findings_summary",
    "render_chain_findings_summary",
)
