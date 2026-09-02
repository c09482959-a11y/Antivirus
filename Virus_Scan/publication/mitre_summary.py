"""Canonical projection-only MITRE ATT&CK findings summary.

The projector consumes only final immutable ``model_evidence.mitre_evidence``,
``canonical_chain_evidence``, and ``attack_explainability`` records already owned
by ``ScanPublicationSnapshot``.
It does not import ATT&CK registries, the repository owner, the mapper, calibration
owners, or Chain evaluators.  Report-time code may validate and project the frozen
records, but it may not recompute ATT&CK or Chain decisions.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
import io
import json
from typing import Mapping

from Virus_Scan.contracts.canonical_json import canonical_json_sha256
from Virus_Scan.contracts.chain_evidence import CHAIN_EVIDENCE_SCHEMA_VERSION
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
)
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.api.attack_explainability_contracts import (
    ATTACK_EXPLAINABILITY_SCHEMA_VERSION,
)
from Virus_Scan.detection.api.attack_mapping_contracts import ATTACK_MAPPING_SCHEMA_VERSION
from Virus_Scan.publication.content_identity import (
    exact_content_sha256,
    final_record_content_sha256,
)

MITRE_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION = "mitre_evidence_summary_row_v2"
MITRE_FINDING_SUMMARY_ROW_SCHEMA_VERSION = "mitre_finding_summary_row_v4"
MITRE_FINDINGS_SUMMARY_SCHEMA_VERSION = "mitre_findings_summary_v4"
_MAX_RECORDS = 200_000
_MAX_ITEMS = 512
_MAX_TEXT = 4096
_STATUSES = ("confirmed", "candidate", "rejected", "unavailable")


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


def _text_tuple(
    value: object,
    reason: str,
    *,
    limit: int = _MAX_ITEMS,
    sorted_unique: bool = False,
) -> tuple[str, ...]:
    values = tuple(_text(item, reason) for item in _sequence(value, reason, limit=limit))
    if sorted_unique and values != tuple(sorted(set(values))):
        raise ValueError(reason)
    return values


def _source_mitre_evidence(record: object, record_key: str) -> dict[str, object] | None:
    model = _mapping_value(record, "model_evidence")
    if model is None:
        return None
    evidence = _mapping_value(model, "mitre_evidence")
    if evidence is None:
        return None
    materialized = no_hook_materialize(
        evidence,
        max_depth=32,
        max_items=40_000,
        reason_prefix="mitre_summary_source",
    )
    if type(materialized) is not dict:
        raise RuntimeError("mitre_summary_source_invalid:" + record_key)
    if dict.get(materialized, "schema_version") != ATTACK_MAPPING_SCHEMA_VERSION:
        raise RuntimeError("mitre_summary_source_schema_invalid:" + record_key)
    if dict.get(materialized, "mapping_scope") != "official_attack_techniques":
        raise RuntimeError("mitre_summary_mapping_scope_invalid:" + record_key)
    ready = dict.get(materialized, "ready")
    claimed = dict.get(materialized, "technique_ids_claimed")
    if type(ready) is not bool or type(claimed) is not bool:
        raise RuntimeError("mitre_summary_readiness_invalid:" + record_key)
    bucket_counts: dict[str, int] = {}
    seen_ids: set[str] = set()
    for status in _STATUSES:
        bucket = _sequence(dict.get(materialized, status, ()), "mitre_summary_decisions_invalid", limit=128)
        bucket_counts[status] = len(bucket)
        for raw in bucket:
            decision = _mapping(raw, "mitre_summary_decision_invalid")
            if dict.get(decision, "status") != status:
                raise RuntimeError("mitre_summary_decision_status_invalid:" + record_key)
            technique_id = _text(dict.get(decision, "technique_id"), "mitre_summary_technique_id_invalid", maximum=16)
            if technique_id in seen_ids:
                raise RuntimeError("mitre_summary_duplicate_technique:" + record_key)
            seen_ids.add(technique_id)
            _validate_decision_metadata(decision, record_key)
    if ready and not seen_ids:
        raise RuntimeError("mitre_summary_ready_without_decisions:" + record_key)
    if not ready and seen_ids:
        raise RuntimeError("mitre_summary_unavailable_with_decisions:" + record_key)
    if claimed is not bool(bucket_counts["confirmed"]):
        raise RuntimeError("mitre_summary_claimed_state_invalid:" + record_key)
    probability = _number(dict.get(materialized, "probability"), "mitre_summary_probability_invalid")
    unavailable = _text(
        dict.get(materialized, "unavailable_reason", ""),
        "mitre_summary_unavailable_reason_invalid",
        allow_blank=True,
        maximum=256,
    )
    probability_unavailable = _text(
        dict.get(materialized, "probability_unavailable_reason", ""),
        "mitre_summary_probability_unavailable_invalid",
        allow_blank=True,
        maximum=256,
    )
    if ready and unavailable:
        raise RuntimeError("mitre_summary_ready_unavailable_conflict:" + record_key)
    if not ready and (not unavailable or probability != 0.0):
        raise RuntimeError("mitre_summary_unavailable_state_invalid:" + record_key)
    if ready and probability == 0.0 and not probability_unavailable:
        raise RuntimeError("mitre_summary_probability_state_invalid:" + record_key)
    repository_status = _mapping(dict.get(materialized, "repository_status"), "mitre_summary_repository_status_invalid")
    if ready:
        _text(dict.get(materialized, "repository_digest"), "mitre_summary_repository_digest_invalid", maximum=64)
        _text(dict.get(materialized, "dataset_version"), "mitre_summary_dataset_invalid", maximum=40)
    return materialized


def _validate_decision_metadata(decision: Mapping[str, object], record_key: str) -> None:
    _text(dict.get(decision, "technique_name"), "mitre_summary_technique_name_invalid", maximum=256)
    _text(dict.get(decision, "parent_technique_id", ""), "mitre_summary_parent_id_invalid", allow_blank=True, maximum=16)
    _text(dict.get(decision, "parent_technique_name", ""), "mitre_summary_parent_name_invalid", allow_blank=True, maximum=256)
    tactic_ids = _text_tuple(dict.get(decision, "tactic_ids", ()), "mitre_summary_tactic_ids_invalid", limit=32)
    tactic_names = _text_tuple(dict.get(decision, "tactic_names", ()), "mitre_summary_tactic_names_invalid", limit=32)
    if len(tactic_ids) != len(tactic_names):
        raise RuntimeError("mitre_summary_tactic_metadata_mismatch:" + record_key)
    for field, limit in (
        ("policy_implementation_ids", 16),
        ("required_chain_ids", 64),
        ("required_data_component_ids", 64),
        ("required_platforms", 64),
        ("required_modalities", 32),
        ("implementation_requirement_digests", 32),
        ("implementation_evaluation_manifest_digests", 32),
        ("strategy_ids", 16),
        ("analytic_ids", 16),
        ("implementation_ids", 16),
        ("claim_scopes", 16),
        ("evidence_ids", 128),
        ("root_evidence_ids", 128),
        ("rejected_evidence_ids", 128),
        ("missing_requirements", 128),
        ("observed_data_component_ids", 64),
        ("unavailable_fields", 128),
        ("policy_requirement_digest_set", 32),
    ):
        _text_tuple(dict.get(decision, field, ()), "mitre_summary_decision_field_invalid:" + field, limit=limit)
    for field in (
        "policy_admission_state",
        "policy_version",
        "parent_scoring_policy",
        "correlation_group",
        "probability_unavailable_reason",
        "policy_evaluation_manifest_digest",
        "policy_calibration_artifact_id",
        "calibration_artifact_id",
        "rejection_reason",
        "unavailable_reason",
    ):
        _text(dict.get(decision, field, ""), "mitre_summary_decision_text_invalid:" + field, allow_blank=True, maximum=256)
    _bool(dict.get(decision, "execution_observed"), "mitre_summary_execution_observed_invalid")
    _bool(dict.get(decision, "revoked"), "mitre_summary_revoked_invalid")
    _bool(dict.get(decision, "deprecated"), "mitre_summary_deprecated_invalid")
    for field in ("direct_evidence_count", "inferred_evidence_count", "support"):
        _nonnegative_int(dict.get(decision, field), "mitre_summary_decision_count_invalid:" + field)
    _number(dict.get(decision, "evidence_completeness"), "mitre_summary_completeness_invalid")
    _number(dict.get(decision, "probability"), "mitre_summary_decision_probability_invalid")


def _attack_explainability_index(
    record: object,
    record_key: str,
    *,
    required: bool,
) -> tuple[dict[str, dict[str, object]], str]:
    raw = _mapping_value(record, "attack_explainability")
    if raw is None:
        if required:
            raise RuntimeError("mitre_summary_attack_explainability_required:" + record_key)
        return {}, ""
    materialized = no_hook_materialize(
        raw, max_depth=40, max_items=80_000, reason_prefix="mitre_summary_attack_explainability",
    )
    if type(materialized) is not dict:
        raise RuntimeError("mitre_summary_attack_explainability_invalid:" + record_key)
    if dict.get(materialized, "schema_version") != ATTACK_EXPLAINABILITY_SCHEMA_VERSION:
        raise RuntimeError("mitre_summary_attack_explainability_schema_invalid:" + record_key)
    if dict.get(materialized, "projection_role") != "explainability_only":
        raise RuntimeError("mitre_summary_attack_explainability_role_invalid:" + record_key)
    if dict.get(materialized, "official_decision_effect") != "none":
        raise RuntimeError("mitre_summary_attack_explainability_authority_invalid:" + record_key)
    semantic_digest = _text(
        dict.get(materialized, "semantic_digest"),
        "mitre_summary_attack_explainability_digest_invalid", maximum=64,
    )
    core = dict(materialized)
    core.pop("semantic_digest", None)
    if canonical_json_sha256(core) != semantic_digest:
        raise RuntimeError("mitre_summary_attack_explainability_digest_mismatch:" + record_key)
    out: dict[str, dict[str, object]] = {}
    for raw_decision in _sequence(
        dict.get(materialized, "decisions", ()),
        "mitre_summary_attack_explainability_decisions_invalid", limit=128,
    ):
        decision = _mapping(raw_decision, "mitre_summary_attack_explainability_decision_invalid")
        technique_id = _text(
            dict.get(decision, "technique_id"),
            "mitre_summary_attack_explainability_technique_invalid", maximum=16,
        )
        if technique_id in out:
            raise RuntimeError("mitre_summary_attack_explainability_duplicate:" + technique_id)
        out[technique_id] = decision
    return out, semantic_digest


def _attack_explainability_fields(
    explanation: Mapping[str, object],
    decision: Mapping[str, object],
    record_key: str,
) -> dict[str, object]:
    technique_id = _text(dict.get(decision, "technique_id"), "mitre_summary_technique_id_invalid", maximum=16)
    if _text(dict.get(explanation, "technique_id"), "mitre_summary_explainability_technique_invalid", maximum=16) != technique_id:
        raise RuntimeError("mitre_summary_attack_explainability_technique_conflict:" + technique_id)
    if _text(dict.get(explanation, "status"), "mitre_summary_explainability_status_invalid", maximum=16) != dict.get(decision, "status"):
        raise RuntimeError("mitre_summary_attack_explainability_status_conflict:" + technique_id)
    if _bool(dict.get(explanation, "execution_observed"), "mitre_summary_explainability_execution_invalid") != dict.get(decision, "execution_observed"):
        raise RuntimeError("mitre_summary_attack_explainability_execution_conflict:" + technique_id)
    explanation_roots = _text_tuple(
        tuple(
            _mapping(raw, "mitre_summary_explainability_root_invalid").get("root_evidence_id")
            for raw in _sequence(dict.get(explanation, "physical_roots", ()), "mitre_summary_explainability_roots_invalid", limit=128)
        ),
        "mitre_summary_explainability_root_id_invalid", limit=128, sorted_unique=True,
    )
    decision_roots = _text_tuple(dict.get(decision, "root_evidence_ids", ()), "mitre_summary_root_ids_invalid", limit=128, sorted_unique=True)
    if explanation_roots != decision_roots:
        raise RuntimeError("mitre_summary_attack_explainability_root_conflict:" + technique_id)

    bindings: set[str] = set()
    relations: set[str] = set()
    derivations: set[str] = set()
    for raw_requirement in _sequence(dict.get(explanation, "requirements", ()), "mitre_summary_explainability_requirements_invalid", limit=64):
        requirement = _mapping(raw_requirement, "mitre_summary_explainability_requirement_invalid")
        chain_id = _text(dict.get(requirement, "chain_id"), "mitre_summary_explainability_chain_invalid")
        satisfied = _bool(dict.get(requirement, "satisfied"), "mitre_summary_explainability_satisfied_invalid")
        roots = _text_tuple(dict.get(requirement, "root_evidence_ids", ()), "mitre_summary_explainability_requirement_roots_invalid", limit=128, sorted_unique=True)
        if not roots:
            bindings.add(chain_id + "|satisfied=" + str(satisfied).lower() + "|root=")
        for root in roots:
            bindings.add(chain_id + "|satisfied=" + str(satisfied).lower() + "|root=" + root)
        for raw_relation in _sequence(dict.get(requirement, "relation_requirements", ()), "mitre_summary_explainability_relations_invalid", limit=64):
            materialized = no_hook_materialize(raw_relation, max_depth=12, max_items=512, reason_prefix="mitre_summary_relation")
            if type(materialized) is not dict:
                raise RuntimeError("mitre_summary_explainability_relation_invalid:" + record_key)
            relations.add(chain_id + "|" + json.dumps(materialized, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        derivations.add(chain_id + "|" + _text(dict.get(requirement, "chain_status"), "mitre_summary_explainability_chain_status_invalid", maximum=16))

    root_sources: set[str] = set()
    for raw_root in _sequence(dict.get(explanation, "physical_roots", ()), "mitre_summary_explainability_roots_invalid", limit=128):
        root = _mapping(raw_root, "mitre_summary_explainability_root_invalid")
        root_id = _text(dict.get(root, "root_evidence_id"), "mitre_summary_explainability_root_id_invalid", maximum=128)
        source_kind = _text(dict.get(root, "source_kind"), "mitre_summary_explainability_root_kind_invalid", maximum=64)
        owner = dict.get(root, "producer_id") if source_kind == "physical_observation" else dict.get(root, "rule_name")
        owner_text = _text(owner, "mitre_summary_explainability_root_owner_invalid", allow_blank=True, maximum=256)
        root_sources.add(root_id + "|" + source_kind + "|" + owner_text)

    yara = _mapping(dict.get(explanation, "yara"), "mitre_summary_explainability_yara_invalid")
    yara_role = _text(dict.get(yara, "role"), "mitre_summary_explainability_yara_role_invalid", maximum=32)
    if yara_role not in {"corroborated", "not_used", "absent"}:
        raise RuntimeError("mitre_summary_explainability_yara_role_invalid:" + technique_id)
    yara_roots = _text_tuple(dict.get(yara, "used_root_evidence_ids", ()), "mitre_summary_explainability_yara_roots_invalid", limit=128, sorted_unique=True)

    model = _mapping(dict.get(explanation, "model_assistance"), "mitre_summary_explainability_model_invalid")
    evidence_authority = _text(dict.get(model, "evidence_authority"), "mitre_summary_explainability_model_authority_invalid", maximum=32)
    decision_effect = _text(dict.get(model, "official_decision_effect"), "mitre_summary_explainability_model_effect_invalid", maximum=32)
    if evidence_authority != "context_only" or decision_effect != "none":
        raise RuntimeError("mitre_summary_attack_explainability_model_authority_conflict:" + technique_id)
    query_ids: set[str] = set()
    for raw_query in _sequence(dict.get(model, "discovery_queries", ()), "mitre_summary_explainability_queries_invalid", limit=512):
        query = _mapping(raw_query, "mitre_summary_explainability_query_invalid")
        query_ids.add(_text(dict.get(query, "query_id"), "mitre_summary_explainability_query_id_invalid", maximum=96))

    materialized_explanation = no_hook_materialize(explanation, max_depth=32, max_items=40_000, reason_prefix="mitre_summary_explainability_decision")
    if type(materialized_explanation) is not dict:
        raise RuntimeError("mitre_summary_explainability_decision_materialization_invalid")
    return {
        "authority_requirement_root_bindings": tuple(sorted(bindings)),
        "authority_relation_requirements": tuple(sorted(relations)),
        "physical_root_provenance": tuple(sorted(root_sources)),
        "deterministic_derivations": tuple(sorted(derivations)),
        "yara_role": yara_role,
        "yara_used_root_evidence_ids": yara_roots,
        "model_assistance_evidence_authority": evidence_authority,
        "model_assistance_official_decision_effect": decision_effect,
        "model_assistance_discovery_query_ids": tuple(sorted(query_ids)),
        "authority_chain_semantic_digest": canonical_json_sha256(materialized_explanation),
    }


def _chain_index(record: object, record_key: str) -> dict[str, dict[str, object]]:
    raw = _mapping_value(record, "canonical_chain_evidence")
    if raw is None:
        return {}
    materialized = no_hook_materialize(raw, max_depth=32, max_items=30_000, reason_prefix="mitre_summary_chain")
    if type(materialized) is not dict or dict.get(materialized, "schema_version") != CHAIN_EVIDENCE_SCHEMA_VERSION:
        raise RuntimeError("mitre_summary_chain_source_invalid:" + record_key)
    out: dict[str, dict[str, object]] = {}
    for raw_decision in _sequence(dict.get(materialized, "decisions", ()), "mitre_summary_chain_decisions_invalid", limit=256):
        decision = _mapping(raw_decision, "mitre_summary_chain_decision_invalid")
        chain_id = _text(dict.get(decision, "chain_id"), "mitre_summary_chain_id_invalid")
        if chain_id in out:
            raise RuntimeError("mitre_summary_chain_duplicate:" + chain_id)
        out[chain_id] = decision
    return out


def _chain_requirements(
    required_chain_ids: tuple[str, ...],
    chain_index: Mapping[str, dict[str, object]],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    states: set[str] = set()
    required_terms: set[str] = set()
    optional_terms: set[str] = set()
    forbidden_terms: set[str] = set()
    operation_ids: set[str] = set()
    for chain_id in required_chain_ids:
        decision = chain_index.get(chain_id)
        if decision is None:
            states.add(chain_id + "=not_present_in_final_chain_evidence")
            continue
        status = _text(dict.get(decision, "status"), "mitre_summary_chain_status_invalid", maximum=16)
        states.add(chain_id + "=" + status)
        rule = _mapping(dict.get(decision, "rule"), "mitre_summary_chain_rule_invalid")
        for raw_step in _sequence(dict.get(rule, "steps", ()), "mitre_summary_chain_steps_invalid", limit=64):
            step = _mapping(raw_step, "mitre_summary_chain_step_invalid")
            alternatives = _text_tuple(dict.get(step, "alternatives", ()), "mitre_summary_chain_terms_invalid", limit=32)
            optional = _bool(dict.get(step, "optional"), "mitre_summary_chain_optional_invalid")
            (optional_terms if optional else required_terms).update(alternatives)
        optional_terms.update(_text_tuple(dict.get(rule, "optional_evidence", ()), "mitre_summary_optional_evidence_invalid", limit=64))
        forbidden_terms.update(_text_tuple(dict.get(rule, "forbidden_evidence", ()), "mitre_summary_forbidden_evidence_invalid", limit=64))
        for raw_step in _sequence(dict.get(decision, "matched_steps", ()), "mitre_summary_matched_steps_invalid", limit=64):
            step = _mapping(raw_step, "mitre_summary_matched_step_invalid")
            event = _mapping(dict.get(step, "event"), "mitre_summary_chain_event_invalid")
            location = _mapping_value(event, "source_location")
            location_items = no_hook_mapping_items(location)
            if location_items is None:
                continue
            location_map = {key: item for key, item in location_items if type(key) is str}
            if dict.get(location_map, "location_type") == "static_operation":
                event_id = dict.get(location_map, "event_id")
                if type(event_id) is str and event_id:
                    operation_ids.add(str.__str__(event_id))
    return (
        tuple(sorted(states)),
        tuple(sorted(required_terms)),
        tuple(sorted(optional_terms)),
        tuple(sorted(forbidden_terms)),
        tuple(sorted(operation_ids)),
    )


@dataclass(frozen=True, slots=True)
class MitreEvidenceSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    ready: bool
    repository_digest: str
    dataset_version: str
    policy_version: str
    evaluation_provenance: str
    probability: float
    probability_unavailable_reason: str
    unavailable_reason: str
    repository_status_semantic_digest: str
    evidence_semantic_digest: str
    schema_version: str = MITRE_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION

    def to_record(self) -> dict[str, object]:
        exact_content_sha256(self.content_sha256, "mitre_evidence_summary_content_sha256_invalid")
        return {
            "record_keys": self.record_keys,
            "content_sha256": self.content_sha256,
            "ready": self.ready,
            "repository_digest": self.repository_digest,
            "dataset_version": self.dataset_version,
            "policy_version": self.policy_version,
            "evaluation_provenance": self.evaluation_provenance,
            "probability": self.probability,
            "probability_unavailable_reason": self.probability_unavailable_reason,
            "unavailable_reason": self.unavailable_reason,
            "repository_status_semantic_digest": self.repository_status_semantic_digest,
            "evidence_semantic_digest": self.evidence_semantic_digest,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class MitreFindingSummaryRow:
    record_keys: tuple[str, ...]
    content_sha256: str
    repository_digest: str
    dataset_version: str
    repository_status_semantic_digest: str
    technique_id: str
    technique_name: str
    parent_technique_id: str
    parent_technique_name: str
    tactic_ids: tuple[str, ...]
    tactic_names: tuple[str, ...]
    decision_status: str
    claim_scopes: tuple[str, ...]
    execution_observed: bool
    policy_implementation_ids: tuple[str, ...]
    implementation_ids: tuple[str, ...]
    strategy_ids: tuple[str, ...]
    analytic_ids: tuple[str, ...]
    required_data_component_ids: tuple[str, ...]
    observed_data_component_ids: tuple[str, ...]
    required_chain_ids: tuple[str, ...]
    required_chain_states: tuple[str, ...]
    required_evidence_terms: tuple[str, ...]
    optional_evidence_terms: tuple[str, ...]
    forbidden_evidence_terms: tuple[str, ...]
    operation_ids: tuple[str, ...]
    required_platforms: tuple[str, ...]
    required_modalities: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    root_evidence_ids: tuple[str, ...]
    rejected_evidence_ids: tuple[str, ...]
    missing_requirements: tuple[str, ...]
    unavailable_fields: tuple[str, ...]
    direct_evidence_count: int
    inferred_evidence_count: int
    evidence_completeness: float
    probability: float
    probability_unavailable_reason: str
    support: int
    policy_version: str
    policy_admission_state: str
    parent_scoring_policy: str
    correlation_group: str
    policy_requirement_digest_set: tuple[str, ...]
    implementation_requirement_digests: tuple[str, ...]
    policy_evaluation_manifest_digest: str
    implementation_evaluation_manifest_digests: tuple[str, ...]
    policy_calibration_artifact_id: str
    calibration_artifact_id: str
    rejection_reason: str
    unavailable_reason: str
    revoked: bool
    deprecated: bool
    authority_requirement_root_bindings: tuple[str, ...]
    authority_relation_requirements: tuple[str, ...]
    physical_root_provenance: tuple[str, ...]
    deterministic_derivations: tuple[str, ...]
    yara_role: str
    yara_used_root_evidence_ids: tuple[str, ...]
    model_assistance_evidence_authority: str
    model_assistance_official_decision_effect: str
    model_assistance_discovery_query_ids: tuple[str, ...]
    attack_explainability_semantic_digest: str
    authority_chain_semantic_digest: str
    decision_semantic_digest: str
    schema_version: str = MITRE_FINDING_SUMMARY_ROW_SCHEMA_VERSION

    def to_record(self) -> dict[str, object]:
        exact_content_sha256(self.content_sha256, "mitre_finding_summary_content_sha256_invalid")
        return {field: getattr(self, field) for field in self.__dataclass_fields__}


@dataclass(frozen=True, slots=True)
class MitreFindingsSummary:
    scan_id: str
    snapshot_semantic_digest: str
    source_record_count: int
    evidence_record_count: int
    duplicate_alias_count: int
    source_rows: tuple[MitreEvidenceSummaryRow, ...]
    finding_rows: tuple[MitreFindingSummaryRow, ...]
    schema_version: str = MITRE_FINDINGS_SUMMARY_SCHEMA_VERSION

    def counts_record(self) -> dict[str, int]:
        return {
            "source_record_count": self.source_record_count,
            "evidence_record_count": self.evidence_record_count,
            "unique_evidence_count": len(self.source_rows),
            "duplicate_alias_count": self.duplicate_alias_count,
            "ready_evidence_count": sum(row.ready for row in self.source_rows),
            "unavailable_evidence_count": sum(not row.ready for row in self.source_rows),
            "decision_count": len(self.finding_rows),
            "confirmed_count": sum(row.decision_status == "confirmed" for row in self.finding_rows),
            "candidate_count": sum(row.decision_status == "candidate" for row in self.finding_rows),
            "rejected_count": sum(row.decision_status == "rejected" for row in self.finding_rows),
            "unavailable_decision_count": sum(
                row.decision_status == "unavailable" for row in self.finding_rows
            ),
        }

    @property
    def semantic_digest(self) -> str:
        return canonical_json_sha256(self.core_record())

    def core_record(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "snapshot_semantic_digest": self.snapshot_semantic_digest,
            "schema_version": self.schema_version,
            "counts": self.counts_record(),
            "source_rows": tuple(row.to_record() for row in self.source_rows),
            "finding_rows": tuple(row.to_record() for row in self.finding_rows),
            "projection_policy": {
                "source": "final_immutable_mitre_chain_and_explainability_only",
                "report_time_attack_mapping": False,
                "report_time_chain_evaluation": False,
                "unknown_is_negative": False,
            },
        }

    def to_record(self) -> dict[str, object]:
        record = self.core_record()
        record["summary_semantic_digest"] = self.semantic_digest
        return record


def _row_from_decision(
    *,
    record_keys: tuple[str, ...],
    content_sha256: str,
    evidence: Mapping[str, object],
    repository_status_digest: str,
    decision: Mapping[str, object],
    chain_index: Mapping[str, dict[str, object]],
    attack_explainability: Mapping[str, object],
    attack_explainability_semantic_digest: str,
) -> MitreFindingSummaryRow:
    required_chain_ids = _text_tuple(dict.get(decision, "required_chain_ids", ()), "mitre_summary_required_chains_invalid", limit=64, sorted_unique=True)
    chain_states, required_terms, optional_terms, forbidden_terms, operation_ids = _chain_requirements(required_chain_ids, chain_index)
    materialized_decision = no_hook_materialize(decision, max_depth=24, max_items=20_000, reason_prefix="mitre_summary_decision")
    if type(materialized_decision) is not dict:
        raise RuntimeError("mitre_summary_decision_materialization_invalid")
    authority = _attack_explainability_fields(attack_explainability, decision, ",".join(record_keys))
    return MitreFindingSummaryRow(
        record_keys=record_keys,
        content_sha256=exact_content_sha256(content_sha256, "mitre_summary_content_sha256_invalid"),
        repository_digest=_text(dict.get(evidence, "repository_digest"), "mitre_summary_repository_digest_invalid", maximum=64),
        dataset_version=_text(dict.get(evidence, "dataset_version"), "mitre_summary_dataset_invalid", maximum=40),
        repository_status_semantic_digest=repository_status_digest,
        technique_id=_text(dict.get(decision, "technique_id"), "mitre_summary_technique_id_invalid", maximum=16),
        technique_name=_text(dict.get(decision, "technique_name"), "mitre_summary_technique_name_invalid", maximum=256),
        parent_technique_id=_text(dict.get(decision, "parent_technique_id", ""), "mitre_summary_parent_id_invalid", allow_blank=True, maximum=16),
        parent_technique_name=_text(dict.get(decision, "parent_technique_name", ""), "mitre_summary_parent_name_invalid", allow_blank=True, maximum=256),
        tactic_ids=_text_tuple(dict.get(decision, "tactic_ids", ()), "mitre_summary_tactic_ids_invalid", limit=32),
        tactic_names=_text_tuple(dict.get(decision, "tactic_names", ()), "mitre_summary_tactic_names_invalid", limit=32),
        decision_status=_text(dict.get(decision, "status"), "mitre_summary_status_invalid", maximum=16),
        claim_scopes=_text_tuple(dict.get(decision, "claim_scopes", ()), "mitre_summary_claim_scopes_invalid", limit=16),
        execution_observed=_bool(dict.get(decision, "execution_observed"), "mitre_summary_execution_observed_invalid"),
        policy_implementation_ids=_text_tuple(dict.get(decision, "policy_implementation_ids", ()), "mitre_summary_policy_implementation_ids_invalid", limit=16, sorted_unique=True),
        implementation_ids=_text_tuple(dict.get(decision, "implementation_ids", ()), "mitre_summary_implementation_ids_invalid", limit=16, sorted_unique=True),
        strategy_ids=_text_tuple(dict.get(decision, "strategy_ids", ()), "mitre_summary_strategy_ids_invalid", limit=16, sorted_unique=True),
        analytic_ids=_text_tuple(dict.get(decision, "analytic_ids", ()), "mitre_summary_analytic_ids_invalid", limit=16, sorted_unique=True),
        required_data_component_ids=_text_tuple(dict.get(decision, "required_data_component_ids", ()), "mitre_summary_required_data_components_invalid", limit=64, sorted_unique=True),
        observed_data_component_ids=_text_tuple(dict.get(decision, "observed_data_component_ids", ()), "mitre_summary_observed_data_components_invalid", limit=64, sorted_unique=True),
        required_chain_ids=required_chain_ids,
        required_chain_states=chain_states,
        required_evidence_terms=required_terms,
        optional_evidence_terms=optional_terms,
        forbidden_evidence_terms=forbidden_terms,
        operation_ids=operation_ids,
        required_platforms=_text_tuple(dict.get(decision, "required_platforms", ()), "mitre_summary_required_platforms_invalid", limit=64, sorted_unique=True),
        required_modalities=_text_tuple(dict.get(decision, "required_modalities", ()), "mitre_summary_required_modalities_invalid", limit=32, sorted_unique=True),
        evidence_ids=_text_tuple(dict.get(decision, "evidence_ids", ()), "mitre_summary_evidence_ids_invalid", limit=128, sorted_unique=True),
        root_evidence_ids=_text_tuple(dict.get(decision, "root_evidence_ids", ()), "mitre_summary_root_ids_invalid", limit=128, sorted_unique=True),
        rejected_evidence_ids=_text_tuple(dict.get(decision, "rejected_evidence_ids", ()), "mitre_summary_rejected_ids_invalid", limit=128, sorted_unique=True),
        missing_requirements=_text_tuple(dict.get(decision, "missing_requirements", ()), "mitre_summary_missing_requirements_invalid", limit=128, sorted_unique=True),
        unavailable_fields=_text_tuple(dict.get(decision, "unavailable_fields", ()), "mitre_summary_unavailable_fields_invalid", limit=128, sorted_unique=True),
        direct_evidence_count=_nonnegative_int(dict.get(decision, "direct_evidence_count"), "mitre_summary_direct_count_invalid"),
        inferred_evidence_count=_nonnegative_int(dict.get(decision, "inferred_evidence_count"), "mitre_summary_inferred_count_invalid"),
        evidence_completeness=_number(dict.get(decision, "evidence_completeness"), "mitre_summary_completeness_invalid"),
        probability=_number(dict.get(decision, "probability"), "mitre_summary_probability_invalid"),
        probability_unavailable_reason=_text(dict.get(decision, "probability_unavailable_reason", ""), "mitre_summary_probability_reason_invalid", allow_blank=True, maximum=256),
        support=_nonnegative_int(dict.get(decision, "support"), "mitre_summary_support_invalid"),
        policy_version=_text(dict.get(decision, "policy_version"), "mitre_summary_policy_version_invalid", maximum=128),
        policy_admission_state=_text(dict.get(decision, "policy_admission_state"), "mitre_summary_policy_admission_invalid", maximum=32),
        parent_scoring_policy=_text(dict.get(decision, "parent_scoring_policy"), "mitre_summary_parent_scoring_invalid", maximum=32),
        correlation_group=_text(dict.get(decision, "correlation_group"), "mitre_summary_correlation_group_invalid", maximum=128),
        policy_requirement_digest_set=_text_tuple(dict.get(decision, "policy_requirement_digest_set", ()), "mitre_summary_policy_requirement_digests_invalid", limit=32, sorted_unique=True),
        implementation_requirement_digests=_text_tuple(dict.get(decision, "implementation_requirement_digests", ()), "mitre_summary_implementation_requirement_digests_invalid", limit=32, sorted_unique=True),
        policy_evaluation_manifest_digest=_text(dict.get(decision, "policy_evaluation_manifest_digest", ""), "mitre_summary_policy_evaluation_digest_invalid", allow_blank=True, maximum=64),
        implementation_evaluation_manifest_digests=_text_tuple(dict.get(decision, "implementation_evaluation_manifest_digests", ()), "mitre_summary_implementation_evaluation_digests_invalid", limit=32, sorted_unique=True),
        policy_calibration_artifact_id=_text(dict.get(decision, "policy_calibration_artifact_id", ""), "mitre_summary_policy_calibration_invalid", allow_blank=True, maximum=128),
        calibration_artifact_id=_text(dict.get(decision, "calibration_artifact_id", ""), "mitre_summary_calibration_invalid", allow_blank=True, maximum=128),
        rejection_reason=_text(dict.get(decision, "rejection_reason", ""), "mitre_summary_rejection_invalid", allow_blank=True, maximum=256),
        unavailable_reason=_text(dict.get(decision, "unavailable_reason", ""), "mitre_summary_decision_unavailable_invalid", allow_blank=True, maximum=256),
        revoked=_bool(dict.get(decision, "revoked"), "mitre_summary_revoked_invalid"),
        deprecated=_bool(dict.get(decision, "deprecated"), "mitre_summary_deprecated_invalid"),
        attack_explainability_semantic_digest=attack_explainability_semantic_digest,
        **authority,
        decision_semantic_digest=canonical_json_sha256(materialized_decision),
    )


def build_mitre_findings_summary(
    *,
    scan_id: object,
    snapshot_semantic_digest: object,
    local_results: object,
) -> MitreFindingsSummary:
    scan_id_text = _text(scan_id, "mitre_findings_summary_scan_id_invalid", maximum=128)
    snapshot_digest = _text(snapshot_semantic_digest, "mitre_findings_summary_snapshot_digest_invalid", maximum=64)
    items = no_hook_mapping_items(local_results)
    if items is None or len(items) > _MAX_RECORDS:
        raise TypeError("mitre_findings_summary_local_results_invalid")
    source_record_count = len(items)
    evidence_record_count = 0
    evidence_groups: dict[tuple[str, str], dict[str, object]] = {}
    decisions_by_digest: dict[tuple[str, str], dict[str, object]] = {}
    physical_decisions: dict[tuple[object, ...], str] = {}

    for raw_key, record in items:
        record_key = _text(raw_key, "mitre_summary_record_key_invalid")
        evidence = _source_mitre_evidence(record, record_key)
        if evidence is None:
            continue
        evidence_record_count += 1
        content_sha256 = final_record_content_sha256(
            record, "mitre_summary_content_sha256_invalid:" + record_key
        )
        evidence_digest = canonical_json_sha256(evidence)
        repository_status = _mapping(dict.get(evidence, "repository_status"), "mitre_summary_repository_status_invalid")
        repository_status_digest = canonical_json_sha256(repository_status)
        source_identity = (content_sha256, evidence_digest)
        group = evidence_groups.get(source_identity)
        if group is None:
            evidence_groups[source_identity] = {
                "content_sha256": content_sha256,
                "evidence": evidence,
                "record_keys": {record_key},
                "repository_status_digest": repository_status_digest,
            }
        else:
            group["record_keys"].add(record_key)
        if dict.get(evidence, "ready") is not True:
            continue
        decision_count = sum(len(_sequence(dict.get(evidence, status, ()), "mitre_summary_decisions_invalid", limit=128)) for status in _STATUSES)
        explainability_index, explainability_digest = _attack_explainability_index(
            record, record_key, required=decision_count > 0,
        )
        chain_index = _chain_index(record, record_key)
        for status in _STATUSES:
            for raw_decision in _sequence(dict.get(evidence, status, ()), "mitre_summary_decisions_invalid", limit=128):
                decision = _mapping(raw_decision, "mitre_summary_decision_invalid")
                materialized_decision = no_hook_materialize(decision, max_depth=24, max_items=20_000, reason_prefix="mitre_summary_decision")
                if type(materialized_decision) is not dict:
                    raise RuntimeError("mitre_summary_decision_materialization_invalid")
                decision_digest = canonical_json_sha256(materialized_decision)
                technique_id = _text(dict.get(decision, "technique_id"), "mitre_summary_technique_id_invalid", maximum=16)
                explanation = explainability_index.get(technique_id)
                if explanation is None:
                    raise RuntimeError("mitre_summary_attack_explainability_decision_missing:" + technique_id)
                roots = _text_tuple(dict.get(decision, "root_evidence_ids", ()), "mitre_summary_root_ids_invalid", limit=128, sorted_unique=True)
                physical_key = (
                    content_sha256,
                    dict.get(evidence, "repository_digest"),
                    dict.get(evidence, "dataset_version"),
                    technique_id,
                    roots,
                )
                prior = physical_decisions.get(physical_key)
                if prior is not None and prior != decision_digest:
                    raise RuntimeError("mitre_summary_physical_decision_conflict:" + technique_id)
                physical_decisions[physical_key] = decision_digest
                decision_identity = (content_sha256, decision_digest)
                decision_group = decisions_by_digest.get(decision_identity)
                if decision_group is None:
                    decisions_by_digest[decision_identity] = {
                        "content_sha256": content_sha256,
                        "decision": decision,
                        "record_keys": {record_key},
                        "evidence": evidence,
                        "repository_status_digest": repository_status_digest,
                        "chain_index": chain_index,
                        "attack_explainability": explanation,
                        "attack_explainability_semantic_digest": explainability_digest,
                    }
                else:
                    required_chain_ids = _text_tuple(
                        dict.get(decision, "required_chain_ids", ()),
                        "mitre_summary_required_chains_invalid",
                        limit=64,
                        sorted_unique=True,
                    )
                    prior_chain_projection = _chain_requirements(
                        required_chain_ids, decision_group["chain_index"]
                    )
                    current_chain_projection = _chain_requirements(
                        required_chain_ids, chain_index
                    )
                    if prior_chain_projection != current_chain_projection:
                        raise RuntimeError(
                            "mitre_summary_chain_projection_conflict:" + technique_id
                        )
                    prior_authority = _attack_explainability_fields(
                        decision_group["attack_explainability"], decision_group["decision"], record_key,
                    )
                    current_authority = _attack_explainability_fields(explanation, decision, record_key)
                    if prior_authority != current_authority:
                        raise RuntimeError("mitre_summary_attack_explainability_conflict:" + technique_id)
                    decision_group["record_keys"].add(record_key)

    source_rows = tuple(sorted((
        MitreEvidenceSummaryRow(
            record_keys=tuple(sorted(group["record_keys"])),
            content_sha256=content_sha256,
            ready=_bool(dict.get(group["evidence"], "ready"), "mitre_summary_ready_invalid"),
            repository_digest=_text(dict.get(group["evidence"], "repository_digest", ""), "mitre_summary_repository_digest_invalid", allow_blank=True, maximum=64),
            dataset_version=_text(dict.get(group["evidence"], "dataset_version", ""), "mitre_summary_dataset_invalid", allow_blank=True, maximum=40),
            policy_version=_text(dict.get(group["evidence"], "policy_version"), "mitre_summary_policy_version_invalid", maximum=128),
            evaluation_provenance=_text(dict.get(group["evidence"], "evaluation_provenance"), "mitre_summary_evaluation_provenance_invalid", maximum=128),
            probability=_number(dict.get(group["evidence"], "probability"), "mitre_summary_probability_invalid"),
            probability_unavailable_reason=_text(dict.get(group["evidence"], "probability_unavailable_reason", ""), "mitre_summary_probability_reason_invalid", allow_blank=True, maximum=256),
            unavailable_reason=_text(dict.get(group["evidence"], "unavailable_reason", ""), "mitre_summary_unavailable_reason_invalid", allow_blank=True, maximum=256),
            repository_status_semantic_digest=group["repository_status_digest"],
            evidence_semantic_digest=evidence_digest,
        )
        for (content_sha256, evidence_digest), group in evidence_groups.items()
    ), key=lambda row: (row.content_sha256, not row.ready, row.repository_digest, row.dataset_version, row.evidence_semantic_digest)))

    finding_rows = tuple(sorted((
        _row_from_decision(
            record_keys=tuple(sorted(group["record_keys"])),
            content_sha256=group["content_sha256"],
            evidence=group["evidence"],
            repository_status_digest=group["repository_status_digest"],
            decision=group["decision"],
            chain_index=group["chain_index"],
            attack_explainability=group["attack_explainability"],
            attack_explainability_semantic_digest=group["attack_explainability_semantic_digest"],
        )
        for group in decisions_by_digest.values()
    ), key=lambda row: (row.content_sha256, row.technique_id, row.decision_status, row.root_evidence_ids, row.decision_semantic_digest)))

    return MitreFindingsSummary(
        scan_id=scan_id_text,
        snapshot_semantic_digest=snapshot_digest,
        source_record_count=source_record_count,
        evidence_record_count=evidence_record_count,
        duplicate_alias_count=evidence_record_count - len(source_rows),
        source_rows=source_rows,
        finding_rows=finding_rows,
    )


def mitre_findings_json_bytes(summary: MitreFindingsSummary) -> bytes:
    if type(summary) is not MitreFindingsSummary:
        raise TypeError("mitre_findings_summary_required")
    return (json.dumps(summary.to_record(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def mitre_findings_markdown_bytes(summary: MitreFindingsSummary) -> bytes:
    if type(summary) is not MitreFindingsSummary:
        raise TypeError("mitre_findings_summary_required")
    counts = summary.counts_record()
    lines = [
        "# MITRE ATT&CK Findings Summary",
        "",
        f"- Scan ID: `{summary.scan_id}`",
        f"- Snapshot semantic digest: `{summary.snapshot_semantic_digest}`",
        f"- Summary semantic digest: `{summary.semantic_digest}`",
        f"- Decisions: {counts['decision_count']}",
        f"- Confirmed / candidate / rejected / unavailable: {counts['confirmed_count']} / {counts['candidate_count']} / {counts['rejected_count']} / {counts['unavailable_decision_count']}",
        f"- Ready / unavailable MITRE evidence snapshots: {counts['ready_evidence_count']} / {counts['unavailable_evidence_count']}",
        "- Projection policy: final immutable ATT&CK and Chain evidence only; no report-time ATT&CK mapping or Chain evaluation.",
        "",
        "| Content SHA-256 | Technique | State | Decision reason | Claim scope | Exec observed | Data components | Chains | Roots | YARA | Model authority | Authority digest | Probability |",
        "|---|---|---|---|---|---|---:|---:|---:|---|---|---|---|",
    ]
    for row in summary.finding_rows:
        probability = str(row.probability) if row.probability > 0.0 else (row.probability_unavailable_reason or "unavailable")
        lines.append(
            "| " + " | ".join((
                _md(row.content_sha256),
                _md(row.technique_id + " " + row.technique_name),
                _md(row.decision_status),
                _md(row.rejection_reason or row.unavailable_reason or ""),
                _md(",".join(row.claim_scopes) or "unavailable"),
                _md(row.execution_observed),
                str(len(row.observed_data_component_ids)),
                str(len(row.required_chain_ids)),
                str(len(row.root_evidence_ids)),
                _md(row.yara_role),
                _md(row.model_assistance_evidence_authority + "/" + row.model_assistance_official_decision_effect),
                _md(row.authority_chain_semantic_digest),
                _md(probability),
            )) + " |"
        )
    if any(not row.ready for row in summary.source_rows):
        lines.extend(("", "## Unavailable MITRE states", ""))
        for row in summary.source_rows:
            if not row.ready:
                lines.append(f"- `{','.join(row.record_keys)}`: `{row.unavailable_reason}`")
    lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def mitre_findings_csv_bytes(summary: MitreFindingsSummary) -> bytes:
    if type(summary) is not MitreFindingsSummary:
        raise TypeError("mitre_findings_summary_required")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow((
        "content_sha256", "technique_id", "technique_name", "parent_technique_id", "parent_technique_name",
        "tactic_ids", "tactic_names", "decision_status", "claim_scopes", "execution_observed",
        "policy_implementation_ids", "implementation_ids", "strategy_ids", "analytic_ids",
        "required_data_component_ids", "observed_data_component_ids", "required_chain_ids",
        "required_chain_states", "required_evidence_terms", "optional_evidence_terms",
        "forbidden_evidence_terms", "operation_ids", "required_platforms", "required_modalities",
        "evidence_ids", "root_evidence_ids", "missing_requirements", "unavailable_fields",
        "probability", "probability_unavailable_reason", "rejection_reason", "unavailable_reason",
        "policy_version", "policy_admission_state",
        "policy_requirement_digest_set", "implementation_requirement_digests",
        "policy_evaluation_manifest_digest", "implementation_evaluation_manifest_digests",
        "policy_calibration_artifact_id", "calibration_artifact_id", "repository_digest",
        "dataset_version", "repository_status_semantic_digest",
        "authority_requirement_root_bindings", "authority_relation_requirements",
        "physical_root_provenance", "deterministic_derivations", "yara_role",
        "yara_used_root_evidence_ids", "model_assistance_evidence_authority",
        "model_assistance_official_decision_effect", "model_assistance_discovery_query_ids",
        "attack_explainability_semantic_digest", "authority_chain_semantic_digest",
        "decision_semantic_digest", "record_keys",
    ))
    for row in summary.finding_rows:
        writer.writerow((
            row.content_sha256, row.technique_id, row.technique_name, row.parent_technique_id, row.parent_technique_name,
            json.dumps(row.tactic_ids), json.dumps(row.tactic_names), row.decision_status,
            json.dumps(row.claim_scopes), row.execution_observed, json.dumps(row.policy_implementation_ids),
            json.dumps(row.implementation_ids), json.dumps(row.strategy_ids), json.dumps(row.analytic_ids),
            json.dumps(row.required_data_component_ids), json.dumps(row.observed_data_component_ids),
            json.dumps(row.required_chain_ids), json.dumps(row.required_chain_states),
            json.dumps(row.required_evidence_terms), json.dumps(row.optional_evidence_terms),
            json.dumps(row.forbidden_evidence_terms), json.dumps(row.operation_ids),
            json.dumps(row.required_platforms), json.dumps(row.required_modalities),
            json.dumps(row.evidence_ids), json.dumps(row.root_evidence_ids),
            json.dumps(row.missing_requirements), json.dumps(row.unavailable_fields),
            row.probability, row.probability_unavailable_reason, row.rejection_reason,
            row.unavailable_reason, row.policy_version, row.policy_admission_state,
            json.dumps(row.policy_requirement_digest_set),
            json.dumps(row.implementation_requirement_digests), row.policy_evaluation_manifest_digest,
            json.dumps(row.implementation_evaluation_manifest_digests), row.policy_calibration_artifact_id,
            row.calibration_artifact_id, row.repository_digest, row.dataset_version,
            row.repository_status_semantic_digest, json.dumps(row.authority_requirement_root_bindings),
            json.dumps(row.authority_relation_requirements), json.dumps(row.physical_root_provenance),
            json.dumps(row.deterministic_derivations), row.yara_role,
            json.dumps(row.yara_used_root_evidence_ids), row.model_assistance_evidence_authority,
            row.model_assistance_official_decision_effect, json.dumps(row.model_assistance_discovery_query_ids),
            row.attack_explainability_semantic_digest, row.authority_chain_semantic_digest,
            row.decision_semantic_digest, json.dumps(row.record_keys),
        ))
    return stream.getvalue().encode("utf-8")


def render_mitre_findings_summary(summary: MitreFindingsSummary) -> tuple[tuple[str, bytes], ...]:
    if type(summary) is not MitreFindingsSummary:
        raise TypeError("mitre_findings_summary_required")
    return (
        ("mitre_findings_summary.json", mitre_findings_json_bytes(summary)),
        ("mitre_findings_summary.md", mitre_findings_markdown_bytes(summary)),
        ("mitre_findings_summary.csv", mitre_findings_csv_bytes(summary)),
    )


__all__ = (
    "MITRE_EVIDENCE_SUMMARY_ROW_SCHEMA_VERSION",
    "MITRE_FINDING_SUMMARY_ROW_SCHEMA_VERSION",
    "MITRE_FINDINGS_SUMMARY_SCHEMA_VERSION",
    "MitreEvidenceSummaryRow",
    "MitreFindingSummaryRow",
    "MitreFindingsSummary",
    "build_mitre_findings_summary",
    "render_mitre_findings_summary",
)
