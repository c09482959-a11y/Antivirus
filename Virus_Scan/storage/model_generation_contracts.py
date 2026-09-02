"""Immutable Phase-4 candidate custody, promotion-audit, and model-generation contracts.

These records define trust-boundary schemas only. Candidate records remain
non-authoritative until the later canonical promotion lifecycle validates and
activates them. SQLite database/schema generations are deliberately distinct
from model generations represented here.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Final

CANDIDATE_OBSERVATION_SCHEMA_VERSION: Final[str] = "candidate_observation_v1"
MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION: Final[str] = "model_candidate_quarantine_v1"
PROMOTION_AUDIT_SCHEMA_VERSION: Final[str] = "promotion_audit_v1"
PROMOTION_INTENT_SCHEMA_VERSION: Final[str] = "promotion_intent_v1"
MODEL_GENERATION_MANIFEST_SCHEMA_VERSION: Final[str] = "model_generation_manifest_v1"

_HEX = frozenset("0123456789abcdef")
_AUTHORITY_CLASSES = frozenset({"A", "B"})


def _is_sha256(value: object, *, allow_empty: bool = False) -> bool:
    if allow_empty and value == "":
        return True
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _text(value: object, field: str, *, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and value == ""):
        raise ValueError(f"{field}_invalid")
    return value


def _sha256(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not _is_sha256(value, allow_empty=allow_empty):
        raise ValueError(f"{field}_invalid")
    return str(value)


def _nonnegative_int(value: object, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field}_invalid")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        text = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("canonical_record_not_json_safe") from exc
    return text.encode("utf-8")


def canonical_record_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _ordered_unique_texts(values: object, field: str, *, allow_empty_sequence: bool = True) -> tuple[str, ...]:
    if type(values) not in (tuple, list):
        raise ValueError(f"{field}_invalid")
    rows = tuple(values)
    if not allow_empty_sequence and not rows:
        raise ValueError(f"{field}_invalid")
    if any(type(value) is not str or value == "" for value in rows):
        raise ValueError(f"{field}_invalid")
    if rows != tuple(sorted(set(rows))):
        raise ValueError(f"{field}_noncanonical")
    return rows


def _ordered_unique_sha256s(values: object, field: str, *, allow_empty_sequence: bool = True) -> tuple[str, ...]:
    rows = _ordered_unique_texts(values, field, allow_empty_sequence=allow_empty_sequence)
    if any(not _is_sha256(value) for value in rows):
        raise ValueError(f"{field}_invalid")
    return rows


def _pairs(values: object, field: str) -> tuple[tuple[str, str], ...]:
    if type(values) not in (tuple, list):
        raise ValueError(f"{field}_invalid")
    rows: list[tuple[str, str]] = []
    for value in values:
        if type(value) not in (tuple, list) or len(value) != 2:
            raise ValueError(f"{field}_invalid")
        key = _text(value[0], field)
        item = _text(value[1], field)
        rows.append((key, item))
    result = tuple(rows)
    if result != tuple(sorted(set(result))):
        raise ValueError(f"{field}_noncanonical")
    return result


def _require_exact_keys(record: object, expected: frozenset[str], error: str) -> dict[str, object]:
    if type(record) is not dict or frozenset(record) != expected:
        raise ValueError(error)
    return record


@dataclass(frozen=True, slots=True)
class CandidateObservation:
    """One immutable non-authoritative scan-derived learning candidate."""

    candidate_id: str
    scan_id: str
    artifact_identity: str
    artifact_sha256: str
    physical_target_identity: str
    member_identity: str
    evidence_ids: tuple[str, ...]
    evidence_snapshot_id: str
    authority_class: str
    evidence_type: str
    producer_id: str
    producer_version: str
    model_id: str
    model_generation: str
    external_source: str
    observed_at: int
    normalized_value: object
    confidence_context: tuple[tuple[str, str], ...]
    source_independence_key: str
    replay_key: str
    semantic_domain: str
    proposed_effect: str
    schema_version: str = CANDIDATE_OBSERVATION_SCHEMA_VERSION

    @staticmethod
    def _identity_record(fields: dict[str, object]) -> dict[str, object]:
        return {key: value for key, value in fields.items() if key != "candidate_id"}

    @classmethod
    def build(
        cls,
        *,
        scan_id: str,
        artifact_identity: str,
        artifact_sha256: str,
        physical_target_identity: str,
        member_identity: str = "",
        evidence_ids: tuple[str, ...],
        evidence_snapshot_id: str,
        authority_class: str,
        evidence_type: str,
        producer_id: str,
        producer_version: str,
        model_id: str = "",
        model_generation: str = "",
        external_source: str = "",
        observed_at: int,
        normalized_value: object,
        confidence_context: tuple[tuple[str, str], ...],
        source_independence_key: str,
        replay_key: str,
        semantic_domain: str,
        proposed_effect: str,
    ) -> "CandidateObservation":
        base: dict[str, object] = {
            "schema_version": CANDIDATE_OBSERVATION_SCHEMA_VERSION,
            "scan_id": scan_id,
            "artifact_identity": artifact_identity,
            "artifact_sha256": artifact_sha256,
            "physical_target_identity": physical_target_identity,
            "member_identity": member_identity,
            "evidence_ids": list(evidence_ids),
            "evidence_snapshot_id": evidence_snapshot_id,
            "authority_class": authority_class,
            "evidence_type": evidence_type,
            "producer_id": producer_id,
            "producer_version": producer_version,
            "model_id": model_id,
            "model_generation": model_generation,
            "external_source": external_source,
            "observed_at": observed_at,
            "normalized_value": normalized_value,
            "confidence_context": [list(row) for row in confidence_context],
            "source_independence_key": source_independence_key,
            "replay_key": replay_key,
            "semantic_domain": semantic_domain,
            "proposed_effect": proposed_effect,
        }
        candidate_id = canonical_record_sha256(base)
        return cls.from_record({"candidate_id": candidate_id, **base})

    def to_record(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "scan_id": self.scan_id,
            "artifact_identity": self.artifact_identity,
            "artifact_sha256": self.artifact_sha256,
            "physical_target_identity": self.physical_target_identity,
            "member_identity": self.member_identity,
            "evidence_ids": list(self.evidence_ids),
            "evidence_snapshot_id": self.evidence_snapshot_id,
            "authority_class": self.authority_class,
            "evidence_type": self.evidence_type,
            "producer_id": self.producer_id,
            "producer_version": self.producer_version,
            "model_id": self.model_id,
            "model_generation": self.model_generation,
            "external_source": self.external_source,
            "observed_at": self.observed_at,
            "normalized_value": self.normalized_value,
            "confidence_context": [list(row) for row in self.confidence_context],
            "source_independence_key": self.source_independence_key,
            "replay_key": self.replay_key,
            "semantic_domain": self.semantic_domain,
            "proposed_effect": self.proposed_effect,
        }

    @classmethod
    def from_record(cls, record: object) -> "CandidateObservation":
        expected = frozenset({
            "schema_version", "candidate_id", "scan_id", "artifact_identity", "artifact_sha256",
            "physical_target_identity", "member_identity", "evidence_ids", "evidence_snapshot_id",
            "authority_class", "evidence_type", "producer_id", "producer_version", "model_id",
            "model_generation", "external_source", "observed_at", "normalized_value",
            "confidence_context", "source_independence_key", "replay_key", "semantic_domain",
            "proposed_effect",
        })
        data = _require_exact_keys(record, expected, "candidate_observation_record_invalid")
        if data.get("schema_version") != CANDIDATE_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("candidate_observation_schema_unsupported")
        value = cls(
            candidate_id=_sha256(data.get("candidate_id"), "candidate_observation_id"),
            scan_id=_text(data.get("scan_id"), "candidate_observation_scan_id"),
            artifact_identity=_text(data.get("artifact_identity"), "candidate_observation_artifact_identity"),
            artifact_sha256=_sha256(data.get("artifact_sha256"), "candidate_observation_artifact_sha256"),
            physical_target_identity=_text(data.get("physical_target_identity"), "candidate_observation_physical_target_identity"),
            member_identity=_text(data.get("member_identity"), "candidate_observation_member_identity", allow_empty=True),
            evidence_ids=_ordered_unique_texts(data.get("evidence_ids"), "candidate_observation_evidence_ids", allow_empty_sequence=False),
            evidence_snapshot_id=_text(data.get("evidence_snapshot_id"), "candidate_observation_evidence_snapshot_id"),
            authority_class=_text(data.get("authority_class"), "candidate_observation_authority_class"),
            evidence_type=_text(data.get("evidence_type"), "candidate_observation_evidence_type"),
            producer_id=_text(data.get("producer_id"), "candidate_observation_producer_id"),
            producer_version=_text(data.get("producer_version"), "candidate_observation_producer_version"),
            model_id=_text(data.get("model_id"), "candidate_observation_model_id", allow_empty=True),
            model_generation=_text(data.get("model_generation"), "candidate_observation_model_generation", allow_empty=True),
            external_source=_text(data.get("external_source"), "candidate_observation_external_source", allow_empty=True),
            observed_at=_nonnegative_int(data.get("observed_at"), "candidate_observation_observed_at"),
            normalized_value=data.get("normalized_value"),
            confidence_context=_pairs(data.get("confidence_context"), "candidate_observation_confidence_context"),
            source_independence_key=_sha256(data.get("source_independence_key"), "candidate_observation_source_independence_key"),
            replay_key=_sha256(data.get("replay_key"), "candidate_observation_replay_key"),
            semantic_domain=_text(data.get("semantic_domain"), "candidate_observation_semantic_domain"),
            proposed_effect=_text(data.get("proposed_effect"), "candidate_observation_proposed_effect"),
            schema_version=CANDIDATE_OBSERVATION_SCHEMA_VERSION,
        )
        value.validate()
        return value

    def validate(self) -> bool:
        if self.schema_version != CANDIDATE_OBSERVATION_SCHEMA_VERSION:
            raise ValueError("candidate_observation_schema_unsupported")
        if self.authority_class not in _AUTHORITY_CLASSES:
            raise ValueError("candidate_observation_authority_class_invalid")
        _sha256(self.candidate_id, "candidate_observation_id")
        _sha256(self.artifact_sha256, "candidate_observation_artifact_sha256")
        _sha256(self.source_independence_key, "candidate_observation_source_independence_key")
        _sha256(self.replay_key, "candidate_observation_replay_key")
        for field, value in (
            ("scan_id", self.scan_id),
            ("artifact_identity", self.artifact_identity),
            ("physical_target_identity", self.physical_target_identity),
            ("evidence_snapshot_id", self.evidence_snapshot_id),
            ("evidence_type", self.evidence_type),
            ("producer_id", self.producer_id),
            ("producer_version", self.producer_version),
            ("semantic_domain", self.semantic_domain),
            ("proposed_effect", self.proposed_effect),
        ):
            _text(value, f"candidate_observation_{field}")
        _text(self.member_identity, "candidate_observation_member_identity", allow_empty=True)
        _text(self.model_id, "candidate_observation_model_id", allow_empty=True)
        _text(self.model_generation, "candidate_observation_model_generation", allow_empty=True)
        _text(self.external_source, "candidate_observation_external_source", allow_empty=True)
        _nonnegative_int(self.observed_at, "candidate_observation_observed_at")
        _ordered_unique_texts(self.evidence_ids, "candidate_observation_evidence_ids", allow_empty_sequence=False)
        _pairs(self.confidence_context, "candidate_observation_confidence_context")
        _canonical_json_bytes(self.normalized_value)
        record = self.to_record_unchecked()
        expected = canonical_record_sha256(self._identity_record(record))
        if expected != self.candidate_id:
            raise ValueError("candidate_observation_identity_mismatch")
        return True

    def to_record_unchecked(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "scan_id": self.scan_id,
            "artifact_identity": self.artifact_identity,
            "artifact_sha256": self.artifact_sha256,
            "physical_target_identity": self.physical_target_identity,
            "member_identity": self.member_identity,
            "evidence_ids": list(self.evidence_ids),
            "evidence_snapshot_id": self.evidence_snapshot_id,
            "authority_class": self.authority_class,
            "evidence_type": self.evidence_type,
            "producer_id": self.producer_id,
            "producer_version": self.producer_version,
            "model_id": self.model_id,
            "model_generation": self.model_generation,
            "external_source": self.external_source,
            "observed_at": self.observed_at,
            "normalized_value": self.normalized_value,
            "confidence_context": [list(row) for row in self.confidence_context],
            "source_independence_key": self.source_independence_key,
            "replay_key": self.replay_key,
            "semantic_domain": self.semantic_domain,
            "proposed_effect": self.proposed_effect,
        }


@dataclass(frozen=True, slots=True)
class ModelCandidateQuarantineManifest:
    """Digest-bound immutable custody manifest for one offline candidate model."""

    candidate_id: str
    payload_sha256: str
    payload_size: int
    payload_object_key: str
    trainer_version: str
    code_source_generation: str
    feature_schema_identity: str
    dataset_manifest_ids: tuple[str, ...]
    split_manifest_ids: tuple[str, ...]
    dependency_graph_identity: str
    calibration_identity: str
    evaluation_release_identity: str
    parent_model_generation_id: str
    model_id: str
    model_version: str
    model_schema_identity: str
    policy_identity: str
    admitted_at_ns: int
    candidate_kind: str = "model_generation"
    schema_version: str = MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION

    @classmethod
    def build(cls, **fields: object) -> "ModelCandidateQuarantineManifest":
        base = dict(fields)
        base["candidate_kind"] = "model_generation"
        base["schema_version"] = MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION
        if "dataset_manifest_ids" in base:
            base["dataset_manifest_ids"] = list(base["dataset_manifest_ids"])
        if "split_manifest_ids" in base:
            base["split_manifest_ids"] = list(base["split_manifest_ids"])
        candidate_id = canonical_record_sha256(base)
        return cls.from_record({"candidate_id": candidate_id, **base})

    def to_record(self) -> dict[str, object]:
        self.validate()
        return self.to_record_unchecked()

    def to_record_unchecked(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "candidate_kind": self.candidate_kind,
            "payload_sha256": self.payload_sha256,
            "payload_size": self.payload_size,
            "payload_object_key": self.payload_object_key,
            "trainer_version": self.trainer_version,
            "code_source_generation": self.code_source_generation,
            "feature_schema_identity": self.feature_schema_identity,
            "dataset_manifest_ids": list(self.dataset_manifest_ids),
            "split_manifest_ids": list(self.split_manifest_ids),
            "dependency_graph_identity": self.dependency_graph_identity,
            "calibration_identity": self.calibration_identity,
            "evaluation_release_identity": self.evaluation_release_identity,
            "parent_model_generation_id": self.parent_model_generation_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "model_schema_identity": self.model_schema_identity,
            "policy_identity": self.policy_identity,
            "admitted_at_ns": self.admitted_at_ns,
        }

    @classmethod
    def from_record(cls, record: object) -> "ModelCandidateQuarantineManifest":
        expected = frozenset({
            "schema_version", "candidate_id", "candidate_kind", "payload_sha256", "payload_size",
            "payload_object_key", "trainer_version", "code_source_generation", "feature_schema_identity",
            "dataset_manifest_ids", "split_manifest_ids", "dependency_graph_identity", "calibration_identity",
            "evaluation_release_identity", "parent_model_generation_id", "model_id", "model_version",
            "model_schema_identity", "policy_identity", "admitted_at_ns",
        })
        data = _require_exact_keys(record, expected, "model_candidate_manifest_record_invalid")
        if data.get("schema_version") != MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION:
            raise ValueError("model_candidate_manifest_schema_unsupported")
        if data.get("candidate_kind") != "model_generation":
            raise ValueError("model_candidate_kind_invalid")
        value = cls(
            candidate_id=_sha256(data.get("candidate_id"), "model_candidate_id"),
            payload_sha256=_sha256(data.get("payload_sha256"), "model_candidate_payload_sha256"),
            payload_size=_nonnegative_int(data.get("payload_size"), "model_candidate_payload_size"),
            payload_object_key=_text(data.get("payload_object_key"), "model_candidate_payload_object_key"),
            trainer_version=_text(data.get("trainer_version"), "model_candidate_trainer_version"),
            code_source_generation=_text(data.get("code_source_generation"), "model_candidate_code_source_generation"),
            feature_schema_identity=_text(data.get("feature_schema_identity"), "model_candidate_feature_schema_identity"),
            dataset_manifest_ids=_ordered_unique_texts(data.get("dataset_manifest_ids"), "model_candidate_dataset_manifest_ids"),
            split_manifest_ids=_ordered_unique_texts(data.get("split_manifest_ids"), "model_candidate_split_manifest_ids"),
            dependency_graph_identity=_text(data.get("dependency_graph_identity"), "model_candidate_dependency_graph_identity"),
            calibration_identity=_text(data.get("calibration_identity"), "model_candidate_calibration_identity", allow_empty=True),
            evaluation_release_identity=_text(data.get("evaluation_release_identity"), "model_candidate_evaluation_release_identity"),
            parent_model_generation_id=_sha256(data.get("parent_model_generation_id"), "model_candidate_parent_generation", allow_empty=True),
            model_id=_text(data.get("model_id"), "model_candidate_model_id"),
            model_version=_text(data.get("model_version"), "model_candidate_model_version"),
            model_schema_identity=_text(data.get("model_schema_identity"), "model_candidate_model_schema_identity"),
            policy_identity=_text(data.get("policy_identity"), "model_candidate_policy_identity"),
            admitted_at_ns=_nonnegative_int(data.get("admitted_at_ns"), "model_candidate_admitted_at_ns"),
        )
        value.validate()
        return value

    def validate(self) -> bool:
        if self.schema_version != MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION or self.candidate_kind != "model_generation":
            raise ValueError("model_candidate_manifest_schema_invalid")
        _sha256(self.candidate_id, "model_candidate_id")
        _sha256(self.payload_sha256, "model_candidate_payload_sha256")
        _sha256(self.parent_model_generation_id, "model_candidate_parent_generation", allow_empty=True)
        _nonnegative_int(self.payload_size, "model_candidate_payload_size")
        _nonnegative_int(self.admitted_at_ns, "model_candidate_admitted_at_ns")
        if self.payload_object_key != "sha256:" + self.payload_sha256:
            raise ValueError("model_candidate_payload_object_key_invalid")
        for field, value, allow_empty in (
            ("trainer_version", self.trainer_version, False),
            ("code_source_generation", self.code_source_generation, False),
            ("feature_schema_identity", self.feature_schema_identity, False),
            ("dependency_graph_identity", self.dependency_graph_identity, False),
            ("calibration_identity", self.calibration_identity, True),
            ("evaluation_release_identity", self.evaluation_release_identity, False),
            ("model_id", self.model_id, False),
            ("model_version", self.model_version, False),
            ("model_schema_identity", self.model_schema_identity, False),
            ("policy_identity", self.policy_identity, False),
        ):
            _text(value, f"model_candidate_{field}", allow_empty=allow_empty)
        _ordered_unique_texts(self.dataset_manifest_ids, "model_candidate_dataset_manifest_ids")
        _ordered_unique_texts(self.split_manifest_ids, "model_candidate_split_manifest_ids")
        body = self.to_record_unchecked()
        body.pop("candidate_id")
        if canonical_record_sha256(body) != self.candidate_id:
            raise ValueError("model_candidate_identity_mismatch")
        return True


@dataclass(frozen=True, slots=True)
class PromotionIntentRecord:
    """Immutable non-authoritative intent for one bounded promotion attempt."""

    promotion_intent_id: str
    current_candidate_id: str
    candidate_ids: tuple[str, ...]
    source_generation_id: str
    authoritative_transaction_id: str
    replay_key: str
    semantic_domain: str
    proposed_effect: str
    required_independent_sources: int
    created_at_ns: int
    schema_version: str = PROMOTION_INTENT_SCHEMA_VERSION

    @classmethod
    def build(cls, **fields: object) -> "PromotionIntentRecord":
        base = dict(fields)
        base["schema_version"] = PROMOTION_INTENT_SCHEMA_VERSION
        if "candidate_ids" in base:
            base["candidate_ids"] = list(base["candidate_ids"])
        promotion_intent_id = canonical_record_sha256(base)
        return cls.from_record({"promotion_intent_id": promotion_intent_id, **base})

    def to_record_unchecked(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "promotion_intent_id": self.promotion_intent_id,
            "current_candidate_id": self.current_candidate_id,
            "candidate_ids": list(self.candidate_ids),
            "source_generation_id": self.source_generation_id,
            "authoritative_transaction_id": self.authoritative_transaction_id,
            "replay_key": self.replay_key,
            "semantic_domain": self.semantic_domain,
            "proposed_effect": self.proposed_effect,
            "required_independent_sources": self.required_independent_sources,
            "created_at_ns": self.created_at_ns,
        }

    def to_record(self) -> dict[str, object]:
        self.validate()
        return self.to_record_unchecked()

    @classmethod
    def from_record(cls, record: object) -> "PromotionIntentRecord":
        expected = frozenset({
            "schema_version", "promotion_intent_id", "current_candidate_id",
            "candidate_ids", "source_generation_id", "authoritative_transaction_id",
            "replay_key", "semantic_domain", "proposed_effect",
            "required_independent_sources", "created_at_ns",
        })
        data = _require_exact_keys(record, expected, "promotion_intent_record_invalid")
        if data.get("schema_version") != PROMOTION_INTENT_SCHEMA_VERSION:
            raise ValueError("promotion_intent_schema_unsupported")
        value = cls(
            promotion_intent_id=_sha256(data.get("promotion_intent_id"), "promotion_intent_id"),
            current_candidate_id=_sha256(data.get("current_candidate_id"), "promotion_intent_current_candidate"),
            candidate_ids=_ordered_unique_sha256s(
                data.get("candidate_ids"), "promotion_intent_candidate_ids",
                allow_empty_sequence=False,
            ),
            source_generation_id=_sha256(data.get("source_generation_id"), "promotion_intent_source_generation"),
            authoritative_transaction_id=_sha256(
                data.get("authoritative_transaction_id"), "promotion_intent_authoritative_transaction",
            ),
            replay_key=_sha256(data.get("replay_key"), "promotion_intent_replay_key"),
            semantic_domain=_text(data.get("semantic_domain"), "promotion_intent_semantic_domain"),
            proposed_effect=_text(data.get("proposed_effect"), "promotion_intent_proposed_effect"),
            required_independent_sources=_nonnegative_int(
                data.get("required_independent_sources"), "promotion_intent_required_independent_sources",
            ),
            created_at_ns=_nonnegative_int(data.get("created_at_ns"), "promotion_intent_created_at_ns"),
        )
        value.validate()
        return value

    def validate(self) -> bool:
        if self.schema_version != PROMOTION_INTENT_SCHEMA_VERSION:
            raise ValueError("promotion_intent_schema_unsupported")
        _sha256(self.promotion_intent_id, "promotion_intent_id")
        _sha256(self.current_candidate_id, "promotion_intent_current_candidate")
        candidate_ids = _ordered_unique_sha256s(
            self.candidate_ids, "promotion_intent_candidate_ids", allow_empty_sequence=False,
        )
        if self.current_candidate_id not in candidate_ids:
            raise ValueError("promotion_intent_current_candidate_not_in_cohort")
        _sha256(self.source_generation_id, "promotion_intent_source_generation")
        _sha256(self.authoritative_transaction_id, "promotion_intent_authoritative_transaction")
        _sha256(self.replay_key, "promotion_intent_replay_key")
        _text(self.semantic_domain, "promotion_intent_semantic_domain")
        _text(self.proposed_effect, "promotion_intent_proposed_effect")
        required = _nonnegative_int(
            self.required_independent_sources, "promotion_intent_required_independent_sources",
        )
        if required <= 0 or len(candidate_ids) < required:
            raise ValueError("promotion_intent_independent_support_insufficient")
        _nonnegative_int(self.created_at_ns, "promotion_intent_created_at_ns")
        body = self.to_record_unchecked()
        body.pop("promotion_intent_id")
        if canonical_record_sha256(body) != self.promotion_intent_id:
            raise ValueError("promotion_intent_identity_mismatch")
        return True


@dataclass(frozen=True, slots=True)
class PromotionAuditRecord:
    """Immutable audit schema for one later promotion attempt."""

    promotion_id: str
    candidate_ids: tuple[str, ...]
    source_generation_id: str
    proposed_target_generation_id: str
    accepted: bool
    rejection_reasons: tuple[str, ...]
    semantic_validators_executed: tuple[str, ...]
    bounds_evaluated: tuple[str, ...]
    replay_decision: str
    independence_decision: str
    provenance_roots: tuple[str, ...]
    state_delta_summary: object
    created_at_ns: int
    application_version: str
    model_versions: tuple[tuple[str, str], ...]
    schema_version: str = PROMOTION_AUDIT_SCHEMA_VERSION

    @classmethod
    def build(cls, **fields: object) -> "PromotionAuditRecord":
        base = dict(fields)
        base["schema_version"] = PROMOTION_AUDIT_SCHEMA_VERSION
        for key in (
            "candidate_ids", "rejection_reasons", "semantic_validators_executed", "bounds_evaluated",
            "provenance_roots",
        ):
            if key in base:
                base[key] = list(base[key])
        if "model_versions" in base:
            base["model_versions"] = [list(row) for row in base["model_versions"]]
        promotion_id = canonical_record_sha256(base)
        return cls.from_record({"promotion_id": promotion_id, **base})

    def to_record_unchecked(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "promotion_id": self.promotion_id,
            "candidate_ids": list(self.candidate_ids),
            "source_generation_id": self.source_generation_id,
            "proposed_target_generation_id": self.proposed_target_generation_id,
            "accepted": self.accepted,
            "rejection_reasons": list(self.rejection_reasons),
            "semantic_validators_executed": list(self.semantic_validators_executed),
            "bounds_evaluated": list(self.bounds_evaluated),
            "replay_decision": self.replay_decision,
            "independence_decision": self.independence_decision,
            "provenance_roots": list(self.provenance_roots),
            "state_delta_summary": self.state_delta_summary,
            "created_at_ns": self.created_at_ns,
            "application_version": self.application_version,
            "model_versions": [list(row) for row in self.model_versions],
        }

    def to_record(self) -> dict[str, object]:
        self.validate()
        return self.to_record_unchecked()

    @classmethod
    def from_record(cls, record: object) -> "PromotionAuditRecord":
        expected = frozenset({
            "schema_version", "promotion_id", "candidate_ids", "source_generation_id",
            "proposed_target_generation_id", "accepted", "rejection_reasons",
            "semantic_validators_executed", "bounds_evaluated", "replay_decision",
            "independence_decision", "provenance_roots", "state_delta_summary",
            "created_at_ns", "application_version", "model_versions",
        })
        data = _require_exact_keys(record, expected, "promotion_audit_record_invalid")
        if data.get("schema_version") != PROMOTION_AUDIT_SCHEMA_VERSION:
            raise ValueError("promotion_audit_schema_unsupported")
        if type(data.get("accepted")) is not bool:
            raise ValueError("promotion_audit_accepted_invalid")
        value = cls(
            promotion_id=_sha256(data.get("promotion_id"), "promotion_audit_id"),
            candidate_ids=_ordered_unique_sha256s(data.get("candidate_ids"), "promotion_audit_candidate_ids", allow_empty_sequence=False),
            source_generation_id=_sha256(data.get("source_generation_id"), "promotion_audit_source_generation", allow_empty=True),
            proposed_target_generation_id=_sha256(data.get("proposed_target_generation_id"), "promotion_audit_target_generation"),
            accepted=bool(data.get("accepted")),
            rejection_reasons=_ordered_unique_texts(data.get("rejection_reasons"), "promotion_audit_rejection_reasons"),
            semantic_validators_executed=_ordered_unique_texts(data.get("semantic_validators_executed"), "promotion_audit_validators", allow_empty_sequence=False),
            bounds_evaluated=_ordered_unique_texts(data.get("bounds_evaluated"), "promotion_audit_bounds", allow_empty_sequence=False),
            replay_decision=_text(data.get("replay_decision"), "promotion_audit_replay_decision"),
            independence_decision=_text(data.get("independence_decision"), "promotion_audit_independence_decision"),
            provenance_roots=_ordered_unique_texts(data.get("provenance_roots"), "promotion_audit_provenance_roots"),
            state_delta_summary=data.get("state_delta_summary"),
            created_at_ns=_nonnegative_int(data.get("created_at_ns"), "promotion_audit_created_at_ns"),
            application_version=_text(data.get("application_version"), "promotion_audit_application_version"),
            model_versions=_pairs(data.get("model_versions"), "promotion_audit_model_versions"),
        )
        value.validate()
        return value

    def validate(self) -> bool:
        if self.schema_version != PROMOTION_AUDIT_SCHEMA_VERSION:
            raise ValueError("promotion_audit_schema_unsupported")
        _sha256(self.promotion_id, "promotion_audit_id")
        _ordered_unique_sha256s(self.candidate_ids, "promotion_audit_candidate_ids", allow_empty_sequence=False)
        _sha256(self.source_generation_id, "promotion_audit_source_generation", allow_empty=True)
        _sha256(self.proposed_target_generation_id, "promotion_audit_target_generation")
        if type(self.accepted) is not bool:
            raise ValueError("promotion_audit_accepted_invalid")
        if self.accepted and self.rejection_reasons:
            raise ValueError("promotion_audit_accepted_with_rejections")
        if not self.accepted and not self.rejection_reasons:
            raise ValueError("promotion_audit_rejection_reason_required")
        _ordered_unique_texts(self.rejection_reasons, "promotion_audit_rejection_reasons")
        _ordered_unique_texts(self.semantic_validators_executed, "promotion_audit_validators", allow_empty_sequence=False)
        _ordered_unique_texts(self.bounds_evaluated, "promotion_audit_bounds", allow_empty_sequence=False)
        _ordered_unique_texts(self.provenance_roots, "promotion_audit_provenance_roots")
        _text(self.replay_decision, "promotion_audit_replay_decision")
        _text(self.independence_decision, "promotion_audit_independence_decision")
        _text(self.application_version, "promotion_audit_application_version")
        _pairs(self.model_versions, "promotion_audit_model_versions")
        _nonnegative_int(self.created_at_ns, "promotion_audit_created_at_ns")
        _canonical_json_bytes(self.state_delta_summary)
        body = self.to_record_unchecked()
        body.pop("promotion_id")
        if canonical_record_sha256(body) != self.promotion_id:
            raise ValueError("promotion_audit_identity_mismatch")
        return True


@dataclass(frozen=True, slots=True)
class ModelGenerationManifest:
    """Tamper-evident immutable model-generation manifest, not a DB schema generation."""

    generation_id: str
    application_model_version: str
    created_at_ns: int
    previous_generation_id: str
    previous_generation_manifest_hash: str
    canonical_state_digest: str
    promotion_transaction_id: str
    feature_schema_identity: str
    policy_identity: str
    dependency_graph_identity: str
    evaluation_release_identity: str
    schema_version: str = MODEL_GENERATION_MANIFEST_SCHEMA_VERSION

    @classmethod
    def build(cls, **fields: object) -> "ModelGenerationManifest":
        base = dict(fields)
        base["schema_version"] = MODEL_GENERATION_MANIFEST_SCHEMA_VERSION
        generation_id = hashlib.sha256(
            b"model-generation:" + _canonical_json_bytes(base)
        ).hexdigest()
        return cls.from_record({"generation_id": generation_id, **base})

    def to_record_unchecked(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "application_model_version": self.application_model_version,
            "created_at_ns": self.created_at_ns,
            "previous_generation_id": self.previous_generation_id,
            "previous_generation_manifest_hash": self.previous_generation_manifest_hash,
            "canonical_state_digest": self.canonical_state_digest,
            "promotion_transaction_id": self.promotion_transaction_id,
            "feature_schema_identity": self.feature_schema_identity,
            "policy_identity": self.policy_identity,
            "dependency_graph_identity": self.dependency_graph_identity,
            "evaluation_release_identity": self.evaluation_release_identity,
        }

    def to_record(self) -> dict[str, object]:
        self.validate()
        return self.to_record_unchecked()

    def manifest_sha256(self) -> str:
        return canonical_record_sha256(self.to_record())

    @classmethod
    def from_record(cls, record: object) -> "ModelGenerationManifest":
        expected = frozenset({
            "schema_version", "generation_id", "application_model_version", "created_at_ns",
            "previous_generation_id", "previous_generation_manifest_hash", "canonical_state_digest",
            "promotion_transaction_id", "feature_schema_identity", "policy_identity",
            "dependency_graph_identity", "evaluation_release_identity",
        })
        data = _require_exact_keys(record, expected, "model_generation_manifest_record_invalid")
        if data.get("schema_version") != MODEL_GENERATION_MANIFEST_SCHEMA_VERSION:
            raise ValueError("model_generation_manifest_schema_unsupported")
        value = cls(
            generation_id=_sha256(data.get("generation_id"), "model_generation_id"),
            application_model_version=_text(data.get("application_model_version"), "model_generation_application_version"),
            created_at_ns=_nonnegative_int(data.get("created_at_ns"), "model_generation_created_at_ns"),
            previous_generation_id=_sha256(data.get("previous_generation_id"), "model_generation_previous_id", allow_empty=True),
            previous_generation_manifest_hash=_sha256(data.get("previous_generation_manifest_hash"), "model_generation_previous_manifest", allow_empty=True),
            canonical_state_digest=_sha256(data.get("canonical_state_digest"), "model_generation_state_digest"),
            promotion_transaction_id=_sha256(data.get("promotion_transaction_id"), "model_generation_promotion_transaction", allow_empty=True),
            feature_schema_identity=_text(data.get("feature_schema_identity"), "model_generation_feature_schema"),
            policy_identity=_text(data.get("policy_identity"), "model_generation_policy_identity"),
            dependency_graph_identity=_text(data.get("dependency_graph_identity"), "model_generation_dependency_graph"),
            evaluation_release_identity=_text(data.get("evaluation_release_identity"), "model_generation_evaluation_release", allow_empty=True),
        )
        value.validate()
        return value

    def validate(self) -> bool:
        if self.schema_version != MODEL_GENERATION_MANIFEST_SCHEMA_VERSION:
            raise ValueError("model_generation_manifest_schema_unsupported")
        _sha256(self.generation_id, "model_generation_id")
        _sha256(self.previous_generation_id, "model_generation_previous_id", allow_empty=True)
        _sha256(self.previous_generation_manifest_hash, "model_generation_previous_manifest", allow_empty=True)
        if bool(self.previous_generation_id) != bool(self.previous_generation_manifest_hash):
            raise ValueError("model_generation_lineage_incomplete")
        _sha256(self.canonical_state_digest, "model_generation_state_digest")
        _sha256(self.promotion_transaction_id, "model_generation_promotion_transaction", allow_empty=True)
        for field, value, allow_empty in (
            ("application_version", self.application_model_version, False),
            ("feature_schema", self.feature_schema_identity, False),
            ("policy_identity", self.policy_identity, False),
            ("dependency_graph", self.dependency_graph_identity, False),
            ("evaluation_release", self.evaluation_release_identity, True),
        ):
            _text(value, f"model_generation_{field}", allow_empty=allow_empty)
        _nonnegative_int(self.created_at_ns, "model_generation_created_at_ns")
        body = self.to_record_unchecked()
        body.pop("generation_id")
        expected = hashlib.sha256(
            b"model-generation:" + _canonical_json_bytes(body)
        ).hexdigest()
        if expected != self.generation_id:
            raise ValueError("model_generation_identity_mismatch")
        return True


__all__ = (
    "CANDIDATE_OBSERVATION_SCHEMA_VERSION",
    "MODEL_CANDIDATE_QUARANTINE_SCHEMA_VERSION",
    "MODEL_GENERATION_MANIFEST_SCHEMA_VERSION",
    "PROMOTION_AUDIT_SCHEMA_VERSION",
    "PROMOTION_INTENT_SCHEMA_VERSION",
    "CandidateObservation",
    "ModelCandidateQuarantineManifest",
    "ModelGenerationManifest",
    "PromotionAuditRecord",
    "PromotionIntentRecord",
    "canonical_record_sha256",
)
