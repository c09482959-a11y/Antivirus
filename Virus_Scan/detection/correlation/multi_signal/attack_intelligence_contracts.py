"""Immutable contracts for the canonical attack-intelligence ensemble."""
from __future__ import annotations

from dataclasses import dataclass

from Virus_Scan.contracts.runtime_function_identity import is_runtime_native_function
from math import exp, isfinite
from typing import Callable

from Virus_Scan.detection.tags.heuristics.classifier_evidence import ClassifierEvidenceResult

ATTACK_INTELLIGENCE_EVIDENCE_VERSION = "attack_intelligence_evidence_v3"
_DIRECT_KINDS = frozenset({"observed", "normalized"})
_INFERRED_KINDS = frozenset({"derived", "composite"})
_ALLOWED_KINDS = _DIRECT_KINDS | _INFERRED_KINDS
_ALLOWED_CLASSIFIER_YARA_STATES = frozenset({
    "present_unverified", "unavailable", "verified_conflicting_or_rejected",
    "verified_corroborating",
})
_ALLOWED_YARA_INTEGRITY_STATES = frozenset({"present_unverified", "verified"})


def _require_text(value: object, reason: str) -> str:
    if type(value) is not str or not value:
        raise TypeError(reason)
    return value


def _require_text_tuple(value: object, reason: str) -> tuple[str, ...]:
    if type(value) is not tuple or any(type(item) is not str or not item for item in value):
        raise TypeError(reason)
    return value


def _require_number(value: object, reason: str, *, minimum: float = 0.0, maximum: float | None = None) -> float:
    if type(value) not in (int, float) or type(value) is bool or not isfinite(value):
        raise TypeError(reason)
    number = float(value)
    if number < minimum or (maximum is not None and number > maximum):
        raise ValueError(reason)
    return number




@dataclass(frozen=True, slots=True)
class AttackClassifierSpec:
    classifier_id: str
    version: str
    family: str
    detector: Callable[[object], ClassifierEvidenceResult]
    score_ceiling: float
    calibration_slope: float
    calibration_midpoint: float
    production_threshold: float
    minimum_distinct_roots: int = 1
    minimum_direct_roots: int = 1
    required_evidence_kinds: frozenset[str] = _ALLOWED_KINDS

    def __post_init__(self) -> None:
        _require_text(self.classifier_id, "attack_classifier_identity_required")
        _require_text(self.version, "attack_classifier_identity_required")
        _require_text(self.family, "attack_classifier_identity_required")
        if not is_runtime_native_function(self.detector):
            raise TypeError("attack_classifier_function_required")
        _require_number(self.score_ceiling, "attack_classifier_score_ceiling_invalid", minimum=1e-12)
        _require_number(self.calibration_slope, "attack_classifier_calibration_slope_invalid", minimum=1e-12)
        midpoint = _require_number(self.calibration_midpoint, "attack_classifier_calibration_midpoint_invalid", maximum=1.0)
        threshold = _require_number(self.production_threshold, "attack_classifier_threshold_invalid", maximum=1.0)
        if midpoint <= 0.0 or midpoint >= 1.0 or threshold <= 0.0 or threshold >= 1.0:
            raise ValueError("attack_classifier_probability_boundary_invalid")
        if type(self.minimum_distinct_roots) is not int or self.minimum_distinct_roots < 1:
            raise ValueError("attack_classifier_minimum_roots_invalid")
        if type(self.minimum_direct_roots) is not int or self.minimum_direct_roots < 0:
            raise ValueError("attack_classifier_minimum_direct_roots_invalid")
        if (
            type(self.required_evidence_kinds) is not frozenset
            or not self.required_evidence_kinds
            or any(type(item) is not str for item in self.required_evidence_kinds)
        ):
            raise TypeError("attack_classifier_evidence_kinds_required")
        if not self.required_evidence_kinds <= _ALLOWED_KINDS:
            raise ValueError("attack_classifier_evidence_kind_invalid")

    def calibrate(self, raw_score: object) -> float:
        if type(raw_score) not in (int, float) or type(raw_score) is bool:
            return 0.0
        if raw_score <= 0.0 or not isfinite(raw_score):
            return 0.0
        ratio = min(1.0, raw_score / self.score_ceiling)
        baseline = 1.0 / (1.0 + exp(self.calibration_slope * self.calibration_midpoint))
        value = 1.0 / (1.0 + exp(-self.calibration_slope * (ratio - self.calibration_midpoint)))
        return round(max(0.0, min(1.0, (value - baseline) / max(1e-9, 1.0 - baseline))), 6)


@dataclass(frozen=True, slots=True)
class AttackClassifierRecord:
    classifier_id: str
    classifier_version: str
    family: str
    matched_root_evidence_ids: tuple[str, ...]
    matched_canonical_tag_ids: tuple[str, ...]
    matched_yara_rule_ids: tuple[str, ...]
    direct_evidence_count: int
    inferred_evidence_count: int
    correlation_groups: tuple[str, ...]
    raw_score: float
    family_probability: float
    uncertainty: float
    support: int
    ready: bool
    rejected_reasons: tuple[str, ...]
    explanation_fields: tuple[str, ...]
    yara_state: str
    production_threshold: float

    def __post_init__(self) -> None:
        _require_text(self.classifier_id, "attack_classifier_record_identity_required")
        _require_text(self.classifier_version, "attack_classifier_record_identity_required")
        _require_text(self.family, "attack_classifier_record_identity_required")
        for value, reason in (
            (self.matched_root_evidence_ids, "attack_classifier_root_ids_invalid"),
            (self.matched_canonical_tag_ids, "attack_classifier_tag_ids_invalid"),
            (self.matched_yara_rule_ids, "attack_classifier_yara_ids_invalid"),
            (self.correlation_groups, "attack_classifier_groups_invalid"),
            (self.rejected_reasons, "attack_classifier_reasons_invalid"),
            (self.explanation_fields, "attack_classifier_explanations_invalid"),
        ):
            _require_text_tuple(value, reason)
        for value in (self.direct_evidence_count, self.inferred_evidence_count, self.support):
            if type(value) is not int or value < 0:
                raise TypeError("attack_classifier_support_invalid")
        raw_score = _require_number(
            self.raw_score, "attack_classifier_raw_score_invalid",
        )
        probability = _require_number(
            self.family_probability,
            "attack_classifier_probability_invalid",
            maximum=1.0,
        )
        _require_number(
            self.uncertainty, "attack_classifier_uncertainty_invalid", maximum=1.0,
        )
        threshold = _require_number(
            self.production_threshold,
            "attack_classifier_threshold_invalid",
            maximum=1.0,
        )
        if threshold <= 0.0 or threshold >= 1.0:
            raise ValueError("attack_classifier_threshold_invalid")
        if type(self.ready) is not bool:
            raise TypeError("attack_classifier_ready_bool_required")
        yara_state = _require_text(
            self.yara_state, "attack_classifier_yara_state_required",
        )
        if yara_state not in _ALLOWED_CLASSIFIER_YARA_STATES:
            raise ValueError("attack_classifier_yara_state_invalid")
        identity_tuples = (
            self.matched_root_evidence_ids,
            self.matched_canonical_tag_ids,
            self.matched_yara_rule_ids,
            self.correlation_groups,
            self.rejected_reasons,
            self.explanation_fields,
        )
        if any(len(value) != len(set(value)) for value in identity_tuples):
            raise ValueError("attack_classifier_record_duplicate_identity")
        if self.support != len(self.matched_root_evidence_ids):
            raise ValueError("attack_classifier_support_root_mismatch")
        if self.direct_evidence_count + self.inferred_evidence_count > self.support:
            raise ValueError("attack_classifier_evidence_count_mismatch")
        if self.ready and self.rejected_reasons:
            raise ValueError("attack_classifier_ready_rejection_conflict")
        if not self.ready and not self.rejected_reasons:
            raise ValueError("attack_classifier_unready_reason_required")
        if not self.ready and probability != 0.0:
            raise ValueError("attack_classifier_unready_probability_invalid")
        if probability > 0.0 and (raw_score <= 0.0 or self.support == 0):
            raise ValueError("attack_classifier_probability_support_invalid")

    def to_record(self) -> dict[str, object]:
        return {
            "classifier_id": self.classifier_id,
            "classifier_version": self.classifier_version,
            "family": self.family,
            "matched_root_evidence_ids": self.matched_root_evidence_ids,
            "matched_canonical_tag_ids": self.matched_canonical_tag_ids,
            "matched_yara_rule_ids": self.matched_yara_rule_ids,
            "direct_evidence_count": self.direct_evidence_count,
            "inferred_evidence_count": self.inferred_evidence_count,
            "correlation_groups": self.correlation_groups,
            "raw_score": self.raw_score,
            "family_probability": self.family_probability,
            "uncertainty": self.uncertainty,
            "support": self.support,
            "ready": self.ready,
            "rejected_reasons": self.rejected_reasons,
            "explanation_fields": self.explanation_fields,
            "yara_state": self.yara_state,
            "production_threshold": self.production_threshold,
        }


@dataclass(frozen=True, slots=True)
class AttackEnsemblePolicy:
    version: str
    aggregate_method: str
    calibration_version: str
    yara_corroboration_bonus: float
    maximum_records: int
    evaluation_provenance: str
    yara_mapping_version: str
    aggregate_threshold: float

    def __post_init__(self) -> None:
        _require_text(self.version, "attack_policy_version_required")
        _require_text(self.aggregate_method, "attack_policy_aggregate_required")
        _require_text(self.calibration_version, "attack_policy_calibration_required")
        _require_number(self.yara_corroboration_bonus, "attack_policy_yara_bonus_invalid", maximum=1.0)
        if type(self.maximum_records) is not int or self.maximum_records < 1:
            raise TypeError("attack_policy_record_limit_invalid")
        _require_text(self.evaluation_provenance, "attack_policy_evaluation_required")
        _require_text(self.yara_mapping_version, "attack_policy_yara_mapping_required")
        threshold = _require_number(self.aggregate_threshold, "attack_policy_threshold_invalid", maximum=1.0)
        if threshold <= 0.0 or threshold >= 1.0:
            raise ValueError("attack_policy_threshold_invalid")

__all__ = (
    "ATTACK_INTELLIGENCE_EVIDENCE_VERSION",
    "AttackClassifierRecord", "AttackClassifierSpec",
    "AttackEnsemblePolicy",
)
