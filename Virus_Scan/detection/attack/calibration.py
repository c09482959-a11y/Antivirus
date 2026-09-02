"""Canonical out-of-sample calibration owner for Enterprise ATT&CK probability."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from math import exp, isfinite
from types import MappingProxyType

from Virus_Scan.contracts.numeric_boundaries import exact_bounded_nonnegative_int
from Virus_Scan.contracts.text_boundaries import exact_bounded_text
from Virus_Scan.detection.attack.mapping.contracts import AttackTechniquePolicy
from Virus_Scan.detection.attack.validation import (
    bounded_float,
    exact_hex,
    official_attack_id,
    ordered_text_tuple,
)
from Virus_Scan.detection.attack.versioning import ATTACK_MAPPING_POLICY_VERSION

ATTACK_CALIBRATION_SCHEMA_VERSION = "stage2636_10011_attack_calibration_v1"
ATTACK_FINAL_FUSION_CALIBRATION_STATE = "unavailable_pending_out_of_sample_refit"
ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST = sha256(
    b"stage2636.10011:confirmed-implementation-evidence-completeness:v1"
).hexdigest()
_CALIBRATION_METHODS = frozenset({"platt"})


def _finite_coefficient(value: object, reason: str, *, positive: bool = False) -> float:
    if type(value) not in (int, float) or type(value) is bool:
        raise TypeError(reason)
    number = float(value)
    if not isfinite(number) or abs(number) > 64.0 or (positive and number <= 0.0):
        raise ValueError(reason)
    return number


def _technique_ids(value: object) -> tuple[str, ...]:
    values = ordered_text_tuple(
        value, "attack_calibration_technique_ids_invalid", maximum_items=64,
    )
    if not values:
        raise ValueError("attack_calibration_technique_ids_invalid")
    out = tuple(
        official_attack_id(item, "attack_calibration_technique_id_invalid")
        for item in values
    )
    if any(not item.startswith("T") or item.startswith("TA") for item in out):
        raise ValueError("attack_calibration_technique_id_invalid")
    return out


def _digest_tuple(value: object, reason: str) -> tuple[str, ...]:
    values = ordered_text_tuple(value, reason, maximum_items=64)
    return tuple(exact_hex(item, reason, length=64) for item in values)


def _artifact_identity_fields(
    calibration_id: object,
    feature_policy_schema_digest: object,
    technique_ids: object,
    evaluation_manifest_digest: object,
    requirement_digest_set: object,
    training_partition_manifest_digest: object,
    out_of_fold_prediction_digest: object,
    calibration_method: object,
) -> tuple[object, ...]:
    identity = exact_bounded_text(
        calibration_id, "attack_calibration_id_invalid", maximum=128,
    )
    feature_digest = exact_hex(
        feature_policy_schema_digest,
        "attack_calibration_feature_schema_invalid",
        length=64,
    )
    if feature_digest != ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST:
        raise ValueError("attack_calibration_feature_schema_invalid")
    techniques = _technique_ids(technique_ids)
    evaluation_digest = exact_hex(
        evaluation_manifest_digest,
        "attack_calibration_evaluation_manifest_invalid",
        length=64,
    )
    requirement_digests = _digest_tuple(
        requirement_digest_set, "attack_calibration_requirement_digest_invalid",
    )
    training_digest = exact_hex(
        training_partition_manifest_digest,
        "attack_calibration_training_manifest_invalid", length=64,
    )
    prediction_digest = exact_hex(
        out_of_fold_prediction_digest,
        "attack_calibration_prediction_digest_invalid", length=64,
    )
    method = exact_bounded_text(
        calibration_method, "attack_calibration_method_invalid", maximum=32,
    )
    if method not in _CALIBRATION_METHODS:
        raise ValueError("attack_calibration_method_invalid")
    return (
        identity, feature_digest, techniques, evaluation_digest,
        requirement_digests, training_digest, prediction_digest, method,
    )


def _artifact_metric_fields(
    intercept: object, slope: object, brier_score: object, log_loss: object,
    expected_calibration_error: object, sample_count: object,
) -> tuple[float, float, float, float, float, int]:
    resolved_intercept = _finite_coefficient(
        intercept, "attack_calibration_intercept_invalid",
    )
    resolved_slope = _finite_coefficient(
        slope, "attack_calibration_slope_invalid", positive=True,
    )
    brier = bounded_float(brier_score, "attack_calibration_brier_invalid")
    resolved_log_loss = bounded_float(
        log_loss, "attack_calibration_log_loss_invalid", maximum=64.0,
    )
    ece = bounded_float(
        expected_calibration_error, "attack_calibration_ece_invalid",
    )
    samples = exact_bounded_nonnegative_int(
        sample_count, "attack_calibration_sample_count_invalid", maximum=10_000_000,
    )
    if samples < 2:
        raise ValueError("attack_calibration_sample_count_invalid")
    return resolved_intercept, resolved_slope, brier, resolved_log_loss, ece, samples


def _artifact_scope_fields(
    valid_claim_scopes: object, valid_platforms: object,
    future_time_validation_digest: object, policy_version: object, version: object,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    claim_scopes = ordered_text_tuple(
        valid_claim_scopes, "attack_calibration_claim_scopes_invalid", maximum_items=32,
    )
    platforms = ordered_text_tuple(
        valid_platforms, "attack_calibration_platforms_invalid", maximum_items=32,
    )
    if not claim_scopes or not platforms:
        raise ValueError("attack_calibration_scope_platform_required")
    future_digest = exact_hex(
        future_time_validation_digest,
        "attack_calibration_future_validation_invalid", length=64,
    )
    if policy_version != ATTACK_MAPPING_POLICY_VERSION:
        raise ValueError("attack_calibration_policy_version_invalid")
    if version != ATTACK_CALIBRATION_SCHEMA_VERSION:
        raise ValueError("attack_calibration_version_invalid")
    return claim_scopes, platforms, future_digest


@dataclass(frozen=True, slots=True)
class AttackCalibrationArtifact:
    """One immutable, out-of-sample Platt calibration artifact."""

    calibration_id: str
    feature_policy_schema_digest: str
    technique_ids: tuple[str, ...]
    evaluation_manifest_digest: str
    requirement_digest_set: tuple[str, ...]
    training_partition_manifest_digest: str
    out_of_fold_prediction_digest: str
    calibration_method: str
    intercept: float
    slope: float
    brier_score: float
    log_loss: float
    expected_calibration_error: float
    sample_count: int
    valid_claim_scopes: tuple[str, ...]
    valid_platforms: tuple[str, ...]
    future_time_validation_digest: str
    policy_version: str
    version: str = ATTACK_CALIBRATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not AttackCalibrationArtifact:
            raise TypeError("attack_calibration_owner_invalid")
        identity_fields = _artifact_identity_fields(
            self.calibration_id, self.feature_policy_schema_digest,
            self.technique_ids, self.evaluation_manifest_digest,
            self.requirement_digest_set, self.training_partition_manifest_digest,
            self.out_of_fold_prediction_digest, self.calibration_method,
        )
        metric_fields = _artifact_metric_fields(
            self.intercept, self.slope, self.brier_score, self.log_loss,
            self.expected_calibration_error, self.sample_count,
        )
        claim_scopes, platforms, future_digest = _artifact_scope_fields(
            self.valid_claim_scopes, self.valid_platforms,
            self.future_time_validation_digest, self.policy_version, self.version,
        )
        field_names = (
            "calibration_id", "feature_policy_schema_digest", "technique_ids",
            "evaluation_manifest_digest", "requirement_digest_set",
            "training_partition_manifest_digest", "out_of_fold_prediction_digest",
            "calibration_method", "intercept", "slope", "brier_score",
            "log_loss", "expected_calibration_error", "sample_count",
        )
        for field_name, value in zip(field_names, (*identity_fields, *metric_fields)):
            object.__setattr__(self, field_name, value)
        object.__setattr__(self, "valid_claim_scopes", claim_scopes)
        object.__setattr__(self, "valid_platforms", platforms)
        object.__setattr__(self, "future_time_validation_digest", future_digest)
        object.__setattr__(self, "policy_version", ATTACK_MAPPING_POLICY_VERSION)
        object.__setattr__(self, "version", ATTACK_CALIBRATION_SCHEMA_VERSION)

    def probability(self, raw_score: object) -> float:
        score = bounded_float(raw_score, "attack_calibration_raw_score_invalid")
        logit = max(-60.0, min(60.0, self.intercept + self.slope * score))
        return round(1.0 / (1.0 + exp(-logit)), 6)

    def to_record(self) -> dict[str, object]:
        return {field: object.__getattribute__(self, field) for field in self.__slots__}


@dataclass(frozen=True, slots=True)
class AttackCalibrationOutcome:
    probability: float
    calibration_artifact_id: str
    unavailable_reason: str

    def __post_init__(self) -> None:
        if type(self) is not AttackCalibrationOutcome:
            raise TypeError("attack_calibration_outcome_owner_invalid")
        probability = bounded_float(
            self.probability, "attack_calibration_outcome_probability_invalid",
        )
        calibration_id = exact_bounded_text(
            self.calibration_artifact_id,
            "attack_calibration_outcome_id_invalid",
            maximum=128,
            allow_blank=True,
        )
        reason = exact_bounded_text(
            self.unavailable_reason,
            "attack_calibration_outcome_reason_invalid",
            maximum=256,
            allow_blank=True,
        )
        if probability > 0.0:
            if not calibration_id or reason:
                raise ValueError("attack_calibration_outcome_ready_invalid")
        elif calibration_id or not reason:
            raise ValueError("attack_calibration_outcome_unavailable_invalid")
        object.__setattr__(self, "probability", probability)
        object.__setattr__(self, "calibration_artifact_id", calibration_id)
        object.__setattr__(self, "unavailable_reason", reason)


ATTACK_CALIBRATION_ARTIFACTS: tuple[AttackCalibrationArtifact, ...] = ()
ATTACK_CALIBRATION_ARTIFACT_BY_ID = MappingProxyType({})


def _artifact_index(
    artifacts: object,
) -> dict[str, AttackCalibrationArtifact]:
    if type(artifacts) is not tuple or len(artifacts) > 4096:
        raise TypeError("attack_calibration_artifacts_invalid")
    if any(type(item) is not AttackCalibrationArtifact for item in artifacts):
        raise TypeError("attack_calibration_artifacts_invalid")
    index = {item.calibration_id: item for item in artifacts}
    if len(index) != len(artifacts):
        raise ValueError("attack_calibration_duplicate_id")
    return index


def resolve_attack_probability(
    policy: AttackTechniquePolicy,
    *,
    raw_score: object,
    claim_scopes: object,
    platforms: object,
    artifacts: object = ATTACK_CALIBRATION_ARTIFACTS,
) -> AttackCalibrationOutcome:
    """Return calibrated probability only for an exact current artifact binding."""
    if type(policy) is not AttackTechniquePolicy:
        raise TypeError("attack_calibration_policy_required")
    scopes = ordered_text_tuple(
        claim_scopes, "attack_calibration_runtime_scopes_invalid", maximum_items=32,
    )
    runtime_platforms = ordered_text_tuple(
        platforms, "attack_calibration_runtime_platforms_invalid", maximum_items=32,
    )
    score = bounded_float(raw_score, "attack_calibration_raw_score_invalid")
    if policy.admission_state != "production_mature":
        return AttackCalibrationOutcome(0.0, "", "policy_not_production_mature")
    if not policy.calibration_artifact_id:
        return AttackCalibrationOutcome(0.0, "", "calibration_artifact_unbound")
    artifact = _artifact_index(artifacts).get(policy.calibration_artifact_id)
    if artifact is None:
        return AttackCalibrationOutcome(0.0, "", "calibration_artifact_missing")
    if policy.technique_id not in artifact.technique_ids:
        return AttackCalibrationOutcome(0.0, "", "calibration_technique_mismatch")
    if artifact.policy_version != policy.policy_version:
        return AttackCalibrationOutcome(0.0, "", "calibration_policy_version_mismatch")
    if artifact.evaluation_manifest_digest != policy.evaluation_manifest_digest:
        return AttackCalibrationOutcome(0.0, "", "calibration_evaluation_mismatch")
    if artifact.requirement_digest_set != policy.requirement_digest_set:
        return AttackCalibrationOutcome(0.0, "", "calibration_requirement_mismatch")
    if not set(scopes).issubset(artifact.valid_claim_scopes):
        return AttackCalibrationOutcome(0.0, "", "calibration_claim_scope_mismatch")
    if not set(runtime_platforms).issubset(artifact.valid_platforms):
        return AttackCalibrationOutcome(0.0, "", "calibration_platform_mismatch")
    probability = artifact.probability(score)
    if probability <= 0.0:
        return AttackCalibrationOutcome(0.0, "", "calibration_probability_unavailable")
    return AttackCalibrationOutcome(probability, artifact.calibration_id, "")


__all__ = (
    "ATTACK_CALIBRATION_ARTIFACTS",
    "ATTACK_CALIBRATION_ARTIFACT_BY_ID",
    "ATTACK_CALIBRATION_FEATURE_POLICY_SCHEMA_DIGEST",
    "ATTACK_CALIBRATION_SCHEMA_VERSION",
    "ATTACK_FINAL_FUSION_CALIBRATION_STATE",
    "AttackCalibrationArtifact",
    "AttackCalibrationOutcome",
    "resolve_attack_probability",
)
