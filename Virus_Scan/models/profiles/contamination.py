"""Profiles-owned pre-mutation contamination and context-integrity policy."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
from typing import Final

from Virus_Scan.models.profiles.context import contextual_profile_learning_policy
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.models.profiles.learning_decision import canonical_context_identity
from Virus_Scan.models.profiles.vector_statistics import record_profile_vector_quarantine

PROFILE_CONTAMINATION_SCHEMA_VERSION: Final[str] = "profile_contamination_v1"
PROFILE_DRIFT_MIN_TRUSTED_SUPPORT: Final[int] = 12
PROFILE_DRIFT_DIMENSION_DELTA: Final[float] = 0.45
PROFILE_DRIFT_MIN_DIMENSIONS: Final[int] = 6
_MAX_QUARANTINE_RECORDS: Final[int] = 256
_IDENTITY_FIELDS: Final[tuple[str, ...]] = (
    "signer", "vendor", "package_family", "publisher", "product_family",
)
_UNSAFE_TRUE_FIELDS: Final[tuple[str, ...]] = (
    "mixed_evidence", "unknown_evidence", "malicious_evidence",
    "dangerous_anchor", "triage_blocked", "learning_quarantined",
)


@dataclass(frozen=True, slots=True)
class ContaminationPlan:
    """Immutable result of the sole pre-mutation contamination decision."""

    accepted: bool
    reason: str
    context_key: str
    diversity_key: str
    drift_dimensions: tuple[int, ...] = ()


def default_profile_contamination_state() -> dict[str, object]:
    return {
        "schema_version": PROFILE_CONTAMINATION_SCHEMA_VERSION,
        "quarantine_ordinal": 0,
        "quarantine_records": {},
        "context_collision_count": 0,
        "drift_quarantine_count": 0,
        "unsafe_evidence_count": 0,
    }



def validate_profile_contamination_state(value: object) -> bool:
    if type(value) is not dict:
        raise ValueError("profile_contamination_state_invalid")
    if value.get("schema_version") != PROFILE_CONTAMINATION_SCHEMA_VERSION:
        raise ValueError("profile_contamination_schema_invalid")
    records = value.get("quarantine_records")
    if type(records) is not dict or len(records) > _MAX_QUARANTINE_RECORDS:
        raise ValueError("profile_contamination_records_invalid")
    for key in (
        "quarantine_ordinal", "context_collision_count",
        "drift_quarantine_count", "unsafe_evidence_count",
    ):
        count = value.get(key)
        if type(count) is not int or isinstance(count, bool) or count < 0:
            raise ValueError("profile_contamination_count_invalid")
    for replay_key, record in records.items():
        if type(replay_key) is not str or type(record) is not dict:
            raise ValueError("profile_contamination_record_invalid")
        if type(record.get("ordinal")) is not int:
            raise ValueError("profile_contamination_record_invalid")
        if type(record.get("reason")) is not str:
            raise ValueError("profile_contamination_record_invalid")
        dimensions = record.get("drift_dimensions")
        if type(dimensions) is not list or any(
            type(index) is not int or isinstance(index, bool) or index < 0
            for index in dimensions
        ):
            raise ValueError("profile_contamination_record_invalid")
    return True

def _exact_contamination_state(profile: dict[str, object]) -> dict[str, object]:
    model_state = profile.get("model_state")
    if type(model_state) is not dict:
        raise ValueError("profile_model_state_unavailable")
    state = model_state.get("contamination")
    validate_profile_contamination_state(state)
    return state


def _context_fields(file_path: str) -> dict[str, object]:
    identity = contextual_profile_learning_policy(
        file_path, trusted_benign=True, degraded=False,
    )
    fields = identity.as_record_fields()
    if type(fields) is not dict:
        raise ValueError("profile_context_identity_unavailable")
    return fields


def _context_key(context: tuple[tuple[str, str], ...]) -> str:
    fields = dict(context)
    return fields.get("learning_baseline_key") or fields.get("baseline_key") or ""


def _safe_identity_value(value: object) -> str:
    if type(value) is str:
        return value.strip().lower()
    if type(value) in (int, float) and not isinstance(value, bool):
        numeric = float(value)
        return format(numeric, ".17g") if math.isfinite(numeric) else ""
    return ""


def _validation_identity(validation: object) -> tuple[str, str] | None:
    if type(validation) is not dict:
        return None
    containers: list[dict[str, object]] = [validation]
    for key in ("identity", "package_identity", "signer_identity", "metadata"):
        value = validation.get(key)
        if type(value) is dict:
            containers.append(value)
    for container in containers:
        for key in _IDENTITY_FIELDS:
            text = _safe_identity_value(container.get(key))
            if text:
                return key, text
    return None


def _diversity_key(request: object) -> str:
    identity = _validation_identity(getattr(request, "validation", None))
    if identity is None:
        return getattr(request.decision, "observation_digest")
    payload = json.dumps(identity, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _unsafe_evidence_reason(validation: object) -> str | None:
    if type(validation) is not dict:
        return "profile_validation_evidence_invalid"
    for key in _UNSAFE_TRUE_FIELDS:
        if validation.get(key) is True:
            return "profile_unsafe_evidence_" + key
    disposition = validation.get("evidence_disposition")
    if type(disposition) is str and disposition.strip().lower() in {
        "mixed", "unknown", "malicious", "quarantined",
    }:
        return "profile_unsafe_evidence_disposition"
    return None


def _finite_profile_vector(vector: object) -> tuple[float, ...]:
    if type(vector) not in (list, tuple) or len(vector) != len(PROFILE_RAW_FEATURE_NAMES):
        raise ValueError("profile_raw_feature_vector_invalid")
    values: list[float] = []
    for value in vector:
        if type(value) not in (int, float) or isinstance(value, bool):
            raise ValueError("profile_raw_feature_vector_invalid")
        numeric = float(value)
        if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
            raise ValueError("profile_raw_feature_vector_invalid")
        values.append(numeric)
    return tuple(values)


def _drift_dimensions(profile: dict[str, object], context_key: str, vector: tuple[float, ...]) -> tuple[int, ...]:
    baselines = profile.get("extension_baselines")
    baseline = baselines.get(context_key) if type(baselines) is dict else None
    statistics = baseline.get("vector_baseline") if type(baseline) is dict else None
    if type(statistics) is not dict:
        return ()
    trusted = statistics.get("trusted_count")
    median = statistics.get("median")
    if type(trusted) is not int or isinstance(trusted, bool) or trusted < PROFILE_DRIFT_MIN_TRUSTED_SUPPORT:
        return ()
    if type(median) is not list or len(median) != len(vector):
        raise ValueError("profile_drift_baseline_invalid")
    dimensions: list[int] = []
    for index, (value, expected) in enumerate(zip(vector, median, strict=True)):
        if type(expected) not in (int, float) or isinstance(expected, bool):
            raise ValueError("profile_drift_baseline_invalid")
        expected_number = float(expected)
        if not math.isfinite(expected_number):
            raise ValueError("profile_drift_baseline_invalid")
        if abs(value - expected_number) > PROFILE_DRIFT_DIMENSION_DELTA:
            dimensions.append(index)
    return tuple(dimensions) if len(dimensions) >= PROFILE_DRIFT_MIN_DIMENSIONS else ()


def _record_quarantine(
    profile: dict[str, object], request: object, *, reason: str,
    context_key: str, drift_dimensions: tuple[int, ...] = (),
) -> None:
    state = _exact_contamination_state(profile)
    ordinal = state["quarantine_ordinal"] + 1
    state["quarantine_ordinal"] = ordinal
    if reason == "profile_context_identity_collision":
        state["context_collision_count"] += 1
    elif reason == "profile_drift_quarantined":
        state["drift_quarantine_count"] += 1
    else:
        state["unsafe_evidence_count"] += 1
    replay_key = request.decision.replay_key
    records = state["quarantine_records"]
    records[replay_key] = {
        "ordinal": ordinal,
        "reason": reason,
        "observation_id": request.decision.observation_id,
        "observation_digest": request.decision.observation_digest,
        "context_key": context_key,
        "drift_dimensions": list(drift_dimensions),
    }
    if len(records) > _MAX_QUARANTINE_RECORDS:
        ranked = sorted(
            (
                record.get("ordinal", 0) if type(record) is dict else 0,
                key,
            )
            for key, record in records.items()
        )
        for _ordinal, key in ranked[:-_MAX_QUARANTINE_RECORDS]:
            records.pop(key, None)
    if reason == "profile_drift_quarantined":
        baselines = profile.get("extension_baselines")
        baseline = baselines.get(context_key) if type(baselines) is dict else None
        if type(baseline) is dict:
            baseline["vector_baseline"] = record_profile_vector_quarantine(
                baseline.get("vector_baseline"),
            )


def preflight_learning_contamination(
    profile: dict[str, object], request: object, profile_vector: object,
) -> ContaminationPlan:
    """Accept or quarantine one exact request before any model target mutates."""
    _exact_contamination_state(profile)
    vector = _finite_profile_vector(profile_vector)
    unsafe_reason = _unsafe_evidence_reason(request.validation)
    actual_context = canonical_context_identity({
        "contextual_engine_identity": _context_fields(request.file_path),
    })
    actual_key = _context_key(actual_context)
    if actual_context != request.decision.context_identity or actual_key == "":
        _record_quarantine(
            profile, request, reason="profile_context_identity_collision",
            context_key=actual_key,
        )
        return ContaminationPlan(False, "profile_context_identity_collision", actual_key, "")
    if unsafe_reason is not None:
        _record_quarantine(
            profile, request, reason=unsafe_reason, context_key=actual_key,
        )
        return ContaminationPlan(False, unsafe_reason, actual_key, "")
    drift = _drift_dimensions(profile, actual_key, vector)
    if drift:
        _record_quarantine(
            profile, request, reason="profile_drift_quarantined",
            context_key=actual_key, drift_dimensions=drift,
        )
        return ContaminationPlan(
            False, "profile_drift_quarantined", actual_key, "", drift,
        )
    return ContaminationPlan(
        True, "profile_contamination_preflight_accepted", actual_key,
        _diversity_key(request),
    )


__all__ = (
    "ContaminationPlan",
    "PROFILE_CONTAMINATION_SCHEMA_VERSION",
    "PROFILE_DRIFT_DIMENSION_DELTA",
    "PROFILE_DRIFT_MIN_DIMENSIONS",
    "PROFILE_DRIFT_MIN_TRUSTED_SUPPORT",
    "default_profile_contamination_state",
    "preflight_learning_contamination",
    "validate_profile_contamination_state",
)
