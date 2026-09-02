"""Strict current engine-profile schema validation."""
from __future__ import annotations

from dataclasses import dataclass
import math

from Virus_Scan.contracts.temporal_baseline import (
    validate_temporal_baselines,
)
from Virus_Scan.models.profiles.chain_state import (
    PROFILE_CHAIN_STATE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.common import profile_safe_text
from Virus_Scan.models.profiles.contamination import (
    PROFILE_CONTAMINATION_SCHEMA_VERSION,
    validate_profile_contamination_state,
)
from Virus_Scan.models.profiles.decision_history import (
    validate_profile_decision_history,
)
from Virus_Scan.models.profiles.feature_registry import (
    PROFILE_RAW_FEATURE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TAG_EVIDENCE_SCHEMA_VERSION,
)
from Virus_Scan.models.profiles.transaction_state import (
    validate_transaction_store,
)
from Virus_Scan.models.profiles.vector_statistics import (
    validate_profile_vector_statistics,
)

_MISSING = object()
_REQUIRED_MODEL_STATE_MAPS = (
    "vector_baselines", "temporal_baselines", "markov_baselines",
    "cluster_baselines", "learning_rejections", "learning_transactions",
    "learning_applied_keys",
)
_MODEL_STATE_KEYS = frozenset((*_REQUIRED_MODEL_STATE_MAPS,
    "contamination", "decision_history", "feature_registry_versions",
))
_CHAIN_STATE_KEYS = frozenset((
    "schema_version", "registry_version", "registry_digest", "suspicious_audit",
))


class ProfileSchemaInvariantError(RuntimeError):
    """Persisted profile state violates the canonical schema contract."""


def _schema_engine_text(engine: object) -> str:
    engine_text = profile_safe_text(engine, replacement="other").lower()
    return engine_text if engine_text != "" else "other"


def _schema_error(engine: object, reason: object) -> str:
    return _schema_engine_text(engine) + ": " + profile_safe_text(
        reason, replacement="profile schema invalid",
    )


def _finite_number(value: object) -> bool:
    return (
        type(value) in (int, float)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _nonnegative_int(value: object) -> bool:
    return type(value) is int and not isinstance(value, bool) and value >= 0



def _validate_tag_evidence(value: object) -> None:
    if type(value) is not dict:
        raise ValueError("tag_evidence must be an object")
    if value.get("schema_version") != PROFILE_TAG_EVIDENCE_SCHEMA_VERSION:
        raise ValueError("tag_evidence schema invalid")
    if type(value.get("records")) is not dict or type(value.get("summary")) is not dict:
        raise ValueError("tag_evidence state invalid")


def _validate_chain_state(value: object) -> None:
    if type(value) is not dict:
        raise ValueError("chains must be an object")
    if frozenset(value) != _CHAIN_STATE_KEYS:
        raise ValueError("chain fields invalid")
    if value.get("schema_version") != PROFILE_CHAIN_STATE_SCHEMA_VERSION:
        raise ValueError("chain schema invalid")
    if type(value.get("suspicious_audit")) is not dict:
        raise ValueError("chain audit invalid")


def _validate_extension_baseline(key: object, baseline: object) -> None:
    if type(key) is not str or key == "" or type(baseline) is not dict:
        raise ValueError("extension baseline invalid")
    if baseline.get("extension") != key:
        raise ValueError("extension baseline identity mismatch")
    if not _nonnegative_int(baseline.get("files")):
        raise ValueError("extension baseline files invalid")
    for field in (
        "behavior_buckets", "timeline_baseline",
        "risk", "learning_gate",
    ):
        if type(baseline.get(field)) is not dict:
            raise ValueError(field + " must be an object")
    _validate_tag_evidence(baseline.get("tag_evidence"))
    _validate_chain_state(baseline.get("chains"))
    validate_profile_vector_statistics(baseline.get("vector_baseline"))



def _validate_temporal_baseline_store(value: object) -> None:
    validate_temporal_baselines(value)

def _validate_model_state(model_state: object) -> None:
    if type(model_state) is not dict:
        raise ValueError("model_state must be an object")
    if frozenset(model_state) != _MODEL_STATE_KEYS:
        raise ValueError("model_state fields invalid")
    for field in _REQUIRED_MODEL_STATE_MAPS:
        if type(model_state.get(field)) is not dict:
            raise ValueError(field + " must be an object")
    applied = model_state["learning_applied_keys"]
    if type(applied.get("profile")) is not dict or len(applied) != 1:
        raise ValueError("learning_applied_keys profile ledger invalid")
    for replay_key, ordinal in applied["profile"].items():
        if (
            type(replay_key) is not str or len(replay_key) != 64
            or type(ordinal) is not int or isinstance(ordinal, bool) or ordinal < 0
        ):
            raise ValueError("learning_applied_keys profile record invalid")
    _validate_temporal_baseline_store(model_state["temporal_baselines"])
    validate_transaction_store(model_state["learning_transactions"])
    validate_profile_contamination_state(model_state.get("contamination"))
    validate_profile_decision_history(model_state.get("decision_history"))
    versions = model_state.get("feature_registry_versions")
    expected = {
        "profile_raw_features": PROFILE_RAW_FEATURE_SCHEMA_VERSION,
        "profile_contamination": PROFILE_CONTAMINATION_SCHEMA_VERSION,
        "learning_transaction": PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
    }
    if versions != expected:
        raise ValueError("feature registry versions invalid")


@dataclass(frozen=True, slots=True)
class EngineProfileSchemaSnapshot:
    """Immutable profile schema view used at load/write boundaries."""

    engine: str
    schema_version: int
    has_extension_baselines: bool
    extension_baselines_is_mapping: bool
    model_state_is_mapping: bool

    @classmethod
    def from_profile(
        cls, profile: object, *, expected_engine: str,
    ) -> "EngineProfileSchemaSnapshot":
        if type(profile) is not dict:
            raise ProfileSchemaInvariantError(
                _schema_error(expected_engine, "profile must be an object"),
            )
        raw_schema = dict.get(profile, "schema_version")
        if type(raw_schema) is not int or type(raw_schema) is bool:
            raise ProfileSchemaInvariantError(
                _schema_error(expected_engine, "invalid profile schema_version"),
            )
        extension_baselines = dict.get(profile, "extension_baselines", _MISSING)
        model_state = dict.get(profile, "model_state")
        engine = dict.get(profile, "engine")
        return cls(
            engine=str.__str__(engine).lower() if isinstance(engine, str) else "",
            schema_version=raw_schema,
            has_extension_baselines=extension_baselines is not _MISSING,
            extension_baselines_is_mapping=type(extension_baselines) is dict,
            model_state_is_mapping=type(model_state) is dict,
        )

    def validate(self, *, expected_engine: str) -> bool:
        engine = _schema_engine_text(expected_engine)
        if self.engine != engine:
            raise ProfileSchemaInvariantError(_schema_error(engine, "profile engine mismatch"))
        if self.schema_version != PROFILE_SCHEMA_VERSION:
            raise ProfileSchemaInvariantError(_schema_error(engine, "invalid profile schema_version"))
        if not self.has_extension_baselines:
            raise ProfileSchemaInvariantError(_schema_error(engine, "missing extension_baselines"))
        if not self.extension_baselines_is_mapping:
            raise ProfileSchemaInvariantError(_schema_error(engine, "extension_baselines must be an object"))
        if not self.model_state_is_mapping:
            raise ProfileSchemaInvariantError(_schema_error(engine, "model_state must be an object"))
        return True


def validate_engine_profile_schema(profile: object, *, expected_engine: str) -> bool:
    snapshot = EngineProfileSchemaSnapshot.from_profile(
        profile, expected_engine=expected_engine,
    )
    snapshot.validate(expected_engine=expected_engine)
    try:
        if not _finite_number(dict.get(profile, "created")) or not _finite_number(dict.get(profile, "updated")):
            raise ValueError("profile timestamps invalid")
        baselines = dict.get(profile, "extension_baselines")
        for key, baseline in dict.items(baselines):
            _validate_extension_baseline(key, baseline)
        _validate_model_state(dict.get(profile, "model_state"))
    except ValueError as exc:
        raise ProfileSchemaInvariantError(
            _schema_error(expected_engine, str(exc)),
        ) from None
    return True


__all__ = (
    "PROFILE_SCHEMA_VERSION",
    "EngineProfileSchemaSnapshot",
    "ProfileSchemaInvariantError",
    "validate_engine_profile_schema",
)
