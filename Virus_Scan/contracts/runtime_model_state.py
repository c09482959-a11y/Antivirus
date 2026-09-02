"""Exact-current runtime model-state envelope contract.

This module owns the serialized schema identity for the complete persisted
runtime-model snapshot.  It intentionally does not migrate historical records:
runtime hydration either receives the exact current envelope or fails before
any model owner is mutated.
"""
from __future__ import annotations

from typing import Final
import math

RUNTIME_MODEL_STATE_SCHEMA_VERSION: Final[int] = 4

RUNTIME_MODEL_STATE_REQUIRED_FIELDS: Final[frozenset[str]] = frozenset({
    "schema_version",
    "updated",
    "markov_state_schema_version",
    "markov_state_migration_evidence",
    "transition_counts",
    "global_tag_baseline",
    "global_tag_pair_baseline",
    "filetype_baseline",
    "cluster_state",
    "temporal_state",
    "learning_applied_keys",
})
RUNTIME_MODEL_STATE_OPTIONAL_FIELDS: Final[frozenset[str]] = frozenset({
    "model_state_unavailable_reasons",
})
RUNTIME_MODEL_STATE_FIELDS: Final[frozenset[str]] = (
    RUNTIME_MODEL_STATE_REQUIRED_FIELDS | RUNTIME_MODEL_STATE_OPTIONAL_FIELDS
)


def runtime_model_state_envelope_error(value: object) -> str | None:
    """Return the exact-current envelope failure reason, or ``None``.

    Only an exact builtin ``dict`` is a serialized runtime-model record.  This
    avoids invoking caller-owned mapping hooks at an authority boundary.
    Nested model domains keep their own validators; this function owns only the
    complete top-level record identity and mandatory section presence/types.
    """
    if type(value) is not dict:
        return "runtime_model_snapshot_record_invalid"
    keys = set(dict.keys(value))
    missing = RUNTIME_MODEL_STATE_REQUIRED_FIELDS - keys
    if missing:
        return "runtime_model_snapshot_fields_missing"
    if not keys.issubset(RUNTIME_MODEL_STATE_FIELDS):
        return "runtime_model_snapshot_fields_unknown"
    schema = dict.get(value, "schema_version")
    if type(schema) is not int or type(schema) is bool:
        return "runtime_model_snapshot_schema_invalid"
    if schema != RUNTIME_MODEL_STATE_SCHEMA_VERSION:
        return "runtime_model_snapshot_schema_unsupported"
    updated = dict.get(value, "updated")
    if type(updated) is not int or type(updated) is bool or updated < 0:
        return "runtime_model_snapshot_revision_invalid"
    markov_schema = dict.get(value, "markov_state_schema_version")
    if type(markov_schema) is not int or type(markov_schema) is bool or markov_schema < 1:
        return "runtime_model_markov_schema_invalid"
    migration_evidence = dict.get(value, "markov_state_migration_evidence")
    if type(migration_evidence) is not str or not migration_evidence:
        return "runtime_model_markov_migration_evidence_invalid"
    if type(dict.get(value, "transition_counts")) not in (list, tuple):
        return "runtime_model_transition_section_invalid"
    if type(dict.get(value, "global_tag_baseline")) is not dict:
        return "runtime_model_tag_section_invalid"
    if type(dict.get(value, "global_tag_pair_baseline")) not in (list, tuple):
        return "runtime_model_pair_section_invalid"
    if type(dict.get(value, "filetype_baseline")) is not dict:
        return "runtime_model_filetype_section_invalid"
    if type(dict.get(value, "cluster_state")) is not dict:
        return "runtime_model_cluster_section_invalid"
    if type(dict.get(value, "temporal_state")) is not dict:
        return "runtime_model_temporal_section_invalid"
    if type(dict.get(value, "learning_applied_keys")) is not dict:
        return "runtime_model_learning_section_invalid"
    unavailable = dict.get(value, "model_state_unavailable_reasons", ())
    if type(unavailable) not in (list, tuple):
        return "runtime_model_unavailable_reasons_invalid"
    return None



def _detach_runtime_value(value: object, *, depth: int = 0) -> object:
    if depth > 10:
        raise ValueError("runtime_model_snapshot_depth_exceeded")
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("runtime_model_snapshot_nonfinite")
        return value
    if type(value) is list:
        if len(value) > 200_000:
            raise ValueError("runtime_model_snapshot_sequence_unbounded")
        return [_detach_runtime_value(item, depth=depth + 1) for item in list(value)]
    if type(value) is tuple:
        if len(value) > 200_000:
            raise ValueError("runtime_model_snapshot_sequence_unbounded")
        return tuple(_detach_runtime_value(item, depth=depth + 1) for item in tuple(value))
    if type(value) is dict:
        if len(value) > 200_000:
            raise ValueError("runtime_model_snapshot_mapping_unbounded")
        detached: dict[str, object] = {}
        for raw_key, raw_item in dict.items(value):
            if type(raw_key) is not str or raw_key == "":
                raise ValueError("runtime_model_snapshot_key_invalid")
            key = str.__str__(raw_key)
            if key in detached:
                raise ValueError("runtime_model_snapshot_key_duplicate")
            detached[key] = _detach_runtime_value(raw_item, depth=depth + 1)
        return detached
    raise TypeError("runtime_model_snapshot_value_invalid")


def materialize_current_runtime_model_state(value: object) -> dict[str, object]:
    """Validate and detach one exact-current complete runtime-model record."""
    reason = runtime_model_state_envelope_error(value)
    if reason is not None:
        raise ValueError(reason)
    try:
        detached = _detach_runtime_value(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(str(exc)) from exc
    if type(detached) is not dict:
        raise ValueError("runtime_model_snapshot_record_invalid")
    return detached

def require_current_runtime_model_state(value: object) -> dict[str, object]:
    """Return an exact-current serialized record or raise before authority."""
    return materialize_current_runtime_model_state(value)


__all__ = (
    "RUNTIME_MODEL_STATE_FIELDS",
    "RUNTIME_MODEL_STATE_OPTIONAL_FIELDS",
    "RUNTIME_MODEL_STATE_REQUIRED_FIELDS",
    "RUNTIME_MODEL_STATE_SCHEMA_VERSION",
    "materialize_current_runtime_model_state",
    "require_current_runtime_model_state",
    "runtime_model_state_envelope_error",
)
