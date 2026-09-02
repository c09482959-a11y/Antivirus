"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING

import math

from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from .constants import (
    MODEL_EVIDENCE_WRITER_VERSION,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .safe_mapping import (
    mapping_readable,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
    safe_repr,
    safe_str,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def contains_non_finite_float(value: object) -> bool:
    if type(value) is float:
        return not math.isfinite(value)
    if model_evidence_is_mapping(value):
        keys, reason = safe_mapping_keys(value)
        if reason:
            return False
        return any(contains_non_finite_float(safe_mapping_get(value, key)) for key in keys)
    if model_evidence_is_sequence(value) or type(value) in (set, frozenset):
        return any(contains_non_finite_float(item) for item in value)
    return False

def contains_non_finite_existing_model_payload(value: object) -> bool:
    if type(value) is float:
        return not math.isfinite(value)
    if model_evidence_is_mapping(value):
        keys, reason = safe_mapping_keys(value)
        if reason:
            return False
        return any(
            contains_non_finite_existing_model_payload(safe_mapping_get(value, key))
            for key in keys
            if safe_str(key) not in {"unavailable_reasons", "feature_probabilities"}
        )
    if model_evidence_is_sequence(value) or type(value) in (set, frozenset):
        return any(contains_non_finite_existing_model_payload(item) for item in value)
    return False

def contains_non_finite_model_signal(value: object) -> bool:
    if type(value) is float:
        return not math.isfinite(value)
    if model_evidence_is_mapping(value):
        keys, reason = safe_mapping_keys(value)
        if reason:
            return False
        return any(
            contains_non_finite_model_signal(safe_mapping_get(value, key))
            for key in keys
            if safe_str(key) != "feature_probabilities"
        )
    if model_evidence_is_sequence(value) or type(value) in (set, frozenset):
        return any(contains_non_finite_model_signal(item) for item in value)
    return False

def invalid_model_signal_failures(record: Mapping[str, object]) -> tuple[dict[str, object], ...]:
    failures: list[dict[str, object]] = []
    for field in MODEL_SIGNAL_SOURCE_FIELDS:
        if not safe_mapping_contains(record, field):
            continue
        value = safe_mapping_get(record, field)
        if value is None:
            continue
        reason = ""
        if model_evidence_is_mapping(value) and not mapping_readable(value):
            reason = "unreadable_model_signal_record"
        elif contains_non_finite_model_signal(value):
            reason = "non_finite_model_signal_value"
        if reason == "":
            continue
        failures.append(
            {
                "model_name": field,
                "failure_type": "model_signal_projection_failed",
                "reason": reason,
                "affected_fields": (field,),
                "model_version": MODEL_EVIDENCE_WRITER_VERSION,
                "details": {
                    "source_field": field,
                    "value_type": no_hook_type_name(value),
                    "value_repr": safe_repr(value),
                },
            }
        )
    return tuple(failures)

__all__ = ('contains_non_finite_existing_model_payload', 'contains_non_finite_float', 'contains_non_finite_model_signal', 'invalid_model_signal_failures')
