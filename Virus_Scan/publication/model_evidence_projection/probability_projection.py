"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import MODEL_PROBABILITY_FIELDS
from .probability_validation import (
    invalid_probability_failure,
    valid_probability,
)
from .safe_mapping import (
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_read,
    model_evidence_child_path,
    model_evidence_unavailable_field,
)
from .sources import feature_probability_sources

if TYPE_CHECKING:
    from collections.abc import Mapping

def probability_fields(feature_probabilities: Mapping[str, object]) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    out: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for field in MODEL_PROBABILITY_FIELDS:
        if not safe_mapping_contains(feature_probabilities, field):
            continue
        value_readable, field_value = safe_mapping_read(feature_probabilities, field)
        if not value_readable:
            exception_message = "feature probability payload unavailable"
            raise RuntimeError(exception_message)
        valid, probability, reason = valid_probability(field_value)
        if valid:
            out[field] = probability
            continue
        unavailable[field] = reason
        failures.append(invalid_probability_failure(field, field_value, reason))
    return out, unavailable, tuple(failures)

def secondary_probability_fields(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
    primary_feature_probabilities: Mapping[str, object],
) -> dict[str, object]:
    """Return valid non-primary probabilities not claimed by the primary map.

    A direct/primary probability source may contain only one model family while
    nested adaptive/profile metadata carries another already-computed probability.
    Publication must materialize those additional valid probabilities, but it must
    not let a secondary source cleanly overwrite or replace a primary field that
    was present but invalid.
    """
    out: dict[str, object] = {}
    primary_claimed_fields = {
        field
        for field in MODEL_PROBABILITY_FIELDS
        if safe_mapping_contains(primary_feature_probabilities, field)
    }
    for source_name, feature_probabilities in feature_probability_sources(record):
        if source_name == primary_source_name:
            continue
        if source_name.startswith("explanation."):
            continue
        # Secondary sources may carry recognized degraded-state evidence
        # (``*_unavailable_reason`` or model failure records) next to valid
        # already-computed probabilities.  Those controls are projected by the
        # unavailable/failure evidence paths below; they must not cause a valid,
        # non-primary probability for a different model family to disappear.
        for field in MODEL_PROBABILITY_FIELDS:
            if field in primary_claimed_fields or field in out:
                continue
            if not safe_mapping_contains(feature_probabilities, field):
                continue
            if safe_mapping_contains(feature_probabilities, model_evidence_unavailable_field(field)):
                continue
            field_value = safe_mapping_get(feature_probabilities, field)
            valid, probability, _reason = valid_probability(field_value)
            if valid:
                out[field] = probability
    return out

def secondary_probability_failures(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    """Return explicit evidence for malformed non-primary model probabilities."""
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for source_name, feature_probabilities in feature_probability_sources(record):
        if source_name == primary_source_name:
            continue
        for field in MODEL_PROBABILITY_FIELDS:
            if not safe_mapping_contains(feature_probabilities, field):
                continue
            field_value = safe_mapping_get(feature_probabilities, field)
            valid, _probability, reason = valid_probability(field_value)
            if valid:
                continue
            unavailable[model_evidence_child_path(source_name, field)] = reason
            failure = invalid_probability_failure(field, field_value, reason)
            failure["model_name"] = model_evidence_child_path(source_name, field)
            failure["affected_fields"] = (source_name, field)
            failure["details"] = {
                **failure.get("details", {}),
                "source_container": source_name,
            }
            failures.append(failure)
    return unavailable, tuple(failures)

__all__ = ('probability_fields', 'secondary_probability_failures', 'secondary_probability_fields')
