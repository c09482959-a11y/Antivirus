"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name

from .constants import (
    MODEL_FAILURE_RECORD_KEYS,
    MODEL_PROBABILITY_FIELDS,
)
from .model_failure_sanitization import sanitize_model_failure_records
from .probability_validation import valid_probability
from .record_validation import (
    invalid_existing_feature_probability_field_failure,
)
from .safe_mapping import (
    json_value,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
    safe_text_result,
    model_evidence_child_path,
    model_evidence_duplicate_key,
    model_evidence_type_marker,
    model_evidence_is_mapping,
)
from .sources import feature_probability_sources

if TYPE_CHECKING:
    from collections.abc import Mapping

def merge_mapping(existing: object, incoming: Mapping[str, object]) -> dict[str, object]:
    merged: dict[str, object] = {}
    if model_evidence_is_mapping(existing):
        merged.update(json_value(existing))
    merged.update(incoming)
    return merged

def sanitize_existing_feature_probabilities(
    existing: object,
) -> tuple[dict[str, object], dict[str, object], tuple[dict[str, object], ...]]:
    """Keep only canonical bounded probability metrics from upstream evidence.

    Upstream ``model_evidence`` may already carry a ``feature_probabilities``
    mapping.  Publication is the final JSON boundary, so control fields such as
    ``*_unavailable_reason`` and ``model_failure`` must be projected into their
    canonical evidence locations instead of being preserved inside the
    probability map.  Unknown fields are explicit degraded evidence rather than
    silently becoming final JSON probability entries.
    """
    if not model_evidence_is_mapping(existing):
        return {}, {}, ()
    keys, read_reason = safe_mapping_keys(existing)
    if read_reason:
        return {}, {"model_evidence.feature_probabilities": read_reason}, (
            invalid_existing_feature_probability_field_failure(
                "model_evidence.feature_probabilities", existing, read_reason
            ),
        )
    sanitized: dict[str, object] = {}
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for raw_key in keys:
        name = safe_str(raw_key).strip()
        value = safe_mapping_get(existing, raw_key)
        source_field = model_evidence_child_path("model_evidence.feature_probabilities", name) if name else "model_evidence.feature_probabilities"
        if name in MODEL_PROBABILITY_FIELDS:
            valid, probability, reason = valid_probability(value)
            if valid:
                sanitized[name] = probability
            else:
                unavailable[source_field] = reason
                failures.append(invalid_existing_feature_probability_field_failure(source_field, value, reason))
            continue
        if name in MODEL_FAILURE_RECORD_KEYS or name.endswith("_unavailable_reason"):
            continue
        reason = "blank_model_probability_field" if not name else "unknown_model_probability_field"
        unavailable[source_field] = reason
        failures.append(invalid_existing_feature_probability_field_failure(source_field, value, reason))
    return sanitized, unavailable, tuple(failures)

def feature_probability_extra_field_evidence(
    record: Mapping[str, object],
    *,
    primary_source_name: str,
) -> tuple[dict[str, object], tuple[dict[str, object], ...]]:
    """Return evidence for non-probability fields inside probability maps.

    Feature-probability containers are final-JSON probability maps, not a
    second place to smuggle control fields or opaque model payloads.  Canonical
    probabilities are handled by probability projection, unavailable-reason
    controls are handled by unavailable-reason projection, and the primary
    source's model_failure is handled by primary failure projection.  Everything
    else becomes explicit degraded evidence so nested/secondary model output
    cannot disappear silently.
    """
    unavailable: dict[str, object] = {}
    failures: list[dict[str, object]] = []
    for source_name, feature_probabilities in feature_probability_sources(record):
        keys, read_reason = safe_mapping_keys(feature_probabilities)
        if read_reason:
            unavailable[source_name] = read_reason
            failures.append(invalid_existing_feature_probability_field_failure(source_name, feature_probabilities, read_reason))
            continue
        for raw_key in keys:
            name = safe_str(raw_key).strip()
            value = safe_mapping_get(feature_probabilities, raw_key)
            source_field = model_evidence_child_path(source_name, name) if name else source_name
            if name in MODEL_PROBABILITY_FIELDS or name.endswith("_unavailable_reason"):
                continue
            if name in MODEL_FAILURE_RECORD_KEYS:
                if source_name == primary_source_name:
                    continue
                records, failure_unavailable, invalid_failure_records = sanitize_model_failure_records(
                    source_field,
                    value,
                )
                unavailable.update(failure_unavailable)
                failures.extend(records)
                failures.extend(invalid_failure_records)
                continue
            if source_name == "model_evidence.feature_probabilities":
                continue
            reason = "blank_model_probability_field" if not name else "unknown_model_probability_field"
            unavailable[source_field] = reason
            failures.append(invalid_existing_feature_probability_field_failure(source_field, value, reason))
    return unavailable, tuple(failures)

def json_existing_model_evidence_value(key: object, value: object) -> object:
    if safe_str(key) in {"unavailable_reasons", "feature_probabilities"}:
        return value
    return json_value(value)

def json_existing_model_evidence_mapping(existing: Mapping[str, object]) -> dict[str, object]:
    keys, reason = safe_mapping_keys(existing)
    if reason:
        return {
            "unavailable_reason": reason,
            "value_type": no_hook_type_name(existing),
        }
    out: dict[str, object] = {}
    for index, key in enumerate(keys):
        key_text, key_reason = safe_text_result(key)
        name = model_evidence_type_marker(key) if key_reason else key_text
        if name in out:
            name = model_evidence_duplicate_key(name, index)
        if key_reason:
            out[name] = {
                "value": None,
                "unavailable_reason": "unreadable_model_evidence_key",
                "value_type": no_hook_type_name(key),
            }
            continue
        out[name] = json_existing_model_evidence_value(key, safe_mapping_get(existing, key))
    return out

__all__ = ('feature_probability_extra_field_evidence', 'json_existing_model_evidence_mapping', 'json_existing_model_evidence_value', 'merge_mapping', 'sanitize_existing_feature_probabilities')
