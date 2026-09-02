"""Internal helpers for publication model-evidence projection.

These modules only materialize evidence that already exists on result records;
they do not compute model probabilities or call model/scoring implementations.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from .constants import (
    MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS,
    MODEL_SIGNAL_SOURCE_FIELDS,
)
from .safe_mapping import (
    mapping_at,
    safe_mapping_contains,
    safe_mapping_get,
    safe_mapping_keys,
    safe_str,
    model_evidence_child_path,
    model_evidence_index_path,
    model_evidence_is_container,
    model_evidence_is_mapping,
    model_evidence_is_sequence,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

def feature_probability_sources(record: Mapping[str, object]) -> tuple[tuple[str, Mapping[str, object]], ...]:
    """Return every already-computed feature-probability container on a record.

    Direct ``feature_probabilities`` remains the canonical primary source, but
    adaptive/layered/profile model outputs may also carry nested probability
    records.  Publication must surface malformed nested probabilities as model
    evidence instead of assuming another boundary saw them.
    """
    sources: list[tuple[str, Mapping[str, object]]] = []
    seen_source_names: set[str] = set()

    def add_source(source_name: str, candidate: object) -> None:
        if not model_evidence_is_mapping(candidate):
            return
        keys, reason = safe_mapping_keys(candidate)
        if reason != '' or len(keys) == 0:
            return
        if source_name in seen_source_names:
            return
        seen_source_names.add(source_name)
        sources.append((source_name, candidate))

    def visit_nested_signal(source_path: str, value: object) -> None:
        if model_evidence_is_mapping(value):
            keys, reason = safe_mapping_keys(value)
            if reason != '':
                return
            feature_probabilities = safe_mapping_get(value, "feature_probabilities")
            if model_evidence_is_mapping(feature_probabilities):
                add_source(model_evidence_child_path(source_path, "feature_probabilities"), feature_probabilities)
            for raw_key in keys:
                key = safe_str(raw_key)
                if key == "feature_probabilities":
                    continue
                item = safe_mapping_get(value, raw_key)
                if model_evidence_is_container(item):
                    visit_nested_signal(model_evidence_child_path(source_path, key), item)
            return
        if model_evidence_is_sequence(value):
            for index, item in enumerate(value):
                if model_evidence_is_container(item):
                    visit_nested_signal(model_evidence_index_path(source_path, index), item)

    add_source("feature_probabilities", safe_mapping_get(record, "feature_probabilities"))
    for metadata_key in MODEL_FEATURE_PROBABILITY_CONTAINER_FIELDS:
        metadata = mapping_at(record, metadata_key)
        add_source(model_evidence_child_path(metadata_key, "feature_probabilities"), safe_mapping_get(metadata, "feature_probabilities"))
    for metadata_key in MODEL_SIGNAL_SOURCE_FIELDS:
        if not safe_mapping_contains(record, metadata_key):
            continue
        value = safe_mapping_get(record, metadata_key)
        if model_evidence_is_container(value):
            visit_nested_signal(metadata_key, value)
    model_evidence = mapping_at(record, "model_evidence")
    add_source("model_evidence.feature_probabilities", safe_mapping_get(model_evidence, "feature_probabilities"))
    explanation = mapping_at(record, "explanation")
    add_source("explanation.feature_probabilities", safe_mapping_get(explanation, "feature_probabilities"))
    return tuple(sources)

def feature_probability_source_with_name(record: Mapping[str, object]) -> tuple[str, Mapping[str, object]]:
    sources = feature_probability_sources(record)
    if not sources:
        return "", {}
    return sources[0]

def feature_probability_source(record: Mapping[str, object]) -> Mapping[str, object]:
    return feature_probability_source_with_name(record)[1]

__all__ = ('feature_probability_source', 'feature_probability_source_with_name', 'feature_probability_sources')
