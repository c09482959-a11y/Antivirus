"""Canonical evidence and likelihood support for Markov feature projection."""
from __future__ import annotations

import math

from Virus_Scan.contracts.behavior_rarity import behavior_rarity_from_flow
from Virus_Scan.contracts.markov_learning import MARKOV_CONTEXT_GLOBAL
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.markov.counters import markov_count_value
from Virus_Scan.models.markov.feature_boundaries import (
    _markov_mapping_float,
    _markov_mapping_is_true,
    _markov_mapping_value,
)
from Virus_Scan.models.markov.flow import canonical_behavior_flow
from Virus_Scan.runtime.model_state import runtime_model_mapping_snapshot
from Virus_Scan.utils.probability import safe_clamp

def markov_tag_rarity_score(tags: object) -> float:
    """Return the separate global tag-rarity side signal from owned state."""
    flow = canonical_behavior_flow(tags)
    baseline = runtime_model_mapping_snapshot("GLOBAL_TAG_BASELINE")
    return behavior_rarity_from_flow(flow, baseline)


def markov_mapping_total(mapping: object) -> tuple[int, str]:
    """Return total positive support from an exact owned mapping snapshot."""
    if mapping is None:
        return 0, ""
    items = no_hook_mapping_items(mapping)
    if items is None:
        return 0, "non_mapping_markov_baseline"
    total = 0
    first_error = ""
    for _raw_key, raw_value in items:
        count, error = markov_count_value(raw_value)
        if error != "" or count is None:
            if first_error == "":
                first_error = error or "invalid_markov_count"
            continue
        total += int(count)
    return total, first_error


def ready_probability(record: object) -> float | None:
    if _markov_mapping_is_true(record, "ready") is not True:
        return None
    value, reason = _markov_mapping_float(record, "probability")
    if reason != "" or not math.isfinite(value):
        return None
    return max(1e-300, min(1.0, value))


def record_reason(record: object, default: str) -> str:
    value = _markov_mapping_value(record, "reason", default)
    return value if type(value) is str and value != "" else default


def record_fallback_level(record: object) -> str:
    value = _markov_mapping_value(record, "fallback_level", MARKOV_CONTEXT_GLOBAL)
    return value if type(value) is str and value != "" else MARKOV_CONTEXT_GLOBAL


def record_confidence(record: object) -> float:
    value, reason = _markov_mapping_float(record, "fallback_confidence")
    return safe_clamp(value) if reason == "" else 0.0


def surprisal_projection(probabilities: tuple[float, ...]) -> tuple[float, float]:
    """Return average surprisal and its bounded anomaly projection."""
    if not probabilities:
        return 0.0, 0.0
    average = sum(-math.log(value) for value in probabilities) / len(probabilities)
    return average, safe_clamp(1.0 - math.exp(-average))


__all__ = (
    "markov_mapping_total",
    "markov_tag_rarity_score",
    "ready_probability",
    "record_confidence",
    "record_fallback_level",
    "record_reason",
    "surprisal_projection",
)
