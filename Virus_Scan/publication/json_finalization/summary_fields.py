"""Compact final JSON summary appenders."""
from __future__ import annotations

from typing import Mapping

from Virus_Scan.publication.json_finalization.base_projection import (
    bounded_dict,
    bounded_signal_value,
)
from Virus_Scan.publication.json_finalization.projection_text import (
    final_json_mapping_get,
    final_json_mapping_items,
)


_MAPPING_ONLY_MODEL_CONTRACT_SUMMARIES = frozenset((
    "model_feature_bundle",
    "model_snapshot",
    "model_evidence_record",
    "probability_record",
    "markov_probability_record",
    "temporal_overlay_record",
    "profile_evidence",
    "profile_evidence_record",
    "cluster_evidence",
    "cluster_evidence_record",
    "graph_evidence",
    "graph_evidence_record",
    "cold_start_record",
    "replay_model_comparison",
    "replay_model_comparison_record",
))


def append_compact_summaries(compact: dict[str, object], record: Mapping[str, object]) -> None:
    for key in (
        "analytical_calibration",
        "layered_detection",
        "api",
        "graph_features",
        "temporal_features",
        "markov_features",
        "model_context",
        "contextual_expected_behavior",
        "context_confidence_amplifier",
        "context_confidence",
        "contextual_confidence",
        "engine_context",
        "engine_confidence",
        "baseline_maturity",
        "profile_selection",
        "detection_profile_context",
        "adaptive_learning",
        "adaptive_weights",
        "pre_rolling_weights",
        "rolling_learned_static",
        "bucket_vector",
        "model_feature_bundle",
        "model_snapshot",
        "model_evidence_record",
        "probability_record",
        "markov_probability_record",
        "temporal_overlay_record",
        "profile_evidence",
        "profile_evidence_record",
        "cluster_evidence",
        "cluster_evidence_record",
        "graph_evidence",
        "graph_evidence_record",
        "cold_start_record",
        "replay_model_comparison",
        "replay_model_comparison_record",
    ):
        value = final_json_mapping_get(record, key)
        if final_json_mapping_items(value) is not None:
            compact[key + "_summary"] = bounded_dict(value, 8)
        elif value is not None and key not in _MAPPING_ONLY_MODEL_CONTRACT_SUMMARIES:
            compact[key + "_summary"] = bounded_signal_value(value)
    vector = final_json_mapping_get(record, "feature_vector")
    if vector is not None:
        compact["feature_vector_summary"] = bounded_signal_value(vector)



__all__ = (
    "append_compact_summaries",
)
