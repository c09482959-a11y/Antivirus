"""Clustering-owned raw-observation projection for authorized learning."""
from __future__ import annotations

from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.clustering.common import (
    cluster_input_sequence,
    cluster_mapping,
    finite_cluster_metric,
)
from Virus_Scan.models.clustering.feature_registry import VECTOR_FEATURE_NAMES
from Virus_Scan.models.clustering.mapping_boundaries import cluster_mapping_get
from Virus_Scan.models.clustering.tag_evidence import cluster_tag_vector_projection
from Virus_Scan.utils.entropy import tag_entropy


def _unit_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0.0:
        return 0.0
    value = numerator / denominator
    return max(0.0, min(1.0, value))


def build_learning_feature_vector(
    tags: object,
    engine_context: object,
) -> list[float]:
    """Build a clustering vector without any current model or cluster outputs."""
    if type(tags) is TagEvidence:
        tag_input = tags
        raw_observation_count = finite_cluster_metric(
            tags.summary.get("raw_observation_count", 0), 0.0,
        )
    else:
        tag_values, tag_reason = cluster_input_sequence(
            tags, reason="cluster_learning_tag_input_unavailable",
        )
        tag_input = tag_values if tag_reason is None else ()
        raw_observation_count = float(len(tag_input)) if tag_reason is None else 0.0
    _bundle, root_tags, _root_count, correlation_groups, tag_reason = (
        cluster_tag_vector_projection(tag_input)
    )
    tags_for_entropy = list(root_tags if tag_reason is None else ())
    context, _context_reason = cluster_mapping(
        engine_context, reason="cluster_learning_engine_context_unavailable",
    )
    values = {
        "tag_count": raw_observation_count if tag_reason is None else 0.0,
        "tag_entropy": finite_cluster_metric(tag_entropy(tags_for_entropy)),
        "unique_tag_count": float(correlation_groups if tag_reason is None else 0),
        "unity_context": finite_cluster_metric(cluster_mapping_get(context, "unity", 0.0)),
        "renpy_context": finite_cluster_metric(cluster_mapping_get(context, "renpy", 0.0)),
        "rpgm_context": finite_cluster_metric(cluster_mapping_get(context, "rpgm", 0.0)),
        "media_context": finite_cluster_metric(cluster_mapping_get(context, "media", 0.0)),
        "other_context": finite_cluster_metric(
            cluster_mapping_get(context, "other", cluster_mapping_get(context, "unknown", 0.0)),
        ),
    }
    return [finite_cluster_metric(values.get(name, 0.0)) for name in VECTOR_FEATURE_NAMES]


__all__ = (
    "build_learning_feature_vector",
)
