"""Detection-owned boundary for adaptive model signal collection.

This module is the single adaptive-scoring import point for model-layer
probability/evidence signals. It intentionally does not score, cap, or mutate
model state; it only delegates to the existing public model APIs so
``model_score`` does not reach across multiple model modules directly.
"""

from __future__ import annotations
from typing import TYPE_CHECKING


from Virus_Scan.models.api.adaptive_signals import (
    MIN_CLUSTER_MEMBERS_FOR_CONTEXT as MODEL_MIN_CLUSTER_MEMBERS_FOR_CONTEXT,
    MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT as MODEL_MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT,
    adaptive_cluster_signal,
    adaptive_markov_signal,
    adaptive_profile_signal,
    canonical_behavior_flow,
    cluster_risk_score_evidence,
    compute_graph_relationship_layer,
    compute_markov_features,
    context_cluster_quality,
    coordinated_model_validation_signal,
    extension_profile_anomaly,
    get_graph_risk_enhanced,
    graph_risk_enhanced_evidence,
)
from Virus_Scan.models.api.temporal_contracts import snapshot_temporal
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_event_sequence,
)
from Virus_Scan.models.contracts.model_feature_bundle import make_model_feature_bundle
from Virus_Scan.models.contracts.model_failure import (
    make_model_failure_record,
    materialize_model_failure_record,
)

if TYPE_CHECKING:
    from collections.abc import (
        Iterable,
        Mapping,
    )

AdaptiveFeatureValue = object


def model_feature_bundle(values: Mapping[str, AdaptiveFeatureValue], *, model_version: str) -> Mapping[str, AdaptiveFeatureValue]:
    return make_model_feature_bundle(values, model_version=model_version)


def model_failure_record(
    *,
    model_name: AdaptiveFeatureValue,
    failure_type: AdaptiveFeatureValue,
    reason: AdaptiveFeatureValue,
    affected_fields: Iterable[AdaptiveFeatureValue] | None = None,
    degraded: AdaptiveFeatureValue = True,
    output_affecting: AdaptiveFeatureValue = True,
    details: Mapping[str, AdaptiveFeatureValue] | None = None,
    model_version: str = "model_failure_record_v1",
) -> Mapping[str, AdaptiveFeatureValue]:
    return make_model_failure_record(
        model_name=model_name,
        failure_type=failure_type,
        reason=reason,
        affected_fields=affected_fields,
        degraded=degraded,
        output_affecting=output_affecting,
        details=details,
        model_version=model_version,
    )


def materialize_model_failure(record: Mapping[str, AdaptiveFeatureValue]) -> dict[str, AdaptiveFeatureValue]:
    return materialize_model_failure_record(record)


def model_graph_risk_enhanced(node: AdaptiveFeatureValue) -> float:
    return float(get_graph_risk_enhanced(node))


def model_graph_risk_enhanced_evidence(node: AdaptiveFeatureValue) -> Mapping[str, AdaptiveFeatureValue]:
    return graph_risk_enhanced_evidence(node)


def model_graph_relationship_layer(
    node: AdaptiveFeatureValue,
    *,
    tags: object = None,
) -> Mapping[str, AdaptiveFeatureValue]:
    return compute_graph_relationship_layer(node, tags=tags)


def model_temporal_snapshot(node: AdaptiveFeatureValue) -> Mapping[str, AdaptiveFeatureValue]:
    return snapshot_temporal(node)


def model_behavior_flow(events: Iterable[AdaptiveFeatureValue] | None) -> tuple[str, ...]:
    return canonical_behavior_flow(adaptive_public_event_sequence(events))


def model_markov_features(prev_stage: AdaptiveFeatureValue, behavior_flow: Iterable[AdaptiveFeatureValue], curr_stage: AdaptiveFeatureValue) -> Mapping[str, AdaptiveFeatureValue]:
    return compute_markov_features(prev_stage, behavior_flow, curr_stage)


def model_cluster_risk_score_evidence(node: AdaptiveFeatureValue) -> Mapping[str, AdaptiveFeatureValue]:
    return cluster_risk_score_evidence(node)


def model_context_cluster_quality(
    node: AdaptiveFeatureValue,
    tags: Iterable[AdaptiveFeatureValue] | None,
    *,
    adaptive_learning: Mapping[str, AdaptiveFeatureValue] | None = None,
) -> Mapping[str, AdaptiveFeatureValue]:
    return context_cluster_quality(node, tags, adaptive_learning=adaptive_learning)


MIN_CLUSTER_MEMBERS_FOR_CONTEXT = int(MODEL_MIN_CLUSTER_MEMBERS_FOR_CONTEXT)
MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT = float(MODEL_MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT)


def model_adaptive_profile_signal(
    node: AdaptiveFeatureValue,
    tags: Iterable[AdaptiveFeatureValue] | None,
    *,
    preliminary_risk: AdaptiveFeatureValue = 0.0,
    strings_blob: AdaptiveFeatureValue = "",
) -> Mapping[str, AdaptiveFeatureValue]:
    return adaptive_profile_signal(
        node,
        tags,
        preliminary_risk=preliminary_risk,
        strings_blob=strings_blob,
    )


def model_adaptive_markov_signal(prev_stage: AdaptiveFeatureValue, curr_stage: AdaptiveFeatureValue, ordered_events: Iterable[AdaptiveFeatureValue] | None) -> Mapping[str, AdaptiveFeatureValue]:
    return adaptive_markov_signal(prev_stage, curr_stage, adaptive_public_event_sequence(ordered_events))


def model_adaptive_cluster_signal(node: AdaptiveFeatureValue, tags: Iterable[AdaptiveFeatureValue] | None) -> Mapping[str, AdaptiveFeatureValue]:
    return adaptive_cluster_signal(node, tags)


def model_extension_profile_anomaly(
    engine: AdaptiveFeatureValue,
    file_path: AdaptiveFeatureValue,
    tags: Iterable[AdaptiveFeatureValue] | None,
    baseline_risk: AdaptiveFeatureValue,
    *,
    strings_blob: AdaptiveFeatureValue = "",
    api_calls: Iterable[AdaptiveFeatureValue] | None = None,
    ordered_events: Iterable[AdaptiveFeatureValue] | None = None,
) -> Mapping[str, AdaptiveFeatureValue]:
    return extension_profile_anomaly(
        engine,
        file_path,
        tags,
        baseline_risk,
        strings_blob=strings_blob,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )


def model_coordinated_validation_signal(
    engine: AdaptiveFeatureValue,
    file_path: AdaptiveFeatureValue,
    tags: Iterable[AdaptiveFeatureValue] | None,
    *,
    strings_blob: AdaptiveFeatureValue = "",
    api_calls: Iterable[AdaptiveFeatureValue] | None = None,
    ordered_events: Iterable[AdaptiveFeatureValue] | None = None,
) -> Mapping[str, AdaptiveFeatureValue]:
    return coordinated_model_validation_signal(
        engine,
        file_path,
        tags,
        strings_blob=strings_blob,
        api_calls=api_calls,
        ordered_events=ordered_events,
    )


__all__ = (
    "MIN_CLUSTER_MEMBERS_FOR_CONTEXT",
    "MIN_CLUSTER_TAG_OVERLAP_FOR_CONTEXT",
    "materialize_model_failure",
    "model_adaptive_cluster_signal",
    "model_adaptive_markov_signal",
    "model_adaptive_profile_signal",
    "model_behavior_flow",
    "model_cluster_risk_score_evidence",
    "model_context_cluster_quality",
    "model_coordinated_validation_signal",
    "model_extension_profile_anomaly",
    "model_failure_record",
    "model_feature_bundle",
    "model_graph_relationship_layer",
    "model_graph_risk_enhanced",
    "model_graph_risk_enhanced_evidence",
    "model_markov_features",
    "model_temporal_snapshot",
)
