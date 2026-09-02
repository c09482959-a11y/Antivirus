"""Canonical detection model/correlation context ownership.

This module owns the immutable model-context/reconciliation inputs shared by
graph, temporal, Markov, clustering, and behavior-flow consumers. It keeps
model-context construction out of the giant tag scanner while preserving
existing scoring, tag, chain, graph, temporal, and clustering semantics.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from Virus_Scan.detection.correlation.behavioral.behavior_flow import detection_behavior_flow
from Virus_Scan.detection.correlation.temporal.timeline import real_timeline_events
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_evidence import recoverable_failure_evidence
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.contracts.model_context_snapshot import ModelContextSnapshot
from Virus_Scan.contracts.model_projection_identity import require_model_projection_identity
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    scoreable_tag_evidence,
    scoreable_tag_set,
)
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tag_evidence
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_cluster_projection,
    detection_feature_vector,
    detection_graph_features,
    detection_markov_features,
    detection_temporal_snapshot,
)
from Virus_Scan.detection.profiles.contracts import DetectionProfileContext
from Virus_Scan.detection.profiles.engine_context import infer_engine_context
from Virus_Scan.detection.profiles.selection import build_detection_profile_context
from Virus_Scan.utils.stages import normalize_stage
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text


ModelContextValue = object
ModelContextSequence = Sequence[ModelContextValue]
ModelContextMapping = Mapping[str, ModelContextValue]
ModelContextBuilder = Callable[..., ModelContextValue]


@dataclass(frozen=True, slots=True)
class ClusterProjectionRequest:
    node: ModelContextValue | None
    vector_tags: ModelContextValue
    engine_context: ModelContextValue
    update_cluster: bool
    failure_evidence: list[ModelContextValue]


def _model_context_sequence(value: ModelContextValue) -> list[ModelContextValue]:
    values, _reason = _model_context_sequence_with_reason(
        value,
        field_name="model_context",
    )
    return values


def _model_context_sequence_with_reason(
    value: ModelContextValue, *, field_name: str,
) -> tuple[list[ModelContextValue], str | None]:
    if value is None:
        return [], None
    if type(value) is TagEvidence:
        return list(value.tags), None
    if type(value) in (str, bytes, bytearray, int, float, bool):
        return [value], None
    if no_hook_mapping_items(value) is not None:
        return [value], None
    if type(value) in (tuple, list, set, frozenset):
        return list(value), None
    return [], f"{field_name}_sequence_rejected"


def _model_context_text(value: ModelContextValue, *, default_text: ModelContextValue = '') -> str:
    replacement_text, _replacement_reason = no_hook_text(
        default_text,
        missing_reason='missing_model_context_default_text',
        unsupported_reason='unsafe_model_context_default_text_rejected',
    )
    text, reason = no_hook_text(
        value,
        missing_reason='missing_model_context_text',
        unsupported_reason='unsafe_model_context_text_rejected',
    )
    if reason is not None and reason != '':
        return str.strip(replacement_text)
    text = str.strip(text)
    return text or str.strip(replacement_text)


def _model_context_path_value(
    file_structure: ModelContextValue | None, node: ModelContextValue | None,
) -> ModelContextValue:
    return file_structure if file_structure is not None else (node if node is not None else '')


def _validated_model_projection(
    value: ModelContextValue, *, stage_name: str, error_source: str,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    """Keep rejected model mappings visible instead of projecting them as zeros."""
    if no_hook_mapping_items(value) is not None:
        return value
    unavailable_reason = f'{stage_name}_mapping_rejected'
    failure = recoverable_failure_evidence(
        stage_name=stage_name,
        error=unavailable_reason,
        error_source=error_source,
        affected_context=type(value).__name__,
    )
    failure_evidence.append(failure)
    return {
        'ready': False,
        'degraded': True,
        'unavailable_reason': unavailable_reason,
        'failure_evidence': [failure.to_record()],
        'confidence_degraded': True,
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def _append_input_rejection_failure(
    failure_evidence: list[ModelContextValue], *, field_name: str, reason: str | None,
) -> None:
    if reason is None:
        return
    failure_evidence.append(recoverable_failure_evidence(
        stage_name="adaptive_input",
        error=reason,
        error_source="build_detection_model_context",
        affected_context=field_name,
    ))


def _model_context_inputs(
    tags: ModelContextValue | None,
    api_calls: ModelContextValue | None,
    ordered_events: ModelContextValue | None,
    behavior_timeline: ModelContextValue | None,
    failure_evidence: list[ModelContextValue],
) -> tuple[
    list[ModelContextValue], TagEvidence,
    list[ModelContextValue], list[ModelContextValue], list[ModelContextValue],
]:
    raw_tags_for_flow, tags_reason = _model_context_sequence_with_reason(tags, field_name="tags")
    tag_evidence = scoreable_tag_evidence(
        tags if type(tags) is TagEvidence else raw_tags_for_flow,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    api_values, api_reason = _model_context_sequence_with_reason(api_calls, field_name="api_calls")
    ordered_values, ordered_reason = _model_context_sequence_with_reason(ordered_events, field_name="ordered_events")
    timeline_values, timeline_reason = _model_context_sequence_with_reason(behavior_timeline, field_name="behavior_timeline")
    for field_name, reason in (
        ("tags", tags_reason), ("api_calls", api_reason),
        ("ordered_events", ordered_reason), ("behavior_timeline", timeline_reason),
    ):
        _append_input_rejection_failure(failure_evidence, field_name=field_name, reason=reason)
    return (
        raw_tags_for_flow, tag_evidence, api_values, ordered_values, timeline_values,
    )


def _graph_features_projection(
    node: ModelContextValue | None,
    graph_features_builder: ModelContextBuilder,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    try:
        graph_features = graph_features_builder(node) if node is not None else {
            'risk': 0.0, 'base_risk': 0.0, 'anomaly': 0.0,
            'ready': False, 'reason': 'missing_node_for_graph_features',
        }
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='graph_features', error=e,
            error_source='get_graph_features', affected_context=node,
        ))
        graph_features = {
            'risk': 0.0, 'base_risk': 0.0, 'anomaly': 0.0,
            'failure_evidence': [failure_evidence[-1].to_record()],
        }
    return _validated_model_projection(
        graph_features, stage_name='graph_features',
        error_source='get_graph_features', failure_evidence=failure_evidence,
    )


def _temporal_features_projection(
    node: ModelContextValue | None,
    ordered_events: ModelContextValue,
    behavior_timeline: ModelContextValue,
    temporal_snapshot_builder: ModelContextBuilder,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    try:
        temporal_features = temporal_snapshot_builder(
            node, ordered_events=ordered_events, behavior_timeline=behavior_timeline,
        ) if node is not None else {
            'belief': 0.0, 'flow': [], 'ready': False,
            'reason': 'missing_node_for_temporal_features',
        }
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='temporal_features', error=e,
            error_source='snapshot_temporal', affected_context=node,
        ))
        temporal_features = {'belief': 0.0, 'flow': [], 'failure_evidence': [failure_evidence[-1].to_record()]}
    return _validated_model_projection(
        temporal_features, stage_name='temporal_features',
        error_source='snapshot_temporal', failure_evidence=failure_evidence,
    )


def _markov_features_projection(
    prev_stage: ModelContextValue,
    behavior_flow: ModelContextValue,
    curr_stage: ModelContextValue,
    markov_features_builder: ModelContextBuilder,
    node: ModelContextValue | None,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    try:
        markov_features = markov_features_builder(prev_stage, behavior_flow, curr_stage)
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='markov_features', error=e,
            error_source='compute_markov_features', affected_context=node,
        ))
        markov_features = {
            'transition': 0.0, 'rarity': 0.0, 'pair_anomaly': 0.0,
            'sequence_anomaly': 0.0, 'flow': behavior_flow,
            'failure_evidence': [failure_evidence[-1].to_record()],
        }
    return _validated_model_projection(
        markov_features, stage_name='markov_features',
        error_source='compute_markov_features', failure_evidence=failure_evidence,
    )


def _engine_context_projection(
    tags: ModelContextValue,
    path_for_stage: ModelContextValue,
    strings_blob: ModelContextValue,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    try:
        engine_context = infer_engine_context(
            tags, file_structure=path_for_stage,
            strings_blob=_model_context_text(strings_blob),
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='engine_context', error=e,
            error_source='infer_engine_context', affected_context=path_for_stage,
        ))
        engine_context = {'other': 1.0, 'failure_evidence': [failure_evidence[-1].to_record()]}
    return _validated_model_projection(
        engine_context, stage_name='engine_context',
        error_source='infer_engine_context', failure_evidence=failure_evidence,
    )


def _feature_vector_projection(
    node: ModelContextValue | None,
    vector_tags: ModelContextValue,
    chain_evidence: ChainEvidence,
    graph_features: ModelContextValue,
    temporal_features: ModelContextValue,
    markov_features: ModelContextValue,
    engine_context: ModelContextValue,
    path_for_stage: ModelContextValue,
    strings_blob: ModelContextValue,
    api_calls: ModelContextValue,
    ordered_events: ModelContextValue,
    failure_evidence: list[ModelContextValue],
) -> ModelContextValue:
    try:
        return detection_feature_vector(
            node, vector_tags, chain_evidence, graph_features, temporal_features, markov_features,
            engine_context, risk=0.0, file_path=path_for_stage,
            strings_blob=_model_context_text(strings_blob), api_calls=api_calls,
            ordered_events=ordered_events,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        failure_evidence.append(recoverable_failure_evidence(
            stage_name='feature_vector', error=e,
            error_source='build_feature_vector', affected_context=node,
        ))
        return []


def _cluster_projection_id(request: ClusterProjectionRequest) -> ModelContextValue | None:
    node = request.node
    if request.update_cluster is not True or node is None:
        return None
    try:
        return detection_cluster_projection(
            node,
            request.vector_tags,
            engine_context=request.engine_context,
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as e:
        request.failure_evidence.append(recoverable_failure_evidence(
            stage_name='cluster_assignment', error=e,
            error_source='assign_cluster_with_context_tags', affected_context=node,
        ))
        return None


def build_detection_model_context(
    node: ModelContextValue | None, tags: ModelContextValue | None = None,
    file_structure: ModelContextValue | None = None, strings_blob: ModelContextValue = '',
    api_calls: ModelContextValue | None = None,
    ordered_events: ModelContextValue | None = None,
    behavior_timeline: ModelContextValue | None = None,
    prev_stage: ModelContextValue | None = None, curr_stage: ModelContextValue | None = None,
    *, chain_evidence: ChainEvidence, projection_identity: ModelContextValue,
    source_artifact_evidence_digest: str, update_cluster: bool = True,
    profile_context_builder: ModelContextBuilder = build_detection_profile_context,
    graph_features_builder: ModelContextBuilder = detection_graph_features,
    temporal_snapshot_builder: ModelContextBuilder = detection_temporal_snapshot,
    markov_features_builder: ModelContextBuilder = detection_markov_features,
) -> ModelContextSnapshot:
    """Build the one canonical context snapshot after provisional evidence exists."""
    if type(tags) is not TagEvidence:
        raise TypeError("detection_model_context_tag_evidence_required")
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("detection_model_context_chain_evidence_required")
    canonical_projection_identity = require_model_projection_identity(projection_identity)
    canonical_tag_evidence = tags
    failure_evidence: list[ModelContextValue] = []
    raw_tags_for_flow, tag_evidence, api_calls, ordered_events, behavior_timeline = _model_context_inputs(
        canonical_tag_evidence, api_calls, ordered_events, behavior_timeline, failure_evidence,
    )
    tags = list(tag_evidence.tags)
    path_for_stage = _model_context_path_value(file_structure, node)
    curr_stage = _model_context_text(
        curr_stage, default_text=normalize_stage(Path(_model_context_text(path_for_stage)).suffix),
    )
    prev_stage = _model_context_text(prev_stage, default_text='unknown')
    behavior_flow = detection_behavior_flow_from_sources(
        raw_tags=raw_tags_for_flow, ordered_events=ordered_events, behavior_timeline=behavior_timeline,
    )
    graph_features = _graph_features_projection(node, graph_features_builder, failure_evidence)
    temporal_features = _temporal_features_projection(
        node, ordered_events, behavior_timeline, temporal_snapshot_builder, failure_evidence,
    )
    markov_features = _markov_features_projection(
        prev_stage, behavior_flow, curr_stage, markov_features_builder, node, failure_evidence,
    )
    engine_context = _engine_context_projection(
        tags, path_for_stage, strings_blob, failure_evidence,
    )
    profile_context = profile_context_builder(
        engine_context=engine_context,
        path=path_for_stage,
        tags=tag_evidence.tags,
        strings_blob=_model_context_text(strings_blob),
    )
    if type(profile_context) is not DetectionProfileContext:
        raise TypeError("detection_model_context_profile_context_required")
    confidence_failures = profile_context.engine_confidence.get("failure_evidence", ())
    if type(confidence_failures) in (tuple, list):
        failure_evidence.extend(confidence_failures)
    failure_evidence.extend(profile_context.failure_evidence)
    flow_evidence = normalize_tag_evidence(
        behavior_flow, source_detector="model_context", source_stage="behavior_flow", derive=False,
    )
    vector_tag_evidence = TagEvidence.from_records(
        (*tag_evidence.records, *flow_evidence.records),
        reasons={"consumer": "detection_model_context"},
    )
    vector_tags = ordered_unique_tags(list(scoreable_tag_set(vector_tag_evidence)))
    vector = _feature_vector_projection(
        node, vector_tag_evidence, chain_evidence, graph_features, temporal_features, markov_features,
        engine_context, path_for_stage, strings_blob, api_calls, ordered_events, failure_evidence,
    )
    cluster_id = _cluster_projection_id(
        ClusterProjectionRequest(
            node=node, vector_tags=vector_tag_evidence, engine_context=engine_context,
            update_cluster=update_cluster, failure_evidence=failure_evidence,
        )
    )
    cluster_context = (
        {"cluster_id": cluster_id}
        if cluster_id is None or type(cluster_id) in (str, int, float, bool)
        else {}
    )
    return ModelContextSnapshot(
        source_artifact_evidence_digest=source_artifact_evidence_digest,
        projection_identity=canonical_projection_identity,
        graph_features=graph_features,
        temporal_features=temporal_features,
        markov_features=markov_features,
        engine_context=engine_context,
        profile_context=profile_context.to_record(),
        behavior_flow=tuple(behavior_flow),
        feature_vector=tuple(vector),
        cluster_context=cluster_context,
        attack_family_classifier_context={},
        failure_evidence=tuple(failure_evidence),
    )

def detection_behavior_flow_from_sources(
    raw_tags: ModelContextValue | None = None,
    ordered_events: ModelContextValue | None = None,
    behavior_timeline: ModelContextValue | None = None,
    behavior_flow: ModelContextValue | None = None,
) -> list[ModelContextValue]:
    """Build sequence-model behavior flow from concrete ordered evidence only.

    Raw detector tags are intentionally excluded here. They are unordered labels,
    not a timeline, and must not synthesize Markov/temporal/cluster ordering.
    """
    del raw_tags
    timeline_events = None
    if behavior_timeline is not None:
        try:
            timeline_events = real_timeline_events(behavior_timeline)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            timeline_events = None
    ordered_sources = (behavior_flow, timeline_events, ordered_events)
    for source in ordered_sources:
        if source is None:
            continue
        try:
            flow = detection_behavior_flow(source)
        except TAG_SCAN_RECOVERABLE_EXCEPTIONS:
            continue
        if len(flow) > 0:
            return flow
    return []
