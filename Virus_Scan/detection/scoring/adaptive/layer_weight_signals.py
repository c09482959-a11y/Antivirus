"""Model signal helpers for adaptive layer-weight learning."""

from Virus_Scan.detection.scoring.adaptive.availability import available_model_signal_probability
from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    model_adaptive_cluster_signal,
    model_adaptive_markov_signal,
    model_adaptive_profile_signal,
    model_coordinated_validation_signal,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import adaptive_public_mapping
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error


def coordinated_validation_unavailable_signal_state(reason: object) -> dict[str, object]:
    """Build explicit unavailable bucket/vector/timeline validation evidence."""
    return {
        'version': 'adaptive_bucket_vector_validation_unavailable_v1',
        'ready': False,
        'reason': reason,
        'bucket_validation': {
            'bucket_anomaly': 0.0,
            'ready': False,
            'reason': reason,
            'unavailable_reason': reason,
        },
        'vector_validation': {
            'anomaly': 0.0,
            'ready': False,
            'reason': reason,
            'unavailable_reason': reason,
        },
        'timeline_validation': {
            'anomaly': 0.0,
            'ready': False,
            'reason': reason,
            'unavailable_reason': reason,
        },
    }


def adaptive_model_signal_state(
    node: object,
    tags: object,
    prev_stage: object,
    curr_stage: object,
    strings_blob: object,
    api_calls: object,
    ordered_events: object,
    preliminary: object,
) -> dict[str, object]:
    """Build model signal and validation state for adaptive weight learning."""
    profile_sig = model_adaptive_profile_signal(
        node, tags, preliminary_risk=preliminary, strings_blob=strings_blob
    )
    markov_sig = model_adaptive_markov_signal(prev_stage, curr_stage, ordered_events)
    cluster_sig = model_adaptive_cluster_signal(node, tags)
    try:
        model_a = model_coordinated_validation_signal(
            profile_sig.get('engine', 'other'),
            node,
            tags,
            strings_blob=strings_blob,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        bucket_record = adaptive_public_mapping(model_a.get('bucket_validation'))
        vector_record = adaptive_public_mapping(model_a.get('vector_validation'))
        timeline_record = adaptive_public_mapping(model_a.get('timeline_validation'))
        bucket_signal = available_model_signal_probability(bucket_record, 'bucket_anomaly')
        vector_signal = available_model_signal_probability(vector_record, 'anomaly')
        timeline_signal = available_model_signal_probability(timeline_record, 'anomaly')
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('adaptive bucket/vector signal failed')
        model_a = coordinated_validation_unavailable_signal_state('coordinated_model_validation_failed')
        bucket_signal = 0.0
        vector_signal = 0.0
        timeline_signal = 0.0
    return {
        'profile': profile_sig,
        'markov': markov_sig,
        'cluster': cluster_sig,
        'profile_anomaly': available_model_signal_probability(profile_sig, 'profile_anomaly')
        if profile_sig.get('profile_ready')
        else 0.0,
        'markov_anomaly': available_model_signal_probability(markov_sig, 'markov_anomaly'),
        'cluster_signal': available_model_signal_probability(cluster_sig, 'cluster_signal'),
        'bucket_vector': model_a,
        'bucket_signal': bucket_signal,
        'vector_signal': vector_signal,
        'timeline_signal': timeline_signal,
    }


def apply_adaptive_model_weight_adjustments(
    base_weights: object,
    score_state: object,
    signal_state: object,
) -> object:
    """Apply profile, Markov, timeline, cluster, graph, and intel adjustments."""
    weights = dict(base_weights)
    concrete_count = score_state.get('concrete_count', 0)
    graph_score = score_state.get('graph_score', 0.0)
    intel_score = score_state.get('intel_score', 0.0)
    p = signal_state.get('profile_anomaly', 0.0)
    m = signal_state.get('markov_anomaly', 0.0)
    c = signal_state.get('cluster_signal', 0.0)
    timeline_signal = signal_state.get('timeline_signal', 0.0)
    if signal_state.get('profile', {}).get('profile_ready') and p >= 0.55:
        weights['stage_timeline'] = weights.get('stage_timeline', 0.22) + 0.05 * p
        weights['threat_intel'] = weights.get('threat_intel', 0.3) + 0.04 * p
        weights['quick_static'] = weights.get('quick_static', 0.28) - 0.03 * p
    if m >= 0.45:
        weights['stage_timeline'] = weights.get('stage_timeline', 0.22) + 0.07 * m
        weights['threat_intel'] = weights.get('threat_intel', 0.3) + 0.02 * m
    if timeline_signal >= 0.45:
        weights['stage_timeline'] = weights.get('stage_timeline', 0.22) + 0.06 * timeline_signal
        weights['quick_static'] = weights.get('quick_static', 0.28) - 0.02 * timeline_signal
    if c >= 0.55:
        weights['graph_relationships'] = weights.get('graph_relationships', 0.2) + 0.035 * c
        weights['threat_intel'] = weights.get('threat_intel', 0.3) + 0.025 * c
    if graph_score >= 35.0 and concrete_count < 2:
        weights['graph_relationships'] = min(weights.get('graph_relationships', 0.2), 0.08)
        weights['quick_static'] = weights.get('quick_static', 0.28) + 0.04
    elif graph_score >= 35.0 and intel_score < 20.0:
        weights['graph_relationships'] = min(weights.get('graph_relationships', 0.2), 0.12)
    if intel_score >= 45.0 and concrete_count >= 2:
        weights['threat_intel'] = weights.get('threat_intel', 0.3) + 0.05
    return weights
