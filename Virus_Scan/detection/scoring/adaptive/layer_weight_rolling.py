"""Rolling-share and metadata helpers for adaptive layer-weight learning."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.detection.scoring.adaptive.confidence import (
    adaptive_learned_model_confidence,
    adaptive_learned_model_weight_from_confidence,
    adaptive_normalized_weights,
)
from Virus_Scan.detection.scoring.adaptive.layer_weight_distribution import (
    distribute_static_learned_model_weights_impl,
)


def rolling_layer_weight_state(
    pre_rolling_weights: object,
    score_state: object,
    signal_state: object,
) -> dict[str, object]:
    """Build learned static/model shares and final normalized layer weights."""
    model_confidence = adaptive_learned_model_confidence(
        profile_signal=signal_state.get('profile'),
        markov_signal=signal_state.get('markov'),
        cluster_signal=signal_state.get('cluster'),
        vector_signal=signal_state.get('vector_signal'),
        bucket_signal=signal_state.get('bucket_signal'),
    )
    static_anchor_score = max(
        score_state.get('quick_score', 0.0),
        score_state.get('intel_score', 0.0),
    )
    profile_files_seen, _reason = no_hook_exact_nonnegative_int(
        signal_state.get('profile', {}).get('files_seen', 0),
        default=0,
        reason='adaptive_profile_files_seen_rejected',
        non_finite_reason='adaptive_profile_files_seen_rejected',
        allow_exact_text=True,
    )
    learned_static = adaptive_learned_model_weight_from_confidence(
        model_confidence,
        concrete_count=score_state.get('concrete_count', 0),
        profile_files_seen=profile_files_seen,
        static_anchor_score=static_anchor_score,
    )
    rolling_weights = distribute_static_learned_model_weights_impl(
        pre_rolling_weights,
        static_share=learned_static.get('static_weight', 0.7),
        learned_model_share=learned_static.get('learned_model_weight', 0.3),
        model_pressure=model_confidence,
    )
    return {
        'model_confidence': model_confidence,
        'learned_static': learned_static,
        'weights': adaptive_normalized_weights(rolling_weights),
    }


def layer_weight_learning_metadata(
    version: object,
    base: object,
    pre_rolling_weights: object,
    weights: object,
    score_state: object,
    signal_state: object,
    learned_static: object,
) -> dict[str, object]:
    """Build the public metadata record for adaptive layer-weight learning."""
    return {
        'version': version,
        'base_weights': base,
        'pre_rolling_weights': pre_rolling_weights,
        'adaptive_weights': weights,
        'concrete_scoreable_evidence_count': score_state.get('concrete_count', 0),
        'layer_unavailable_reasons': {
            key: reason
            for key, reason in (
                ('quick_static', score_state.get('quick_unavailable_reason')),
                ('stage_timeline', score_state.get('stage_unavailable_reason')),
                ('graph_relationships', score_state.get('graph_unavailable_reason')),
                ('threat_intel', score_state.get('intel_unavailable_reason')),
            )
            if reason
        },
        'profile': signal_state.get('profile'),
        'markov': signal_state.get('markov'),
        'cluster': signal_state.get('cluster'),
        'bucket_vector': signal_state.get('bucket_vector'),
        'rolling_learned_static': learned_static,
    }
