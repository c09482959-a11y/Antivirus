
from Virus_Scan.detection.scoring.adaptive.calibration_state import record_fusion_score
from Virus_Scan.detection.scoring.adaptive.confidence import adaptive_learned_model_weight_from_confidence
from Virus_Scan.detection.scoring.adaptive.availability import (
    available_feature_probability,
    probability_feature_unavailable_reason,
)
from Virus_Scan.detection.scoring.adaptive.layer_weights import (
    distribute_static_learned_model_weights,
    learn_adaptive_layer_weights,
)
from Virus_Scan.detection.scoring.adaptive.feature_bundle import (
    model_adaptive_cluster_signal,
    model_adaptive_markov_signal,
    model_adaptive_profile_signal,
    model_coordinated_validation_signal,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_input_rejection_reason,
    adaptive_public_mapping,
)
from Virus_Scan.detection.scoring.adaptive.settings import (
    ADAPTIVE_WEIGHT_MIN_HISTORY,
)
from Virus_Scan.detection.scoring.weighting.scoreable_tags import concrete_score_count
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error
from Virus_Scan.utils.probability import (
    calibrated_sigmoid_probability,
    safe_clamp,
    safe_logit_probability,
)


def hybrid_static_model_evidence_fusion(features: object) -> float:
    """
    Hybrid static/model-evidence fusion:
    - graph, attention, cluster, Markov, temporal, profile, bucket, and vector values are learned-model evidence
    - attack intelligence, chains, evasion, behavior, execution, and entropy values are static/rule evidence
    - unavailable or not-ready evidence is projected to zero with explicit reason fields
    - sigmoid-normalized inputs, log-odds weighted fusion, and percentile calibration are preserved
    """
    feature_values: dict[str, object]
    if type(features) is dict:
        feature_values = features
    else:
        feature_values = adaptive_public_mapping(features)
        if adaptive_public_input_rejection_reason(feature_values) is not None:
            return 0.0
    weights = {'p_attack_intelligence': 1.45, 'p_chain': 1.25, 'p_evasion': 1.25, 'p_behavior': 0.9, 'p_exec': 0.85, 'p_entropy': 0.8, 'p_graph': 1.2, 'p_graph_chain': 1.2, 'p_attention': 1.15, 'p_cluster': 1.05, 'p_markov': 0.95, 'p_temporal': 0.9, 'p_profile': 1.0, 'p_bucket': 1.05, 'p_vector': 1.05, 'p_engine': 0.35}
    try:
        learned_model_conf = safe_clamp(
            0.24 * available_feature_probability(feature_values, 'p_vector', feature_values.get('p_vector_unavailable_reason'))
            + 0.2 * available_feature_probability(feature_values, 'p_bucket', feature_values.get('p_bucket_unavailable_reason'))
            + 0.16 * available_feature_probability(feature_values, 'p_profile', feature_values.get('p_profile_unavailable_reason'))
            + 0.14 * available_feature_probability(feature_values, 'p_markov', feature_values.get('p_markov_unavailable_reason'))
            + 0.12 * available_feature_probability(feature_values, 'p_temporal', feature_values.get('p_temporal_unavailable_reason'))
            + 0.08 * available_feature_probability(feature_values, 'p_cluster', feature_values.get('p_cluster_unavailable_reason'))
            + 0.06 * available_feature_probability(feature_values, 'p_attention', feature_values.get('p_graph_unavailable_reason'))
        )
        static_feature_values = (
            available_feature_probability(feature_values, 'p_attack_intelligence', feature_values.get('p_attack_intelligence_unavailable_reason')),
            available_feature_probability(feature_values, 'p_chain', feature_values.get('p_chain_unavailable_reason')),
            safe_clamp(feature_values.get('p_exec', 0.0)),
            safe_clamp(feature_values.get('p_behavior', 0.0)),
            available_feature_probability(feature_values, 'p_evasion', feature_values.get('p_evasion_unavailable_reason')),
        )
        static_anchor = max(static_feature_values) * 100.0
        concrete_est = int(sum((1 for value in static_feature_values if value >= 0.35)))
        ns = adaptive_learned_model_weight_from_confidence(learned_model_conf, concrete_count=concrete_est, profile_files_seen=ADAPTIVE_WEIGHT_MIN_HISTORY, static_anchor_score=static_anchor)
        learned_model_share = safe_clamp(ns.get('learned_model_weight', 0.3))
        static_share = safe_clamp(ns.get('static_weight', 0.7))
        static_keys = {'p_attack_intelligence', 'p_chain', 'p_evasion', 'p_behavior', 'p_exec', 'p_entropy'}
        learned_model_keys = {'p_graph', 'p_graph_chain', 'p_attention', 'p_cluster', 'p_markov', 'p_temporal', 'p_profile', 'p_bucket', 'p_vector'}
        static_weight_sum = sum((weights.get(k, 0.0) for k in static_keys)) or 1.0
        learned_model_weight_sum = sum((weights.get(k, 0.0) for k in learned_model_keys)) or 1.0
        for k in list(weights):
            if k in static_keys:
                weights[k] = weights[k] * (static_share / static_weight_sum) * len(static_keys)
            elif k in learned_model_keys:
                weights[k] = weights[k] * (learned_model_share / learned_model_weight_sum) * len(learned_model_keys)
        feature_values['p_adaptive_learned_model_confidence'] = learned_model_conf
        feature_values['p_adaptive_learned_model_weight'] = learned_model_share
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('hybrid adaptive learned-model/static fusion weighting failed')
    fusion_feature_values = dict(feature_values)
    for value_key, reason_key in (
        ('p_graph', 'p_graph_unavailable_reason'),
        ('p_graph_chain', 'p_graph_chain_unavailable_reason'),
        ('p_attention', 'p_graph_unavailable_reason'),
        ('p_cluster', 'p_cluster_unavailable_reason'),
        ('p_markov', 'p_markov_unavailable_reason'),
        ('p_temporal', 'p_temporal_unavailable_reason'),
        ('p_profile', 'p_profile_unavailable_reason'),
        ('p_bucket', 'p_bucket_unavailable_reason'),
        ('p_vector', 'p_vector_unavailable_reason'),
        ('p_engine', 'p_engine_unavailable_reason'),
        ('p_attack_intelligence', 'p_attack_intelligence_unavailable_reason'),
        ('p_mitre', 'p_mitre_unavailable_reason'),
        ('p_chain', 'p_chain_unavailable_reason'),
        ('p_evasion', 'p_evasion_unavailable_reason'),
    ):
        reason = probability_feature_unavailable_reason(
            fusion_feature_values,
            value_key,
            fusion_feature_values.get(reason_key),
        )
        if reason and value_key in fusion_feature_values:
            fusion_feature_values[value_key] = 0.0
            fusion_feature_values.setdefault(reason_key, reason)
            try:
                feature_values.setdefault(reason_key, reason)
            except RECOVERABLE_RUNTIME_ERRORS:
                log_error('adaptive fusion feature reason projection failed')
    normalized = {}
    for k, v in fusion_feature_values.items():
        normalized[k] = calibrated_sigmoid_probability((safe_clamp(v) - 0.5) * 6.0)
    raw_log_odds = -1.35
    total_w = 0.0
    for k, w in weights.items():
        if k in normalized:
            raw_log_odds += safe_logit_probability(normalized[k]) * w
            total_w += abs(w)
    fused = calibrated_sigmoid_probability(raw_log_odds / max(1.0, total_w / 4.0))
    calibrated = percentile_calibrate(fused)
    return safe_clamp(calibrated)


def percentile_calibrate(score: object) -> object:
    """Simple rolling percentile calibration for fused risk."""
    history = record_fusion_score(float(score))
    if len(history) < 20:
        return score
    values = sorted(history[-1000:])
    below = sum((1 for v in values if v <= score))
    return safe_clamp(below / max(1, len(values)))


__all__ = (
    "concrete_score_count",
    "distribute_static_learned_model_weights",
    "hybrid_static_model_evidence_fusion",
    "learn_adaptive_layer_weights",
    "model_adaptive_cluster_signal",
    "model_adaptive_markov_signal",
    "model_adaptive_profile_signal",
    "model_coordinated_validation_signal",
    "percentile_calibrate",
)
