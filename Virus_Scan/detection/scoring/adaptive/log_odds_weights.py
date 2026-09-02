from collections.abc import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float
from Virus_Scan.detection.scoring.adaptive.availability import (
    adaptive_unavailable_reason,
    available_feature_probability,
)
from Virus_Scan.detection.scoring.adaptive.confidence import (
    adaptive_learned_model_confidence,
    adaptive_learned_model_weight_from_confidence,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_input_rejection_reason,
    adaptive_public_mapping,
)
from Virus_Scan.detection.scoring.adaptive.settings import ADAPTIVE_WEIGHT_MIN_HISTORY
from Virus_Scan.utils.probability import safe_clamp


PLR2004N3 = 3


def log_odds_weight(value: object, *, default: float, minimum: float, maximum: float) -> float:
    numeric, _reason = no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason='adaptive_log_odds_weight_rejected',
        non_finite_reason='adaptive_log_odds_weight_non_finite',
        allow_exact_text=True,
    )
    return safe_clamp(numeric, minimum, maximum)


def normalize_log_odds_weights(static_weight: object, model_weight: object) -> object:
    static_weight = log_odds_weight(static_weight, default=0.7, minimum=0.2, maximum=0.85)
    model_weight = log_odds_weight(model_weight, default=0.3, minimum=0.15, maximum=0.8)
    total_weight = max(0.0001, static_weight + model_weight)
    return static_weight / total_weight, model_weight / total_weight

def derive_log_odds_weights(rolling_meta: object, profile_meta: object, probs: object, concrete_count: object, raw: object, layer_probs: object) -> object:
    rolling_meta = adaptive_public_mapping(rolling_meta)
    profile_meta = adaptive_public_mapping(profile_meta)
    probs = adaptive_public_mapping(probs)
    layer_probs = adaptive_public_mapping(layer_probs)
    rolling_available = (
        adaptive_public_input_rejection_reason(rolling_meta) is None
        and not adaptive_unavailable_reason(rolling_meta)
    )
    if rolling_available and (rolling_meta.get('degraded') or rolling_meta.get('confidence_degraded')):
        rolling_available = False
    static_weight = rolling_meta.get('static_weight') if rolling_available else None
    model_weight = rolling_meta.get('learned_model_weight') if rolling_available else None
    if static_weight is None or model_weight is None:
        model_conf = adaptive_learned_model_confidence(
            profile_signal={
                'profile_ready': (
                    adaptive_public_input_rejection_reason(profile_meta) is None
                    and not adaptive_unavailable_reason(profile_meta)
                ),
                'profile_anomaly': probs.get('p_profile', 0.0),
            },
            markov_signal={'markov_anomaly': probs.get('p_markov', 0.0)},
            cluster_signal={'cluster_signal': probs.get('p_cluster', 0.0)},
            vector_signal=probs.get('p_vector', 0.0),
            bucket_signal=probs.get('p_bucket', 0.0),
        )
        profile_files_seen = ADAPTIVE_WEIGHT_MIN_HISTORY
        if isinstance(profile_meta, Mapping):
            profile_files_seen = profile_meta.get('files_seen', ADAPTIVE_WEIGHT_MIN_HISTORY)
        ns = adaptive_learned_model_weight_from_confidence(
            model_conf,
            concrete_count=concrete_count,
            profile_files_seen=profile_files_seen,
            static_anchor_score=max(raw, available_feature_probability(layer_probs, 'threat_intel_probability', layer_probs.get('threat_intel_unavailable_reason')) * 100.0),
        )
        static_weight = ns.get('static_weight', 0.7)
        model_weight = ns.get('learned_model_weight', 0.3)
    return normalize_log_odds_weights(static_weight, model_weight)

def apply_log_odds_concrete_caps(static_weight: object, model_weight: object, concrete_count: object) -> object:
    caps = []
    model_weight = log_odds_weight(model_weight, default=0.3, minimum=0.0, maximum=1.0)
    if concrete_count <= 0:
        model_weight = min(model_weight, 0.25)
        caps.append('model_weight_capped_no_concrete_evidence')
    elif concrete_count == 1:
        model_weight = min(model_weight, 0.4)
        caps.append('model_weight_capped_single_concrete_anchor')
    static_weight = log_odds_weight(1.0 - model_weight, default=0.7, minimum=0.2, maximum=0.85)
    return (*normalize_log_odds_weights(static_weight, model_weight), caps)

def log_odds_active_layer_bonus(active_layers: object) -> object:
    count, count_reason = no_hook_exact_nonnegative_int(
        active_layers,
        default=0,
        reason='adaptive_active_layer_count_rejected',
        non_finite_reason='adaptive_active_layer_count_rejected',
        allow_exact_text=True,
    )
    if count_reason:
        return 0.0
    if count >= PLR2004N3:
        return 4.0
    if count == 2:
        return 2.0
    return 0.0

__all__ = (
    'apply_log_odds_concrete_caps',
    'derive_log_odds_weights',
    'log_odds_active_layer_bonus',
    'normalize_log_odds_weights',
)
