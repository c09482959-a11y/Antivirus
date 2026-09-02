from __future__ import annotations

from collections.abc import Mapping
from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_finite_float

from Virus_Scan.detection.scoring.adaptive.public_inputs import adaptive_public_input_rejection_reason, adaptive_public_mapping
from Virus_Scan.detection.scoring.adaptive.boundary_values import (
    adaptive_invalid_flag_reason,
    adaptive_mapping_get,
    adaptive_reason_text,
)
from Virus_Scan.utils.probability import safe_clamp
from Virus_Scan.detection.scoring.weighting.numeric import adaptive_weight_float
from Virus_Scan.detection.scoring.adaptive.feature_bundle import model_feature_bundle
from Virus_Scan.detection.scoring.adaptive.settings import (
    ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP,
    ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP,
    ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT,
    ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT,
    ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP,
    ADAPTIVE_LEARNED_MODEL_STATIC_VERSION,
    ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP,
    ADAPTIVE_WEIGHT_BOUNDS,
    ADAPTIVE_WEIGHT_MIN_HISTORY,
)




def coerce_model_probability(value: object, reason: str) -> tuple[float, str | None]:
    if value is None:
        return 0.0, reason
    numeric, numeric_reason = no_hook_finite_float(
        value,
        default=0.0,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=True,
    )
    if numeric_reason:
        return 0.0, reason
    return safe_clamp(numeric), None

def coerce_scaled_model_probability(value: object, divisor: float, reason: str) -> tuple[float, str | None]:
    if value is None or divisor is None:
        return 0.0, reason
    numeric, numeric_reason = no_hook_finite_float(
        value,
        default=0.0,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=True,
    )
    scale, scale_reason = no_hook_finite_float(
        divisor,
        default=0.0,
        reason=reason,
        non_finite_reason=reason,
        allow_exact_text=True,
    )
    if numeric_reason or scale_reason or scale == 0.0:
        return 0.0, reason
    return safe_clamp(numeric / scale), None

def max_model_probability(values: object, reason: str) -> tuple[float, str | None]:
    valid = []
    degraded = False
    for value in values:
        if value is None:
            degraded = True
            continue
        numeric, numeric_reason = no_hook_finite_float(
            value,
            default=0.0,
            reason=reason,
            non_finite_reason=reason,
            allow_exact_text=True,
        )
        if numeric_reason:
            degraded = True
            continue
        valid.append(safe_clamp(numeric))
    if valid:
        return max(valid), reason if degraded else None
    return 0.0, reason

def finite_engine_context(engine_ctx: object) -> tuple[dict[str, float], str | None]:
    finite = {}
    degraded = False
    for engine, value in adaptive_public_mapping(engine_ctx).items():
        if value is None:
            degraded = True
            continue
        numeric, numeric_reason = no_hook_finite_float(
            value,
            default=0.0,
            reason='nonfinite_engine_context_probability',
            non_finite_reason='nonfinite_engine_context_probability',
            allow_exact_text=True,
        )
        if numeric_reason:
            degraded = True
            continue
        engine_key = engine if type(engine) is str else 'engine_context_key_unavailable'
        finite[engine_key] = safe_clamp(numeric)
    if finite:
        return finite, 'nonfinite_engine_context_probability' if degraded else None
    return {}, 'nonfinite_engine_context_probability'

def adaptive_normalized_weights(weights: object) -> dict[object, float]:
    """Clamp and normalize adaptive layer weights without allowing any layer to vanish."""
    public_weights = adaptive_public_mapping(weights)
    if adaptive_public_input_rejection_reason(public_weights) is not None:
        return dict(public_weights)
    out = {}
    for k, v in public_weights.items():
        lo, hi = ADAPTIVE_WEIGHT_BOUNDS.get(k, (0.05, 0.6))
        out[k] = safe_clamp(adaptive_weight_float(v, 0.0), lo, hi)
    total = sum(out.values()) or 1.0
    return {k: safe_clamp(v / total, 0.0, 1.0) for k, v in out.items()}

def readiness_unavailable_reason(record: object, default_reason: str) -> str | None:
    if not isinstance(record, Mapping):
        return None
    default_reason_text = adaptive_reason_text(default_reason)
    if default_reason_text is None:
        default_reason_text = 'model_signal_not_ready'
    for key in (
        'ready',
        'probability_ready',
        'profile_ready',
        'markov_ready',
        'cluster_ready',
        'cluster_signal_ready',
        'bucket_ready',
        'vector_ready',
        'temporal_ready',
        'stage_probability_ready',
        'sequence_probability_ready',
        'graph_relationship_ready',
        'graph_features_ready',
        'risk_ready',
    ):
        value = adaptive_mapping_get(record, key)
        if value is False:
            return default_reason_text
        invalid_reason = adaptive_invalid_flag_reason(value, key)
        if invalid_reason is not None:
            return invalid_reason
    return None

def model_signal_unavailable_reason(record: object) -> str | None:
    if not isinstance(record, Mapping):
        return None
    for key in ('unavailable_reason', 'markov_unavailable_reason', 'profile_unavailable_reason', 'cluster_unavailable_reason', 'reason', 'failure_reason', 'error_reason'):
        text = adaptive_reason_text(adaptive_mapping_get(record, key))
        if text is not None:
            return text
    readiness_reason = readiness_unavailable_reason(record, 'model_signal_not_ready')
    if readiness_reason is not None:
        return readiness_reason
    degraded = adaptive_mapping_get(record, 'degraded')
    if degraded is True:
        return 'degraded_model_signal'
    invalid_degraded = adaptive_invalid_flag_reason(degraded, 'degraded')
    if invalid_degraded is not None:
        return invalid_degraded
    confidence_degraded = adaptive_mapping_get(record, 'confidence_degraded')
    if confidence_degraded is True:
        return 'confidence_degraded_model_signal'
    invalid_confidence = adaptive_invalid_flag_reason(confidence_degraded, 'confidence_degraded')
    if invalid_confidence is not None:
        return invalid_confidence
    return None

def adaptive_learned_model_confidence(profile_signal: object | None=None, markov_signal: object | None=None, cluster_signal: object | None=None, vector_signal: float=0.0, bucket_signal: float=0.0) -> float:
    profile_signal = adaptive_public_mapping(profile_signal)
    markov_signal = adaptive_public_mapping(markov_signal)
    cluster_signal = adaptive_public_mapping(cluster_signal)
    p_profile = (
        safe_clamp(profile_signal.get('profile_anomaly', 0.0))
        if profile_signal.get('profile_ready') is True
        and model_signal_unavailable_reason(profile_signal) is None
        else 0.0
    )
    p_markov = 0.0 if model_signal_unavailable_reason(markov_signal) is not None else safe_clamp(markov_signal.get('markov_anomaly', 0.0))
    p_cluster = 0.0 if model_signal_unavailable_reason(cluster_signal) is not None else safe_clamp(cluster_signal.get('cluster_signal', 0.0))
    p_vector = safe_clamp(vector_signal)
    p_bucket = safe_clamp(bucket_signal)
    confidence = 0.28 * p_profile + 0.24 * p_vector + 0.18 * p_bucket + 0.18 * p_markov + 0.12 * p_cluster
    return safe_clamp(confidence)

def adaptive_learned_model_weight_from_confidence(model_confidence: float, concrete_count: int=0, profile_files_seen: int=0, static_anchor_score: float=0.0) -> Mapping[str, object]:
    conf = safe_clamp(model_confidence)
    concrete_count, _concrete_count_reason = no_hook_exact_nonnegative_int(
        concrete_count,
        default=0,
        reason='adaptive_concrete_count_rejected',
        non_finite_reason='adaptive_concrete_count_rejected',
        allow_exact_text=True,
    )
    profile_files_seen, _profile_files_seen_reason = no_hook_exact_nonnegative_int(
        profile_files_seen,
        default=0,
        reason='adaptive_profile_files_seen_rejected',
        non_finite_reason='adaptive_profile_files_seen_rejected',
        allow_exact_text=True,
    )
    static_anchor_score, _static_anchor_score_reason = no_hook_finite_float(
        static_anchor_score,
        default=0.0,
        reason='adaptive_static_anchor_score_rejected',
        non_finite_reason='adaptive_static_anchor_score_rejected',
        allow_exact_text=True,
    )
    learned_model_weight = ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT + (ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT - ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT) * conf ** 1.8
    caps = []
    if profile_files_seen and profile_files_seen < ADAPTIVE_WEIGHT_MIN_HISTORY:
        learned_model_weight = min(learned_model_weight, ADAPTIVE_LEARNED_MODEL_IMMATURE_CAP)
        caps.append('immature_profile_history')
    if concrete_count <= 0:
        learned_model_weight = min(learned_model_weight, ADAPTIVE_LEARNED_MODEL_WEAK_EVIDENCE_CAP)
        caps.append('no_concrete_static_anchors')
    elif concrete_count == 1:
        learned_model_weight = min(learned_model_weight, ADAPTIVE_LEARNED_MODEL_SINGLE_ANCHOR_CAP)
        caps.append('single_concrete_anchor')
    if static_anchor_score >= 45.0 and conf < 0.35:
        learned_model_weight = min(learned_model_weight, ADAPTIVE_LEARNED_MODEL_CONTRADICTION_CAP)
        caps.append('static_anchor_overrides_weak_model')
    learned_model_weight = safe_clamp(learned_model_weight, ADAPTIVE_LEARNED_MODEL_MIN_WEIGHT, ADAPTIVE_LEARNED_MODEL_MAX_WEIGHT)
    static_weight = safe_clamp(1.0 - learned_model_weight, 0.2, 0.85)
    total = max(0.0001, learned_model_weight + static_weight)
    learned_model_weight = safe_clamp(learned_model_weight / total)
    static_weight = safe_clamp(static_weight / total)
    return model_feature_bundle({
        'version': ADAPTIVE_LEARNED_MODEL_STATIC_VERSION,
        'model_confidence': conf,
        'learned_model_weight': learned_model_weight,
        'static_weight': static_weight,
        'concrete_scoreable_evidence_count': concrete_count,
        'profile_files_seen': profile_files_seen,
        'static_anchor_score': static_anchor_score,
        'caps_applied': tuple(caps),
    }, model_version=ADAPTIVE_LEARNED_MODEL_STATIC_VERSION)

__all__ = ('adaptive_learned_model_confidence', 'adaptive_learned_model_weight_from_confidence', 'adaptive_normalized_weights', 'coerce_model_probability', 'coerce_scaled_model_probability', 'finite_engine_context', 'max_model_probability', 'model_signal_unavailable_reason', 'readiness_unavailable_reason')
