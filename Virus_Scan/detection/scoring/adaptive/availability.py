from __future__ import annotations
from collections.abc import Mapping
from Virus_Scan.contracts.no_hook_materialization import exact_text_or_none
from Virus_Scan.detection.scoring.adaptive.layer_probability_failure import rejected_layer_probability_summary
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_input_rejection_reason,
    adaptive_public_mapping,
    adaptive_public_mapping_with_state,
)
from Virus_Scan.detection.scoring.adaptive.boundary_values import (
    adaptive_invalid_flag_reason,
    adaptive_mapping_get,
    adaptive_reason_or_default,
    adaptive_reason_text,
)
from Virus_Scan.detection.scoring.adaptive.confidence import (
    model_signal_unavailable_reason,
    readiness_unavailable_reason,
)
from Virus_Scan.detection.scoring.weighting.numeric import adaptive_weight_float
from Virus_Scan.reporting.summary import layer_probability_summary
from Virus_Scan.utils.probability import safe_clamp


def adaptive_unavailable_reason(*records: object) -> str | None:
    for record in records:
        reason = model_signal_unavailable_reason(record)
        if reason is not None:
            return reason
    return None
def available_model_signal_probability(record: object, key: str) -> float:
    """Return a model-side probability only when its metadata is available.

    Adaptive-learning metadata can be replayed or partially degraded. A high
    anomaly next to unavailable/failure evidence is not learned support.
    """
    if not isinstance(record, Mapping):
        return 0.0
    if adaptive_unavailable_reason(record):
        return 0.0
    return safe_clamp(adaptive_mapping_get(record, key, 0.0))
def first_adaptive_reason(record: Mapping[object, object], keys: tuple[str, ...]) -> str | None:
    for reason_key in keys:
        text = adaptive_reason_text(adaptive_mapping_get(record, reason_key))
        if text is not None:
            return text
    return None


def feature_ready_keys(key_text: str, base: str) -> tuple[str, ...]:
    graph_ready = ('graph_ready', 'graph_relationship_ready', 'graph_features_ready')
    extra_readiness = {
        'attention': graph_ready, 'graph': graph_ready, 'graph_chain': graph_ready,
        'attack_intelligence': ('attack_intelligence_ready',),
        'chain': ('chain_ready',),
        'mitre': ('mitre_ready',),
        'temporal': ('temporal_ready', 'stage_probability_ready', 'sequence_probability_ready'),
        'markov': ('markov_ready',), 'profile': ('profile_ready',), 'bucket': ('bucket_ready',),
        'vector': ('vector_ready',), 'evasion': ('evasion_ready',), 'engine': ('engine_ready',),
        'cluster': ('cluster_ready', 'cluster_signal_ready', 'risk_ready'),
    }.get(base, ())
    return (key_text + '_ready', key_text + '_probability_ready', base + '_ready',
            base + '_probability_ready', base + '_signal_ready', 'probability_ready', *extra_readiness)


def feature_ready_state_reason(feature_probs: Mapping[object, object], key_text: str, base: str, default_reason: object | None) -> str | None:
    for ready_key in feature_ready_keys(key_text, base):
        value = adaptive_mapping_get(feature_probs, ready_key)
        if value is False:
            return adaptive_reason_or_default(default_reason, base + '_probability_not_ready')
        invalid_reason = adaptive_invalid_flag_reason(value, ready_key)
        if invalid_reason is not None:
            return invalid_reason
    return None


def feature_degrade_state_reason(feature_probs: Mapping[object, object], base: str, default_reason: object | None) -> str | None:
    degraded_reason = adaptive_reason_or_default(default_reason, 'degraded_' + base + '_probability')
    for degraded_key in (base + '_degraded', 'degraded'):
        degraded = adaptive_mapping_get(feature_probs, degraded_key)
        if degraded is True:
            return degraded_reason
        invalid_degraded = adaptive_invalid_flag_reason(degraded, degraded_key)
        if invalid_degraded is not None:
            return invalid_degraded
    confidence_degraded = adaptive_mapping_get(feature_probs, base + '_confidence_degraded')
    if confidence_degraded is True:
        return adaptive_reason_or_default(default_reason, 'confidence_degraded_' + base + '_probability')
    return adaptive_invalid_flag_reason(confidence_degraded, base + '_confidence_degraded')


def probability_feature_unavailable_reason(feature_probs: object, key: str, unavailable_reason: object | None=None, default_reason: object | None=None) -> str | None:
    """Return feature-level unavailable/readiness evidence for replayed probabilities.

    Probability feature bundles are replayable model evidence and may be
    supplied directly by tests, replay, or final-JSON consumers. A high ``p_*``
    value next to ``*_ready=False``/``*_probability_ready=False`` is not usable
    learned support even when the producer failed to attach an explicit
    unavailable reason.
    """
    explicit_reason = adaptive_reason_text(unavailable_reason)
    if explicit_reason is not None:
        return explicit_reason
    if not isinstance(feature_probs, Mapping):
        return None
    key_text = exact_text_or_none(key)
    if key_text is None:
        return adaptive_reason_or_default(default_reason, 'invalid_probability_feature_key')
    base = key_text.removeprefix('p_')
    explicit_feature_reason = first_adaptive_reason(
        feature_probs,
        (
            key_text + '_unavailable_reason',
            base + '_unavailable_reason',
            base + '_failure_reason',
            base + '_error_reason',
        ),
    )
    if explicit_feature_reason is not None:
        return explicit_feature_reason
    readiness_reason = feature_ready_state_reason(feature_probs, key_text, base, default_reason)
    if readiness_reason is not None:
        return readiness_reason
    return feature_degrade_state_reason(feature_probs, base, default_reason)

def available_feature_probability(feature_probs: object, key: str, unavailable_reason: str) -> float:
    """Return a built feature probability only when its own availability is clean.

    The probability feature bundle is itself replayable model evidence. If a
    feature has already recorded unavailable/degraded/readiness-false evidence,
    its numeric value must not be used later as learned support just because
    downstream adaptive metadata is clean or absent.
    """
    if probability_feature_unavailable_reason(feature_probs, key, unavailable_reason) is not None:
        return 0.0
    return safe_clamp(adaptive_mapping_get(feature_probs, key, 0.0))

def readiness_or_degrade_reason(record: Mapping[object, object], readiness_default: str, degraded_reason: str, confidence_reason: str) -> str | None:
    readiness_reason = readiness_unavailable_reason(record, readiness_default)
    if readiness_reason is not None:
        return readiness_reason
    degraded = adaptive_mapping_get(record, 'degraded')
    if degraded is True:
        return degraded_reason
    invalid_degraded = adaptive_invalid_flag_reason(degraded, 'degraded')
    if invalid_degraded is not None:
        return invalid_degraded
    confidence_degraded = adaptive_mapping_get(record, 'confidence_degraded')
    if confidence_degraded is True:
        return confidence_reason
    return adaptive_invalid_flag_reason(confidence_degraded, 'confidence_degraded')


def layer_weight_unavailable_reason(layer: object, *reason_keys: str) -> str | None:
    """Return explicit layer-weight unavailability metadata before scoring.

    Adaptive layer-weight learning must not let a high score from any degraded
    layer become clean static/model ownership pressure. This applies to static
    quick/stage layers as well as graph and threat-intel layers because the
    derived learned/static split is output-affecting model evidence.
    """
    if not isinstance(layer, Mapping):
        return None
    explicit_reason = first_adaptive_reason(
        layer,
        (
            'unavailable_reason',
            'failure_reason',
            'error_reason',
            'reason',
            'quick_static_unavailable_reason',
            'stage_unavailable_reason',
            'stage_timeline_unavailable_reason',
            'graph_unavailable_reason',
            'graph_model_unavailable_reason',
            'threat_intel_unavailable_reason',
            'attack_intelligence_unavailable_reason',
            *reason_keys,
        ),
    )
    if explicit_reason is not None:
        return explicit_reason
    return readiness_or_degrade_reason(layer, 'layer_weight_signal_not_ready', 'degraded_layer_weight_signal', 'confidence_degraded_layer_weight_signal')

def available_layer_weight_score(layer: object, *reason_keys: str) -> float:
    """Return a layer score only when the layer is not degraded/unavailable."""
    if not isinstance(layer, Mapping):
        return 0.0
    if layer_weight_unavailable_reason(layer, *reason_keys) is not None:
        return 0.0
    return adaptive_weight_float(adaptive_mapping_get(layer, 'score', 0.0))

def layer_unavailable_reason(layer: object, *specific_keys: str) -> str | None:
    """Return explicit layer unavailability/degradation reason, if any.

    Layer probabilities are scoring inputs derived from model/analysis layers. A
    high layer score paired with unavailable/degraded metadata is failure
    evidence, not usable probability support.
    """
    if not isinstance(layer, Mapping):
        return None
    explicit_reason = first_adaptive_reason(
        layer,
        (
            'unavailable_reason',
            'failure_reason',
            'error_reason',
            'reason',
            'graph_unavailable_reason',
            'graph_model_unavailable_reason',
            'threat_intel_unavailable_reason',
            'attack_intelligence_unavailable_reason',
            'quick_unavailable_reason',
            'quick_static_unavailable_reason',
            'stage_unavailable_reason',
            'stage_timeline_unavailable_reason',
            'timeline_unavailable_reason',
            *specific_keys,
        ),
    )
    if explicit_reason is not None:
        return explicit_reason
    return readiness_or_degrade_reason(layer, 'layer_probability_not_ready', 'degraded_layer_probability', 'confidence_degraded_layer_probability')

def availability_aware_layer_probability_summary(layers: object) -> float:
    """Summarize layer probabilities without letting failed layers score.

    ``layer_probability_summary`` intentionally only normalizes scores. This
    adaptive boundary keeps availability metadata attached so downstream log-odds
    model/static probabilities cannot accidentally consume failed layer scores.
    """
    layers, adaptive_input_state = adaptive_public_mapping_with_state(layers)
    rejection_reason = adaptive_public_input_rejection_reason(layers)
    if rejection_reason is not None:
        return rejected_layer_probability_summary(layers, rejection_reason)
    summary: dict[str, object] = dict(layer_probability_summary(layers))
    summary["adaptive_input_state"] = adaptive_input_state
    summary["adaptive_input_reason"] = adaptive_input_state
    graph_reason = layer_unavailable_reason(adaptive_public_mapping(layers.get('graph')))
    intel_reason = layer_unavailable_reason(adaptive_public_mapping(layers.get('intel')))
    stage_reason = layer_unavailable_reason(adaptive_public_mapping(layers.get('stage')))
    quick_reason = layer_unavailable_reason(adaptive_public_mapping(layers.get('quick')))
    if graph_reason:
        summary['graph_probability'] = 0.0
        summary['graph_unavailable_reason'] = graph_reason
    if intel_reason:
        summary['threat_intel_probability'] = 0.0
        summary['threat_intel_unavailable_reason'] = intel_reason
    if stage_reason:
        summary['stage_probability'] = 0.0
        summary['stage_unavailable_reason'] = stage_reason
    if quick_reason:
        summary['quick_static_probability'] = 0.0
        summary['quick_static_unavailable_reason'] = quick_reason
    return summary

__all__ = ('adaptive_unavailable_reason', 'availability_aware_layer_probability_summary', 'available_feature_probability', 'available_layer_weight_score', 'available_model_signal_probability', 'layer_unavailable_reason', 'layer_weight_unavailable_reason', 'probability_feature_unavailable_reason')
