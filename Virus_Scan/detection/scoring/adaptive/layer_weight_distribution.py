"""Input and distribution helpers for adaptive layer-weight learning."""

from Virus_Scan.detection.scoring.adaptive.availability import layer_weight_unavailable_reason
from Virus_Scan.detection.scoring.adaptive.confidence import adaptive_normalized_weights
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_event_sequence,
    adaptive_public_input_rejection_reason,
    adaptive_public_mapping,
    adaptive_public_sequence,
    adaptive_public_text,
)
from Virus_Scan.detection.scoring.weighting.numeric import adaptive_weight_float
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    scoreable_tag_evidence,
)
from Virus_Scan.utils.probability import safe_clamp


def distribute_static_learned_model_weights_impl(
    base_weights: object,
    static_share: object,
    learned_model_share: object,
    model_pressure: object = 0.0,
) -> object:
    """Distribute static/model shares back onto the existing four layer names."""
    base_weights = adaptive_public_mapping(base_weights)
    if adaptive_public_input_rejection_reason(base_weights) is not None:
        return dict(base_weights)
    base_weights = dict(base_weights)
    static_keys = ('quick_static', 'threat_intel')
    model_keys = ('stage_timeline', 'graph_relationships')
    static_total = sum((adaptive_weight_float(base_weights.get(k, 0.0)) for k in static_keys)) or 1.0
    model_total = sum((adaptive_weight_float(base_weights.get(k, 0.0)) for k in model_keys)) or 1.0
    out = {}
    for k in static_keys:
        out[k] = static_share * (adaptive_weight_float(base_weights.get(k, 0.0)) / static_total)
    stage_bias = 0.5 + 0.15 * safe_clamp(model_pressure)
    graph_bias = 1.0 - stage_bias
    raw_stage = adaptive_weight_float(base_weights.get('stage_timeline', 0.0)) / model_total
    raw_graph = adaptive_weight_float(base_weights.get('graph_relationships', 0.0)) / model_total
    mix_stage = safe_clamp(raw_stage * 0.5 + stage_bias * 0.5, 0.25, 0.8)
    mix_graph = safe_clamp(raw_graph * 0.5 + graph_bias * 0.5, 0.2, 0.75)
    total_model_mix = max(0.0001, mix_stage + mix_graph)
    out['stage_timeline'] = learned_model_share * (mix_stage / total_model_mix)
    out['graph_relationships'] = learned_model_share * (mix_graph / total_model_mix)
    return adaptive_normalized_weights(out)


def normalize_layer_weight_learning_inputs(
    tags: object,
    api_calls: object,
    ordered_events: object,
    strings_blob: object,
    quick: object,
    stage: object,
    graph: object,
    intel: object,
) -> dict[str, object]:
    """Normalize public adaptive learner inputs at one no-hook boundary."""
    stable_tags = tags if type(tags) is TagEvidence else adaptive_public_sequence(tags)
    tag_evidence = scoreable_tag_evidence(
        stable_tags, allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    normalized_tags = list(tag_evidence.tags)
    return {
        'tags': normalized_tags,
        'tag_evidence': tag_evidence,
        'api_calls': adaptive_public_sequence(api_calls),
        'ordered_events': adaptive_public_event_sequence(ordered_events),
        'strings_blob': adaptive_public_text(strings_blob),
        'quick': adaptive_public_mapping(quick),
        'stage': adaptive_public_mapping(stage),
        'graph': adaptive_public_mapping(graph),
        'intel': adaptive_public_mapping(intel),
        'scoreable': frozenset(normalized_tags),
    }


def layer_weight_score_state(
    base: object,
    tags: object,
    quick: object,
    stage: object,
    graph: object,
    intel: object,
) -> dict[str, object]:
    """Build unavailable reasons and numeric score state for layer weights."""
    quick_reason = layer_weight_unavailable_reason(
        quick, 'quick_unavailable_reason', 'quick_static_unavailable_reason'
    )
    stage_reason = layer_weight_unavailable_reason(
        stage, 'stage_unavailable_reason', 'stage_timeline_unavailable_reason'
    )
    graph_reason = layer_weight_unavailable_reason(
        graph, 'graph_unavailable_reason', 'graph_model_unavailable_reason'
    )
    intel_reason = layer_weight_unavailable_reason(
        intel, 'threat_intel_unavailable_reason', 'attack_intelligence_unavailable_reason'
    )
    quick_score = 0.0 if quick_reason else adaptive_weight_float(quick.get('score', 0.0))
    stage_score = 0.0 if stage_reason else adaptive_weight_float(stage.get('score', 0.0))
    graph_score = 0.0 if graph_reason else adaptive_weight_float(graph.get('score', 0.0))
    intel_score = 0.0 if intel_reason else adaptive_weight_float(intel.get('score', 0.0))
    preliminary = (
        quick_score * base.get('quick_static', 0.0)
        + stage_score * base.get('stage_timeline', 0.0)
        + graph_score * base.get('graph_relationships', 0.0)
        + intel_score * base.get('threat_intel', 0.0)
    )
    return {
        'quick_unavailable_reason': quick_reason,
        'stage_unavailable_reason': stage_reason,
        'graph_unavailable_reason': graph_reason,
        'intel_unavailable_reason': intel_reason,
        'quick_score': quick_score,
        'stage_score': stage_score,
        'graph_score': graph_score,
        'intel_score': intel_score,
        'preliminary': preliminary,
        'concrete_count': concrete_score_count(tags),
    }
