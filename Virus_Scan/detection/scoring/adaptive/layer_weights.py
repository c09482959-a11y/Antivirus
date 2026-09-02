from Virus_Scan.detection.scoring.adaptive.confidence import (
    adaptive_normalized_weights,
)
from Virus_Scan.detection.scoring.adaptive.layer_weight_distribution import (
    distribute_static_learned_model_weights_impl,
    layer_weight_score_state,
    normalize_layer_weight_learning_inputs,
)
from Virus_Scan.detection.scoring.adaptive.layer_weight_rolling import (
    layer_weight_learning_metadata,
    rolling_layer_weight_state,
)
from Virus_Scan.detection.scoring.adaptive.layer_weight_signals import (
    adaptive_model_signal_state,
    apply_adaptive_model_weight_adjustments,
)
from Virus_Scan.detection.scoring.adaptive.settings import ADAPTIVE_WEIGHT_VERSION


def distribute_static_learned_model_weights(
    base_weights: object,
    static_share: object,
    learned_model_share: object,
    model_pressure: object = 0.0,
) -> object:
    """Distribute static/model shares back onto the existing four layer names."""
    return distribute_static_learned_model_weights_impl(
        base_weights,
        static_share,
        learned_model_share,
        model_pressure=model_pressure,
    )


def learn_adaptive_layer_weights(
    node: object,
    tags: object,
    quick: object,
    stage: object,
    graph: object,
    intel: object,
    prev_stage: object = None,
    curr_stage: object = None,
    strings_blob: object = '',
    api_calls: object = None,
    ordered_events: object = None,
) -> object:
    """Learn adaptive layer weights from explicit public inputs and model signals."""
    base = {
        'quick_static': 0.28,
        'stage_timeline': 0.22,
        'graph_relationships': 0.2,
        'threat_intel': 0.3,
    }
    normalized = normalize_layer_weight_learning_inputs(
        tags,
        api_calls,
        ordered_events,
        strings_blob,
        quick,
        stage,
        graph,
        intel,
    )
    score_state = layer_weight_score_state(
        base,
        normalized['tag_evidence'],
        normalized['quick'],
        normalized['stage'],
        normalized['graph'],
        normalized['intel'],
    )
    signal_state = adaptive_model_signal_state(
        node,
        normalized['tag_evidence'],
        prev_stage,
        curr_stage,
        normalized['strings_blob'],
        normalized['api_calls'],
        normalized['ordered_events'],
        score_state['preliminary'],
    )
    adjusted_weights = apply_adaptive_model_weight_adjustments(
        base,
        score_state,
        signal_state,
    )
    pre_rolling_weights = adaptive_normalized_weights(adjusted_weights)
    rolling_state = rolling_layer_weight_state(
        pre_rolling_weights,
        score_state,
        signal_state,
    )
    weights = rolling_state['weights']
    meta = layer_weight_learning_metadata(
        ADAPTIVE_WEIGHT_VERSION,
        base,
        pre_rolling_weights,
        weights,
        score_state,
        signal_state,
        rolling_state['learned_static'],
    )
    return (weights, meta)
