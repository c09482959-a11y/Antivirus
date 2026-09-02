from collections.abc import Mapping

from Virus_Scan.contracts.no_hook_materialization import no_hook_finite_float

from Virus_Scan.detection.scoring.adaptive.confidence import (
    coerce_model_probability,
    model_signal_unavailable_reason,
    readiness_unavailable_reason,
)
from Virus_Scan.detection.scoring.adaptive.feature_bundle import model_cluster_risk_score_evidence
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_input_rejection_reason,
    adaptive_public_mapping,
    adaptive_public_sequence,
    adaptive_public_text,
    adaptive_public_text_with_reason,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import (
    ClusterStateNotConfigured,
    cluster_state,
    graph_vector_node_key,
    log_error,
)
from Virus_Scan.utils.probability import safe_clamp


PLR2004N100_0 = 100.0

__all__ = (
    'cluster_probability_feature',
    'graph_chain_probability_from_layer',
)


def _graph_unavailable_reason_text(value: object) -> object:
    if isinstance(value, (str, bytes)) or type(value) in {bool, int, float}:
        text, failure = adaptive_public_text_with_reason(value, default='')
        if failure:
            return '', 'graph_unavailable_reason_text_unavailable'
        return text, None
    return '', 'graph_unavailable_reason_text_unavailable'

def cluster_probability_feature(node: object) -> object:
    node_text = adaptive_public_text(node)
    if not node_text:
        return 0.0, 'cluster_node_not_provided'
    try:
        state = cluster_state()
    except ClusterStateNotConfigured:
        log_error('cluster probability unavailable from runtime-owned state')
        return 0.0, 'runtime_cluster_state_not_configured'
    graph_key = graph_vector_node_key(node)
    node_key = graph_key or node_text
    if node_key not in state.node_cluster_map:
        return 0.0, 'cluster_not_assigned'
    try:
        cluster_risk_evidence = model_cluster_risk_score_evidence(node)
        probability, value_reason = coerce_model_probability(
            cluster_risk_evidence.get('risk', 0.0),
            'non_finite_cluster_probability',
        )
        return probability, model_signal_unavailable_reason(cluster_risk_evidence) or value_reason
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('cluster probability computation failed')
        return 0.0, 'cluster_probability_failed'

def graph_chain_probability_from_layer(layer: object) -> object:
    """Project canonical graph-layer evidence into a bounded probability.

    Adaptive scoring consumes the graph model's public relationship layer instead of
    leaving p_graph_chain as an inactive zero field or recomputing graph internals.
    A malformed graph-layer score is degraded graph evidence; hits alone must not
    boost the learned-model side when the graph score contract is invalid.
    """
    if not isinstance(layer, Mapping):
        return 0.0, 'non_mapping_graph_relationship_layer'
    layer = adaptive_public_mapping(layer)
    rejection_reason = adaptive_public_input_rejection_reason(layer)
    if rejection_reason is not None:
        return 0.0, rejection_reason
    unavailable_reason = layer.get('graph_unavailable_reason')
    if unavailable_reason is not None:
        unavailable_reason_text, unavailable_text_failure = _graph_unavailable_reason_text(unavailable_reason)
        if unavailable_reason_text:
            return 0.0, unavailable_reason_text
        if unavailable_text_failure:
            return 0.0, 'graph_unavailable_reason_text_unavailable'
    readiness_reason = readiness_unavailable_reason(layer, 'graph_relationship_layer_not_ready')
    if readiness_reason:
        return 0.0, readiness_reason
    raw_score_value = layer.get('score', 0.0)
    if (
        type(raw_score_value) is dict
        and dict.get(raw_score_value, 'unavailable_reason')
        == 'non_finite_adaptive_public_input_number'
    ):
        return 0.0, 'non_finite_graph_chain_score'
    raw_score, raw_score_reason = no_hook_finite_float(
        raw_score_value,
        default=0.0,
        reason='non_numeric_graph_chain_score',
        non_finite_reason='non_finite_graph_chain_score',
        allow_exact_text=True,
    )
    if raw_score_value is None or raw_score_reason:
        return 0.0, raw_score_reason or 'non_numeric_graph_chain_score'
    if raw_score < 0.0 or raw_score > PLR2004N100_0:
        return 0.0, 'out_of_bounds_graph_chain_score'
    score = safe_clamp(raw_score / 100.0)
    hits = adaptive_public_sequence(layer.get('hits'))
    propagated = adaptive_public_sequence(layer.get('propagated_chains'))
    if not hits and not propagated:
        return 0.0, None
    evidence_boost = min(0.35, 0.06 * len(hits) + 0.08 * len(propagated))
    return safe_clamp(max(score, evidence_boost)), None
