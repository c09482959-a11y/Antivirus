from __future__ import annotations

from collections.abc import Callable, Mapping

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.attack.mapping.contracts import AttackMappingResult
from Virus_Scan.detection.attack.api import (
    official_attack_probability_evidence,
    unavailable_official_attack_probability_evidence,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence

from Virus_Scan.detection.scoring.adaptive.boundary_values import (
    adaptive_mapping_get,
    first_adaptive_reason_text,
)
from Virus_Scan.detection.scoring.adaptive.confidence import (
    coerce_model_probability,
    coerce_scaled_model_probability,
    max_model_probability,
    model_signal_unavailable_reason,
    readiness_unavailable_reason,
)
from Virus_Scan.detection.scoring.adaptive.model_inputs import (
    graph_chain_probability_from_layer,
)
from Virus_Scan.detection.scoring.adaptive.public_inputs import (
    adaptive_public_text,
)
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.api import log_error


def graph_probability_components(
    node_for_model: object,
    node_unavailable_reason: str | None,
    tags: object,
    *,
    model_graph_risk_enhanced_fn: Callable[[object], object],
    original_model_graph_risk_enhanced: object,
    model_graph_risk_enhanced_evidence_fn: Callable[[object], Mapping[str, object]],
    model_graph_relationship_layer_fn: Callable[..., object],
) -> tuple[float, float, str | None]:
    if node_for_model is None:
        return 0.0, 0.0, node_unavailable_reason or 'graph_node_not_provided'
    if model_graph_risk_enhanced_fn is not original_model_graph_risk_enhanced:
        p_graph, p_graph_reason = coerce_scaled_model_probability(
            model_graph_risk_enhanced_fn(node_for_model),
            10.0,
            'non_finite_graph_probability',
        )
    else:
        graph_risk_evidence = model_graph_risk_enhanced_evidence_fn(node_for_model)
        p_graph, graph_value_reason = coerce_scaled_model_probability(
            graph_risk_evidence.get('risk', 0.0),
            10.0,
            'non_finite_graph_probability',
        )
        p_graph_reason = model_signal_unavailable_reason(graph_risk_evidence) or graph_value_reason
    try:
        graph_layer = model_graph_relationship_layer_fn(node_for_model, tags=tags)
        p_graph_chain, graph_chain_reason = graph_chain_probability_from_layer(graph_layer)
        graph_layer_reason = first_adaptive_reason_text(
            adaptive_mapping_get(graph_layer, 'graph_unavailable_reason')
            if isinstance(graph_layer, Mapping)
            else None
        )
        if graph_layer_reason is not None:
            p_graph_reason = graph_layer_reason
        elif graph_chain_reason is not None:
            p_graph_reason = graph_chain_reason
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('graph chain probability unavailable from graph model evidence')
        p_graph_chain = 0.0
        p_graph_reason = 'graph_chain_probability_failed'
    return p_graph, p_graph_chain, p_graph_reason


def temporal_probability_component(
    node_for_model: object,
    node_unavailable_reason: str | None,
    *,
    model_temporal_snapshot_fn: Callable[[object], Mapping[str, object]],
) -> tuple[float, str | None]:
    if node_for_model is None:
        return 0.0, node_unavailable_reason or 'temporal_node_not_provided'
    try:
        temporal_snapshot = model_temporal_snapshot_fn(node_for_model)
        p_temporal, temporal_value_reason = coerce_model_probability(
            temporal_snapshot.get('belief', 0.0),
            'non_finite_temporal_probability',
        )
        p_temporal_reason = temporal_value_reason
        if adaptive_mapping_get(temporal_snapshot, 'ready') is not True:
            p_temporal_reason = first_adaptive_reason_text(
                adaptive_mapping_get(temporal_snapshot, 'unavailable_reason'),
                adaptive_mapping_get(temporal_snapshot, 'reason'),
                temporal_value_reason,
                'temporal_not_ready',
            )
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('temporal probability unavailable from temporal model evidence')
        p_temporal = 0.0
        p_temporal_reason = 'temporal_probability_failed'
    return p_temporal, p_temporal_reason


def markov_probability_component(
    tags: object,
    ordered_events: object,
    prev_stage: object,
    curr_stage: object,
    *,
    model_behavior_flow_fn: Callable[[object], object],
    model_markov_features_fn: Callable[..., Mapping[str, object]],
) -> tuple[float, str | None]:
    try:
        behavior_source = ordered_events or tags
        behavior_flow = model_behavior_flow_fn(behavior_source)
        markov_f = model_markov_features_fn(
            adaptive_public_text(prev_stage, default='unknown'),
            behavior_flow,
            adaptive_public_text(curr_stage, default='unknown'),
        )
        p_markov, markov_value_reason = max_model_probability(
            (
                markov_f.get('transition', 0.0),
                markov_f.get('rarity', 0.0),
                markov_f.get('pair_anomaly', 0.0),
            ),
            'non_finite_markov_probability',
        )
        p_markov_reason = model_signal_unavailable_reason(markov_f) or markov_value_reason
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('model probability component failed without synthetic substitute')
        p_markov = 0.0
        p_markov_reason = 'markov_probability_failed'
    return p_markov, p_markov_reason


def attack_intelligence_probability_component(
    tags: object,
    yara_hits: object,
    *,
    compute_attack_intelligence_fn: Callable[[object, object], Mapping[str, object]],
) -> tuple[float, str | None]:
    try:
        attack = compute_attack_intelligence_fn(tags, yara_hits)
        probability, value_reason = coerce_model_probability(
            attack.get("aggregate_probability", 0.0),
            "non_finite_attack_intelligence_probability",
        )
        reason = first_adaptive_reason_text(
            readiness_unavailable_reason(attack, "attack_intelligence_not_ready"),
            value_reason,
        )
        return (0.0, reason) if reason else (probability, None)
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error("attack intelligence probability failed without synthetic substitute")
        return 0.0, "attack_intelligence_probability_failed"


def chain_probability_component(
    chain_evidence: ChainEvidence,
) -> tuple[float, str | None]:
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("canonical_chain_evidence_required")
    probability, value_reason = coerce_model_probability(
        chain_evidence.total_score_points / 75.0,
        "non_finite_chain_probability",
    )
    reason = first_adaptive_reason_text(
        "chain_evidence_degraded" if chain_evidence.failures else None,
        value_reason,
    )
    return (0.0, reason) if reason else (probability, None)


def mitre_probability_component(
    attack_mapping_result: AttackMappingResult,
) -> tuple[float, str | None, dict[str, object]]:
    """Project already-final canonical evidence through official ATT&CK mapping.

    YARA physical results and reviewed-alignment policy are intentionally absent
    from this scoring boundary.  Any YARA-backed facts must already have been
    assimilated into canonical Tag/Chain evidence upstream.
    """
    if type(attack_mapping_result) is not AttackMappingResult:
        raise TypeError("canonical_attack_mapping_result_required")
    try:
        evidence = official_attack_probability_evidence(attack_mapping_result)
        if (
            adaptive_mapping_get(evidence, "mapping_scope") != "official_attack_techniques"
            or adaptive_mapping_get(evidence, "ready") is not True
        ):
            return 0.0, "mitre_official_mapping_unavailable", evidence
        probability, value_reason = coerce_model_probability(
            adaptive_mapping_get(evidence, "probability", 0.0),
            "non_finite_mitre_probability",
        )
        reason = first_adaptive_reason_text(
            readiness_unavailable_reason(evidence, "mitre_not_ready"),
            value_reason,
        )
        return ((0.0 if reason else probability), reason, evidence)
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error("MITRE probability unavailable from official mapping evidence")
        return (
            0.0,
            "mitre_probability_failed",
            unavailable_official_attack_probability_evidence(
                "mitre_probability_failed"
            ),
        )

def evasion_probability_component(
    tags: object,
    node_for_model: object,
    node_unavailable_reason: str | None,
    *,
    detect_evasion_signals_fn: Callable[[object, object], object],
) -> tuple[float, str | None]:
    if node_unavailable_reason is not None:
        return 0.0, node_unavailable_reason
    try:
        return coerce_model_probability(
            detect_evasion_signals_fn(tags, node_for_model),
            'non_finite_evasion_probability',
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        log_error('evasion probability failed')
        return 0.0, 'evasion_probability_failed'


def cluster_probability_component(
    node_for_model: object,
    *,
    cluster_probability_feature_fn: Callable[[object], tuple[float, str | None]],
) -> tuple[float, str | None]:
    return cluster_probability_feature_fn(node_for_model)
