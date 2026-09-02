from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import graph_node_snapshot
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.attention import graph_attention_evidence
from Virus_Scan.models.graph.baseline import context_baseline_component
from Virus_Scan.models.graph.cache import GRAPH_RISK_CACHE, cache_get, cache_key, cache_set
from Virus_Scan.models.graph.common import (
    graph_finite_float,
    graph_first_reason,
    graph_unit_interval,
    record_graph_input_degraded,
)
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.risk_support import (
    GRAPH_RISK_CACHE_UNAVAILABLE,
    combine_components,
    remove_corrupt_cache_entry,
    validated_cached_graph_risk,
)
from Virus_Scan.models.graph.contracts import (
    GRAPH_ATTENTION_CONTRACT_VERSION,
    GRAPH_CONTEXT_BASELINE_VERSION,
    GRAPH_EXECUTION_CONTRACT_VERSION,
    GRAPH_RISK_EVIDENCE_VERSION,
    GRAPH_RISK_MODEL_VERSION,
    GRAPH_RISK_POLICY,
    GRAPH_TEMPORAL_CONTRACT_VERSION,
    GraphRiskEvidence,
    unavailable_component,
)
from Virus_Scan.models.graph.execution import (
    execution_graph_component,
    temporal_graph_component,
)
from Virus_Scan.models.graph.snapshot import admitted_graph_snapshot
from Virus_Scan.models.graph.structural import structural_graph_component

GRAPH_RISK_UNAVAILABLE_SCORE = 0.0
def _mapping_get(value: object, name: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if isinstance(key, str) and str.__str__(key) == name:
            return item
    return default


def compute_graph_signal(node: object) -> object:
    return get_graph_risk(node) * 0.5


def get_graph_risk(node: object) -> object:
    """Return the canonical bounded structural graph component."""
    try:
        snapshot, reason = admitted_graph_snapshot(graph_node_snapshot(node))
        if snapshot is None:
            record_graph_input_degraded('graph_risk_snapshot_unavailable', reason)
            return GRAPH_RISK_UNAVAILABLE_SCORE
        return structural_graph_component(snapshot).value
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(graph_exception_message('get_graph_risk failed: ', exc))
        record_graph_input_degraded('graph_risk_computation_failed', 'graph_risk_computation_failed')
        return GRAPH_RISK_UNAVAILABLE_SCORE


def get_graph_risk_enhanced_evidence(node: object) -> object:
    """Return versioned component-level graph-risk evidence."""
    key = cache_key('graph_risk_enhanced', node)
    raw_snapshot = graph_node_snapshot(node)
    snapshot, snapshot_reason = admitted_graph_snapshot(raw_snapshot)
    cached = cache_get(GRAPH_RISK_CACHE, key)
    cached_record = validated_cached_graph_risk(
        cached, key=key, node=node, snapshot=snapshot,
    )
    if cached_record is not GRAPH_RISK_CACHE_UNAVAILABLE:
        return cached_record
    if cached is not None:
        cleanup_failure = remove_corrupt_cache_entry(key, node)
        if cleanup_failure is not None:
            return cleanup_failure
    if snapshot is None:
        return {
            'risk': 0.0,
            'ready': False,
            'degraded': True,
            'unavailable_reason': snapshot_reason,
            'evidence_type': 'graph_risk',
            'evidence_version': GRAPH_RISK_EVIDENCE_VERSION,
            'policy_version': GRAPH_RISK_POLICY.version,
            'decision_threshold': GRAPH_RISK_POLICY.decision_threshold,
            'policy_selection_evidence': GRAPH_RISK_POLICY.selection_evidence,
            'model_version': GRAPH_RISK_MODEL_VERSION,
            'cache_key': key,
            'final_json_must_record': True,
            'replay_record_required': True,
        }
    try:
        structural = structural_graph_component(snapshot)
        attention = graph_attention_evidence(node)
        execution = execution_graph_component(node, snapshot)
        temporal = temporal_graph_component(snapshot)
        primary = {
            'structural': structural,
            'attention': attention,
            'execution': execution,
            'temporal': temporal,
        }
        anomaly = context_baseline_component(snapshot, primary)
        components = {**primary, 'context_anomaly': anomaly}
        combined, confidence, maturity, component_reasons = combine_components(components)
        supplemental_weight = (
            GRAPH_RISK_POLICY.attention_weight
            + GRAPH_RISK_POLICY.execution_weight
            + GRAPH_RISK_POLICY.temporal_weight
            + GRAPH_RISK_POLICY.anomaly_weight
        )
        supplemental = 0.0
        if supplemental_weight > 0.0:
            supplemental = (
                attention.value * GRAPH_RISK_POLICY.attention_weight
                + execution.value * GRAPH_RISK_POLICY.execution_weight
                + temporal.value * GRAPH_RISK_POLICY.temporal_weight
                + anomaly.value * GRAPH_RISK_POLICY.anomaly_weight
            ) / supplemental_weight
        risk = graph_unit_interval(
            structural.value
            + (1.0 - structural.value) * supplemental * confidence
        )[0]
        unavailable_reason = None if structural.ready else structural.unavailable_reason
        evidence = GraphRiskEvidence(
            risk=risk,
            ready=structural.ready,
            degraded=not structural.ready,
            component_degraded=len(component_reasons) > 0,
            component_unavailable_reasons=component_reasons,
            unavailable_reason=unavailable_reason,
            confidence=confidence,
            maturity=maturity,
            snapshot_version=str.__str__(snapshot['snapshot_version']),
            snapshot_digest=str.__str__(snapshot['snapshot_digest']),
            node_id=str.__str__(snapshot['node_id']),
            node_type=str.__str__(snapshot['node_type']),
            update_ordinal=int(snapshot['update_ordinal']),
            policy_version=GRAPH_RISK_POLICY.version,
            model_version=GRAPH_RISK_MODEL_VERSION,
            cache_key=key,
            source='snapshot',
            structural=structural,
            attention=attention,
            execution=execution,
            temporal=temporal,
            context_anomaly=anomaly,
        ).to_record()
        cache_set(GRAPH_RISK_CACHE, key, evidence)
        return evidence
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(graph_exception_message('get_graph_risk_enhanced failed: ', exc))
        return {
            'risk': 0.0,
            'ready': False,
            'degraded': True,
            'unavailable_reason': 'graph_risk_computation_failed',
            'evidence_type': 'graph_risk',
            'evidence_version': GRAPH_RISK_EVIDENCE_VERSION,
            'policy_version': GRAPH_RISK_POLICY.version,
            'decision_threshold': GRAPH_RISK_POLICY.decision_threshold,
            'policy_selection_evidence': GRAPH_RISK_POLICY.selection_evidence,
            'model_version': GRAPH_RISK_MODEL_VERSION,
            'cache_key': key,
            'final_json_must_record': True,
            'replay_record_required': True,
        }


def get_graph_risk_enhanced(node: object) -> object:
    return graph_finite_float(
        _mapping_get(get_graph_risk_enhanced_evidence(node), 'risk', 0.0),
        minimum=0.0,
        maximum=1.0,
    )[0]


__all__ = (
    'compute_graph_signal',
    'get_graph_risk',
    'get_graph_risk_enhanced',
    'get_graph_risk_enhanced_evidence',
)
