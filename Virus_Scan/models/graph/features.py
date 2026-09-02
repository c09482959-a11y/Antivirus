from __future__ import annotations

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.graph_state import graph_node_snapshot
from Virus_Scan.models.graph.common import graph_first_reason
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.graph.attention import graph_snapshot_corruption_reason
from Virus_Scan.models.graph.risk import get_graph_risk_enhanced_evidence


def _mapping_get(value: object, name: str, default: object = None) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if isinstance(key, str) and str.__str__(key) == name:
            return item
    return default


def unavailable_graph_features(reason: object) -> object:
    return {
        'risk': 0.0,
        'base_risk': 0.0,
        'anomaly': 0.0,
        'attention': 0.0,
        'execution': 0.0,
        'temporal_relationship_risk': 0.0,
        'confidence': 0.0,
        'maturity': 0.0,
        'components': {},
        'graph_features_ready': False,
        'graph_features_degraded': True,
        'graph_unavailable_reason': graph_first_reason(reason, default='graph_unavailable'),
        'graph_degraded_reason': graph_first_reason(reason, default='graph_unavailable'),
    }


def get_graph_features(node: object) -> object:
    """Return the canonical component-level graph feature projection."""
    try:
        data = graph_node_snapshot(node)
        if data is None:
            return unavailable_graph_features('graph_node_unavailable')
        corruption_reason = graph_snapshot_corruption_reason(data)
        if graph_first_reason(corruption_reason) != '':
            return unavailable_graph_features(corruption_reason)
        evidence = get_graph_risk_enhanced_evidence(node)
        ready = _mapping_get(evidence, 'ready') is True
        if not ready:
            return unavailable_graph_features(
                _mapping_get(evidence, 'unavailable_reason', 'graph_risk_unavailable')
            )
        structural = float(_mapping_get(evidence, 'structural_risk', 0.0))
        anomaly = float(_mapping_get(evidence, 'context_baseline_anomaly', 0.0))
        return {
            'risk': float(_mapping_get(evidence, 'risk', 0.0)),
            'base_risk': structural,
            'anomaly': anomaly,
            'attention': float(_mapping_get(evidence, 'attention', 0.0)),
            'execution': float(_mapping_get(evidence, 'execution', 0.0)),
            'temporal_relationship_risk': float(
                _mapping_get(evidence, 'temporal_relationship_risk', 0.0)
            ),
            'confidence': float(_mapping_get(evidence, 'confidence', 0.0)),
            'maturity': float(_mapping_get(evidence, 'maturity', 0.0)),
            'components': _mapping_get(evidence, 'components', {}),
            'snapshot_version': _mapping_get(evidence, 'snapshot_version'),
            'snapshot_digest': _mapping_get(evidence, 'snapshot_digest'),
            'policy_version': _mapping_get(evidence, 'policy_version'),
            'model_version': _mapping_get(evidence, 'model_version'),
            'graph_features_ready': True,
            'graph_features_degraded': (
                _mapping_get(evidence, 'degraded') is True
                or _mapping_get(evidence, 'component_degraded') is True
            ),
            'graph_unavailable_reason': None,
            'graph_degraded_reason': (
                _mapping_get(evidence, 'component_unavailable_reasons', ())[0]
                if type(_mapping_get(evidence, 'component_unavailable_reasons', ())) is tuple
                and len(_mapping_get(evidence, 'component_unavailable_reasons', ())) > 0
                else _mapping_get(evidence, 'unavailable_reason')
            ),
        }
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error('graph feature error: ' + no_hook_type_name(exc))
        return unavailable_graph_features('graph_feature_error')


__all__ = ('get_graph_features', 'unavailable_graph_features')
