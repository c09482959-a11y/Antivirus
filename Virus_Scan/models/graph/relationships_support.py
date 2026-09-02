"""Support helpers for graph relationship evidence scoring."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast
import math

from Virus_Scan.contracts.telemetry import log_error, record_detector_error
from Virus_Scan.contracts.tag_evidence import (
    distinct_root_tag_evidence_records,
    tag_evidence_records,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_type_name,
)
from Virus_Scan.models.graph.common import graph_first_reason, graph_flag_enabled
from Virus_Scan.models.graph.features import unavailable_graph_features
from Virus_Scan.models.graph.relationship_boundaries import (
    graph_relationship_mapping_sort_key,
    graph_relationship_phase_hit_text,
    graph_relationship_sequence,
    graph_relationship_set_sort_key,
    graph_relationship_text,
)

def _finite_graph_relationship_metric(value: object, *, default: object=0.0, minimum: object=0.0, maximum: object=None) -> object:
    """Return a finite graph relationship metric without caller numeric hooks."""
    return no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason='non_numeric_graph_relationship_metric',
        non_finite_reason='non_finite_graph_relationship_metric',
        allow_exact_text=True,
    )
def _sanitize_graph_relationship_output(value: object) -> object:
    """Materialize nested graph relationship evidence into JSON-safe values."""
    if isinstance(value, float) and not math.isfinite(value):
        return {
            'value': None,
            'unavailable_reason': 'non_finite_graph_relationship_metric',
        }
    mapping_items = no_hook_mapping_items(value)
    if mapping_items is not None:
        out = {}
        for key, item in sorted(mapping_items, key=graph_relationship_mapping_sort_key):
            name, name_reason = graph_relationship_text(key, 'graph_relationship_key_unavailable')
            if name_reason:
                name = 'graph_relationship_key_unavailable'
            if type(item) is float and not math.isfinite(item):
                out[name] = None
                out[name + '_unavailable_reason'] = 'non_finite_graph_relationship_metric'
            else:
                out[name] = _sanitize_graph_relationship_output(item)
        return out
    if isinstance(value, Mapping):
        return {
            'value': None,
            'unavailable_reason': 'unreadable_graph_relationship_mapping',
            'value_type': no_hook_type_name(value),
        }
    if type(value) is set:
        return tuple(_sanitize_graph_relationship_output(item) for item in sorted(value, key=graph_relationship_set_sort_key))
    if type(value) is frozenset:
        return tuple(_sanitize_graph_relationship_output(item) for item in sorted(value, key=graph_relationship_set_sort_key))
    if type(value) in (list, tuple):
        sequence = cast("list[Any] | tuple[Any, ...]", value)
        return tuple(_sanitize_graph_relationship_output(item) for item in sequence)
    return value
def _sanitize_graph_relationship_mapping_output(value: object) -> dict[str, object]:
    sanitized = _sanitize_graph_relationship_output(value)
    if type(sanitized) is dict:
        return sanitized
    return {
        'value': None,
        'unavailable_reason': 'graph_relationship_mapping_materialization_failed',
        'value_type': no_hook_type_name(value),
    }
_RELATIONSHIP_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def _relationship_tag_evidence(tags: object) -> tuple[TagEvidence, list[str], str | None]:
    """Return one graph relationship tag per independent evidence root."""
    if type(tags) is TagEvidence:
        source = tags
    else:
        values, reason = graph_relationship_sequence(tags, 'graph_relationship_tags_unavailable')
        if reason != '':
            return TagEvidence(), [], 'unreadable_graph_relationship_tags'
        source = scoreable_tag_evidence(
            values, allowed_evidence_kinds=_RELATIONSHIP_EVIDENCE_KINDS,
        )
    records = distinct_root_tag_evidence_records(
        source.records, allowed_evidence_kinds=_RELATIONSHIP_EVIDENCE_KINDS,
    )
    if not records and int(source.summary.get('failure_count', 0)) > 0:
        return source, [], 'unreadable_graph_relationship_tags'
    root_tags = sorted({
        record.canonical_tag_id for record in records
        if record.polarity == 'positive' and record.canonical_tag_id
    })
    return source, root_tags, None


def _normalized_relationship_inputs(
    tags: object,
) -> tuple[TagEvidence, list[str], str | None]:
    """Normalize only graph-owned tag evidence for relationship scoring."""
    return _relationship_tag_evidence(tags)

def _relationship_node_features(node: object, graph_input_unavailable_reason: object, get_graph_features_fn: object) -> tuple[dict[str, object], object, str, list[str]]:
    graph_features = unavailable_graph_features(graph_first_reason(graph_input_unavailable_reason, default='graph_node_not_provided'))
    graph_unavailable_reason = graph_features['graph_unavailable_reason']
    metric_failures: list[str] = []
    node_text = ''
    try:
        node_text, node_text_reason = graph_relationship_text(node, 'graph_relationship_layer_failed') if node is not None else ('', '')
        node_text = str.strip(node_text)
        if node_text_reason != '':
            graph_features = unavailable_graph_features('graph_relationship_layer_failed')
            graph_unavailable_reason = graph_features['graph_unavailable_reason']
        elif node_text != '':
            graph_features = get_graph_features_fn(node_text)
            if graph_first_reason(graph_input_unavailable_reason) != '':
                graph_features = dict(graph_features)
                graph_features['graph_features_ready'] = False
                graph_features['graph_unavailable_reason'] = graph_input_unavailable_reason
            graph_unavailable_reason = graph_features.get('graph_unavailable_reason')
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error('graph relationship layer failed: ' + no_hook_type_name(exc))
        graph_features = unavailable_graph_features('graph_relationship_layer_failed')
        graph_unavailable_reason = graph_features['graph_unavailable_reason']
    return dict(graph_features), graph_unavailable_reason, node_text, metric_failures

def _relationship_feature_metrics(graph_features: dict[str, object], metric_failures: list[str]) -> tuple[float, float, float, dict[str, object]]:
    base, base_reason = _finite_graph_relationship_metric(graph_features.get('base_risk', 0.0))
    enhanced, enhanced_reason = _finite_graph_relationship_metric(graph_features.get('risk', 0.0))
    anomaly, anomaly_reason = _finite_graph_relationship_metric(graph_features.get('anomaly', 0.0))
    metric_failures.extend(reason for reason in (base_reason, enhanced_reason, anomaly_reason) if graph_first_reason(reason) != '')
    if len(metric_failures) > 0:
        graph_features = dict(graph_features)
        graph_features['risk'] = enhanced
        graph_features['base_risk'] = base
        graph_features['anomaly'] = anomaly
        graph_features['graph_features_ready'] = False
        graph_features['graph_unavailable_reason'] = metric_failures[0]
    return base, enhanced, anomaly, graph_features

def _relationship_score_from_node(node_text: str, tags: list[str], phase_hits: object, phase_root_count: int, concrete_count: int, graph_features: dict[str, object], metric_failures: list[str], get_graph_node_fn: object, propagate_fn: object) -> tuple[float, list[str], tuple[object, ...], dict[str, object]]:
    hits: list[str] = []
    score = 0.0
    prop_hits: object = []
    data = get_graph_node_fn(node_text) if node_text != '' else None
    if data is None:
        data = {'edges': set(), 'tags': set(), 'weights': {}, 'types': {}}
    base, enhanced, anomaly, graph_features = _relationship_feature_metrics(graph_features, metric_failures)
    edge_values, edge_values_reason = graph_relationship_sequence(data.get('edges', []), 'graph_relationship_edges_unavailable')
    node_records = tag_evidence_records(data.get('tag_evidence_records', ()))
    if node_records:
        _node_bundle, tag_values, tag_values_reason = _relationship_tag_evidence(
            TagEvidence.from_records(node_records)
        )
    else:
        projected_node_tags, projected_reason = graph_relationship_sequence(
            data.get('tags', ()), 'graph_node_tag_projection_unavailable',
        )
        tag_values = []
        tag_values_reason = (
            'graph_node_tag_evidence_unavailable'
            if projected_reason == '' and len(projected_node_tags) > 0
            else projected_reason
        )
    if graph_first_reason(edge_values_reason, tag_values_reason) != '':
        metric_failures.append(graph_first_reason(edge_values_reason, tag_values_reason))
    tag_overlap = len(set(tag_values) & set(tags))
    graph_base_score = min(30.0, enhanced * 30.0 + anomaly * 15.0 + base * 8.0)
    graph_edge_score = min(10.0, len(edge_values) * 0.2 + tag_overlap * 0.3)
    if concrete_count < 2:
        graph_base_score = min(graph_base_score, 8.0)
        graph_edge_score = min(graph_edge_score, 3.0)
    score += graph_base_score + graph_edge_score
    for phase in phase_hits:
        hits.append(graph_relationship_phase_hit_text(phase))
    if phase_root_count >= 2 and concrete_count >= 2:
        score += min(18.0, phase_root_count * 4.0)
        hits.append('multi_phase_relationship')
    elif len(phase_hits) >= 2:
        hits.append('multi_phase_relationship')
    try:
        prop_score, prop_hits = propagate_fn(node_text, max_depth=3)
        if len(tuple(prop_hits)) > 0:
            if concrete_count >= 2:
                prop_metric, prop_reason = _finite_graph_relationship_metric(prop_score)
                if graph_first_reason(prop_reason) != '':
                    metric_failures.append(prop_reason)
                score += min(14.0, prop_metric)
            hits.append('propagated_behavior_relationship')
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        record_detector_error('propagate_behavior_chains_from_node', exc, context={'node': node_text, 'stage': 'graph_relationship_layer'})
        prop_hits = []
    return score, hits, tuple(prop_hits), graph_features

def _graph_relationship_output(*, score: float, hits: list[str], phase_hits: object, prop_hits: tuple[object, ...], graph_features: dict[str, object], graph_unavailable_reason: object, metric_failures: list[str]) -> dict[str, object]:
    final_score, final_score_reason = _finite_graph_relationship_metric(score, maximum=100.0)
    if graph_first_reason(final_score_reason) != '':
        metric_failures.append(final_score_reason)
    if len(metric_failures) > 0:
        graph_unavailable_reason = graph_first_reason(graph_unavailable_reason, metric_failures[0])
        graph_features = dict(graph_features)
        graph_features['graph_features_ready'] = False
        graph_features['graph_unavailable_reason'] = graph_unavailable_reason
    graph_unavailable_reason_text = graph_first_reason(graph_unavailable_reason)
    graph_unavailable_reason = None if graph_unavailable_reason_text == '' else graph_unavailable_reason_text
    graph_features = _sanitize_graph_relationship_mapping_output(graph_features)
    prop_hits = tuple(_sanitize_graph_relationship_output(item) for item in prop_hits)
    return {
        'name': 'Layer 3 Graph Score',
        'score': final_score,
        'graph_features': graph_features,
        'graph_relationship_ready': graph_flag_enabled(graph_features.get('graph_features_ready')),
        'graph_unavailable_reason': graph_unavailable_reason,
        'degraded': graph_first_reason(graph_unavailable_reason) != '',
        'unavailable_reason': graph_unavailable_reason,
        'final_json_must_record': graph_first_reason(graph_unavailable_reason) != '',
        'replay_record_required': graph_first_reason(graph_unavailable_reason) != '',
        'phase_hits': phase_hits,
        'propagated_chains': prop_hits[:10],
        'hits': sorted(set(hits)),
        'summary': 'relationships',
    }
