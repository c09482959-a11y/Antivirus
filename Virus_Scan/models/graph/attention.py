from __future__ import annotations
import math
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.runtime.constants import GLOBAL_HALF_LIFE
from Virus_Scan.runtime.graph_state import graph_has_node, graph_node_snapshot
from Virus_Scan.models.graph.common import (
    safe_graph_text,
    graph_first_reason,
    graph_finite_float,
    graph_unit_interval,
    graph_owned_key_matches,
    record_graph_input_degraded,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_mapping_items
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.state import get_graph_node
from Virus_Scan.models.graph.contracts import (
    GRAPH_ATTENTION_CONTRACT_VERSION,
    GRAPH_RISK_POLICY,
    GraphComponentEvidence,
    unavailable_component,
)
from Virus_Scan.models.graph.snapshot import admitted_edge_records, admitted_graph_snapshot
from Virus_Scan.models.graph.attention_runtime import (
    coerce_graph_attention_time,
    graph_attention_reference_time,
    graph_tag_baseline_snapshot,
)
from Virus_Scan.models.graph.attention_metrics import (
    GRAPH_ATTENTION_UNAVAILABLE_SCORE,
    attention_lookup_result,
    safe_attention_lookup,
)
PLR2004N0_01 = 0.01
def _owned_mapping_items(value: object) -> object:
    items = no_hook_mapping_items(value)
    return () if items is None else items
def _owned_mapping_get(value: object, name: object, default: object=None) -> object:
    for key, item in _owned_mapping_items(value):
        if graph_owned_key_matches(key, name):
            return item
    return default
def _owned_mapping_values(value: object) -> object:
    return tuple(item for _key, item in _owned_mapping_items(value))
def graph_snapshot_corruption_reason(data: object) -> object:
    """Classify corrupt graph snapshot fields before publishing ready graph evidence.
    Runtime graph-state APIs sanitize non-finite scalars before exposing
    snapshots, but they also preserve unavailable-reason fields so downstream
    model evidence does not silently treat sanitized ``0.0``/``1.0`` values as
    valid learned graph evidence.
    """
    if no_hook_mapping_items(data) is None:
        return 'graph_node_unavailable'
    for reason_key in (
        'risk_unavailable_reason',
        'attention_unavailable_reason',
    ):
        reason_value = graph_first_reason(_owned_mapping_get(data, reason_key))
        if reason_value != '':
            return reason_value
    weight_reasons = _owned_mapping_get(data, 'weight_unavailable_reasons', {})
    if no_hook_mapping_items(weight_reasons) is not None:
        for reason_value in _owned_mapping_values(weight_reasons):
            reason_text = graph_first_reason(reason_value)
            if reason_text != '':
                return reason_text
    elif weight_reasons is not None:
        return 'corrupt_graph_weight_evidence'
    last_seen = _owned_mapping_get(data, 'last_seen')
    if last_seen is not None:
        _, reason = coerce_graph_attention_time(last_seen)
        if reason:
            return 'corrupt_graph_time_evidence'
    edge_time = _owned_mapping_get(data, 'edge_time', {})
    if edge_time is not None and no_hook_mapping_items(edge_time) is None:
        return 'corrupt_graph_time_evidence'
    if no_hook_mapping_items(edge_time) is not None:
        for value in _owned_mapping_values(edge_time):
            if value is None:
                continue
            _, reason = coerce_graph_attention_time(value)
            if reason:
                return 'corrupt_graph_time_evidence'
    weights = _owned_mapping_get(data, 'weights', {})
    if weights is not None and no_hook_mapping_items(weights) is None:
        return 'corrupt_graph_weight_evidence'
    if no_hook_mapping_items(weights) is not None:
        for value in _owned_mapping_values(weights):
            numeric, numeric_reason = graph_finite_float(value, minimum=0.0, reason='corrupt_graph_weight_evidence')
            if numeric_reason != '':
                return 'corrupt_graph_weight_evidence'
            if not math.isfinite(numeric) or numeric < 0.0:
                return 'corrupt_graph_weight_evidence'
    return ''
def compute_attention_weights(node: object) -> object:
    """Return evidence-deduplicated attention weights for one snapshot."""
    snapshot, _reason = admitted_graph_snapshot(graph_node_snapshot(node))
    if snapshot is None:
        return {}
    baseline = graph_tag_baseline_snapshot()
    weights = {}
    type_biases = {
        'call': 1.2, 'tag': 0.8, 'temporal': 1.6,
        'behavior': 1.9, 'engine': 1.7, 'engine_fingerprint': 2.0,
        'attack_phase': 2.1, 'generic': 1.0,
    }
    for record in admitted_edge_records(snapshot):
        destination = _owned_mapping_get(record, 'destination', '')
        edge_type = _owned_mapping_get(record, 'edge_type', 'generic')
        if type(destination) is not str or edge_type in GRAPH_RISK_POLICY.explanation_edge_types:
            continue
        base_w, base_reason = graph_finite_float(
            _owned_mapping_get(record, 'weight', 1.0), default=1.0, minimum=0.0,
        )
        confidence, confidence_reason = graph_finite_float(
            _owned_mapping_get(record, 'confidence', 1.0),
            default=1.0, minimum=0.0, maximum=1.0,
        )
        if base_reason != '' or confidence_reason != '':
            continue
        tag_name = str.replace(destination, 'tag:', '')
        rarity_count, rarity_reason = graph_finite_float(
            _owned_mapping_get(baseline, tag_name, 1), default=1.0, minimum=0.0,
        )
        if rarity_reason != '':
            rarity_count = 1.0
        rarity = 1.0 / (int(rarity_count) + 1)
        weights[destination] = (
            base_w * confidence * type_biases.get(edge_type, 1.0) * (1.0 + rarity)
        )
    total = sum(weights[key] for key in weights) + 1e-06
    for key in weights:
        weights[key] /= total
    return weights
def propagate_graph_attention(node: object, depth: object=2, half_life: object=GLOBAL_HALF_LIFE) -> object:
    """Read graph attention deterministically without mutating graph state."""
    if not graph_has_node(node):
        return GRAPH_ATTENTION_UNAVAILABLE_SCORE
    depth_metric, depth_reason = graph_finite_float(depth, default=1.0, minimum=1.0, maximum=8.0)
    if depth_reason != '':
        record_graph_input_degraded('graph_attention_depth_unavailable', depth_reason)
    max_depth = int(depth_metric) if depth_reason == '' else 1
    reference_now = graph_attention_reference_time(node, depth=max_depth)
    half_life_numeric, _half_life_reason = coerce_graph_attention_time(half_life)
    if half_life_numeric is None or half_life_numeric <= 0.0:
        half_life_numeric = 1e-09
    visited = {}
    stack = [(node, 0, 1.0)]
    total = 0.0
    work = 0
    while stack and work < GRAPH_RISK_POLICY.maximum_attention_work:
        n, d, belief = stack.pop()
        work += 1
        if d > max_depth:
            continue
        if n in visited and visited[n] <= d:
            continue
        visited[n] = d
        data = get_graph_node(n)
        if data is None:
            continue
        last_seen = _owned_mapping_get(data, 'last_seen')
        if last_seen is None:
            continue
        last_seen_numeric, last_seen_reason = coerce_graph_attention_time(last_seen)
        if last_seen_reason or last_seen_numeric is None:
            continue
        age = max(0.0, reference_now - last_seen_numeric)
        node_decay = math.exp(-math.log(2) * age / max(1e-09, half_life_numeric))
        attention = compute_attention_weights(n)
        raw_edges = _owned_mapping_get(data, 'edges', ())
        edges = tuple(edge for edge in raw_edges if edge in attention)
        degree = len(edges)
        local = math.log1p(degree) * belief * node_decay
        total += local / (d + 1)
        for e in sorted(edges, key=safe_graph_text):
            if not graph_has_node(e):
                continue
            w, weight_reason = attention_lookup_result(attention, e)
            if weight_reason != '':
                record_graph_input_degraded('graph_attention_weight_unavailable', weight_reason, edge=safe_graph_text(e))
                continue
            edge_time = _owned_mapping_get(_owned_mapping_get(data, 'edge_time', {}), e, reference_now)
            edge_time_numeric, edge_time_reason = coerce_graph_attention_time(edge_time)
            if edge_time_reason or edge_time_numeric is None:
                edge_time_numeric = reference_now
            edge_age = max(0.0, reference_now - edge_time_numeric)
            edge_decay = math.exp(-math.log(2) * edge_age / max(1e-09, half_life_numeric))
            combined_decay = max(node_decay, edge_decay)
            next_belief = belief * w * combined_decay * (0.7 / (d + 1))
            if next_belief < PLR2004N0_01:
                continue
            stack.append((e, d + 1, next_belief))
    bounded_total, total_reason = graph_unit_interval(total / (depth_metric * 3.0), reason='graph_attention_total_unavailable')
    if total_reason != '':
        record_graph_input_degraded('graph_attention_total_unavailable', total_reason)
    return bounded_total
def graph_attention_evidence(
    node: object,
    depth: object = 2,
    half_life: object = GLOBAL_HALF_LIFE,
) -> GraphComponentEvidence:
    """Return bounded attention with readiness, work, and provenance evidence."""
    raw_snapshot = graph_node_snapshot(node)
    snapshot, snapshot_reason = admitted_graph_snapshot(raw_snapshot)
    if snapshot is None:
        return unavailable_component(
            "attention", snapshot_reason, GRAPH_ATTENTION_CONTRACT_VERSION,
        )
    corruption_reason = graph_snapshot_corruption_reason(snapshot)
    if graph_first_reason(corruption_reason) != '':
        return unavailable_component(
            "attention", graph_first_reason(corruption_reason),
            GRAPH_ATTENTION_CONTRACT_VERSION,
        )
    value = propagate_graph_attention(node, depth=depth, half_life=half_life)
    records = tuple(
        record for record in admitted_edge_records(snapshot)
        if _owned_mapping_get(record, 'edge_type', 'generic')
        not in GRAPH_RISK_POLICY.explanation_edge_types
    )
    edge_types = sorted({
        _owned_mapping_get(record, 'edge_type', 'generic') for record in records
        if type(_owned_mapping_get(record, 'edge_type', 'generic')) is str
    })
    support = len(records)
    return GraphComponentEvidence(
        name="attention",
        value=value,
        ready=True,
        support_count=support,
        maturity=min(1.0, 0.2 + support / 16.0),
        unavailable_reason=None,
        provenance=(
            "deterministic_anchor:" + str(snapshot.get('update_ordinal', 0)),
            "edge_types:" + ",".join(edge_types),
            "work_limit:" + str(GRAPH_RISK_POLICY.maximum_attention_work),
        ),
        version=GRAPH_ATTENTION_CONTRACT_VERSION,
    )
def propagate_graph_attention_refined(node: object, depth: object=2, half_life: object=GLOBAL_HALF_LIFE) -> object:
    """Canonical graph attention propagation used by graph intelligence integration."""
    return graph_attention_evidence(node, depth=depth, half_life=half_life).value

__all__ = (
    'compute_attention_weights',
    'graph_attention_evidence',
    'graph_snapshot_corruption_reason',
    'propagate_graph_attention',
    'propagate_graph_attention_refined',
    'safe_attention_lookup',
)
