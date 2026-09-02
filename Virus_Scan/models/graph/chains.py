from __future__ import annotations

from collections.abc import Mapping

from Virus_Scan.contracts.tag_evidence import required_positive_tags_have_distinct_roots
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.detection.api.tag_evidence_contracts import (
    concrete_score_count,
    scoreable_tag_evidence,
)
from Virus_Scan.runtime.graph_state import graph_has_node, graph_node_snapshot
from Virus_Scan.models.graph.common import (
    ATTACK_GRAPH,
    graph_unit_interval,
)
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_exact_nonnegative_int,
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.chain_boundaries import (
    behavior_chain_name,
    chain_exact_text,
    chain_name,
    chain_ordered_texts,
    first_chain_config_value,
    safe_chain_weight,
    safe_graph_values,
    safe_mapping_items,
)
from Virus_Scan.models.graph.state import get_graph_node

PLR2004N1200 = 1200
_GRAPH_CHAIN_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})
CHAIN_DEPTH_DEFAULT = 1


def _bounded_chain_depth(value: object) -> int:
    """Return the canonical bounded traversal depth without caller hooks."""
    numeric, reason = no_hook_exact_nonnegative_int(
        value, default=CHAIN_DEPTH_DEFAULT, reason='graph_chain_depth_unavailable',
    )
    if reason != '':
        return CHAIN_DEPTH_DEFAULT
    return min(max(0, numeric), 2)



def propagate_behavior_chains_from_node(start_node: object, max_depth: object=4) -> object:
    """Propagate chains using immutable node evidence records only."""
    visited = set()
    stack = [(start_node, 0, (), [])]
    discovered = []
    total_score = 0.0
    scored = set()
    max_depth = _bounded_chain_depth(max_depth)
    while stack and len(visited) < PLR2004N1200:
        node, depth, accumulated_records, flow = stack.pop()
        if node in visited or depth > max_depth:
            continue
        visited.add(node)
        node_data = get_graph_node(node)
        if not isinstance(node_data, Mapping):
            node_data = {'tag_evidence_records': (), 'edges': set()}
        node_records = node_data.get('tag_evidence_records', ())
        node_evidence = TagEvidence.from_records(node_records)
        ordered_node_tags = sorted(node_evidence.tags, key=str.__str__)
        new_flow = (flow + ordered_node_tags)[-12:]
        combined_evidence = scoreable_tag_evidence(
            TagEvidence.from_records((*accumulated_records, *node_evidence.records)),
            allowed_evidence_kinds=_GRAPH_CHAIN_EVIDENCE_KINDS,
        )
        combined_tags = sorted(combined_evidence.tags, key=str.__str__)
        chain_evidence = evaluate_chain_evidence(
            tags=combined_evidence, match_modes=("anchor", "unordered"),
        )
        hits = list(chain_evidence.hits)
        sc = min(40.0, chain_evidence.total_score_points)
        if hits:
            concrete_count = concrete_score_count(combined_evidence)
            report_score = sc * (1 + min(depth, 1) * 0.2)
            discovered.append({
                'start': start_node,
                'end': node,
                'depth': depth,
                'flow': new_flow[-6:],
                'tags': combined_tags,
                'chains': hits,
                'chain_records': tuple(
                    decision.to_record() for decision in chain_evidence.decisions
                    if decision.candidate.chain_id in hits
                ),
                'score': report_score,
                'tag_evidence_summary': dict(combined_evidence.summary),
            })
            if concrete_count >= 2 and depth <= 1:
                for hit in hits:
                    key = (start_node, hit)
                    if key in scored:
                        continue
                    scored.add(key)
                    total_score += min(12.0, report_score) / (depth + 1)
        ordered_edges = chain_ordered_texts(
            safe_graph_values(node_data.get('edges', ())),
            'graph_chain_edge_unavailable',
        )[:200]
        stack.extend(
            (next_node, depth + 1, combined_evidence.records, new_flow)
            for next_node in reversed(ordered_edges)
            if graph_has_node(next_node)
        )
    return (min(40.0, total_score), discovered)


def reconstruct_attack_chain(node: object, max_depth: object=4) -> object:
    node_text, node_reason = chain_exact_text(node, 'graph_chain_node_unavailable')
    node_text = str.strip(node_text)
    if node_reason or node_text == '':
        return []
    path = []
    stack = [(node_text, 0)]
    visited = set()
    while stack:
        n, d = stack.pop()
        if n in visited or d > max_depth:
            continue
        visited.add(n)
        path.append(n)
        data = graph_node_snapshot(n)
        if not isinstance(data, Mapping):
            continue
        ordered_edges = chain_ordered_texts(safe_graph_values(data.get('edges', ())), 'graph_chain_edge_unavailable')
        stack.extend((e, d + 1) for e in reversed(ordered_edges) if graph_has_node(e))
    return path[:50]

def score_attack_chain_presence_from_edges(edges: object, attack_graph: object=None) -> object:
    """Score ATT&CK phase coverage from immutable edge evidence."""
    graph = attack_graph if attack_graph is not None else ATTACK_GRAPH
    edge_values = safe_graph_values(edges)
    graph_items = safe_mapping_items(graph)
    if not edge_values or not graph_items:
        return 0.0
    phases_detected = set()
    edge_texts = chain_ordered_texts(edge_values, 'graph_chain_edge_unavailable')
    for edge_text_raw in edge_texts:
        edge_text = str.lower(edge_text_raw)
        for phase, data in graph_items:
            nodes = safe_graph_values(first_chain_config_value(data, ('nodes',), ()))
            phase_text, phase_reason = chain_exact_text(phase, 'graph_chain_phase_unavailable')
            if phase_reason or phase_text == '':
                continue
            phase_lookup = str.lower(phase_text)
            node_texts = chain_ordered_texts(nodes, 'graph_chain_phase_node_unavailable')
            if edge_text == 'phase:' + phase_lookup or any(str.lower(node_text) in edge_text for node_text in node_texts):
                phases_detected.add(phase_text)
    return graph_unit_interval(len(phases_detected) / max(1, len(graph_items)), reason='graph_chain_phase_score_unavailable')[0]

def score_attack_chain_presence(node: object) -> object:
    """Detect progression across ATT&CK phases in graph edges without mutating graph state."""
    if not graph_has_node(node):
        return 0.0
    snapshot = graph_node_snapshot(node)
    edges = snapshot.get('edges', set()) if isinstance(snapshot, Mapping) else set()
    return score_attack_chain_presence_from_edges(edges)

__all__ = ('propagate_behavior_chains_from_node', 'reconstruct_attack_chain', 'score_attack_chain_presence', 'score_attack_chain_presence_from_edges')
