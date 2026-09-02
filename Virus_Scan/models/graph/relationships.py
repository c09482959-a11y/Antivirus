from __future__ import annotations
from Virus_Scan.models.graph.common import (
    ATTACK_GRAPH,
    record_graph_input_degraded,
    graph_first_reason,
)
from Virus_Scan.contracts.tag_evidence import (
    active_tag_evidence_records,
    positive_tag_group_root_matches,
)
from Virus_Scan.models.contracts.no_hook_materialization import (
    no_hook_mapping_items,
)
from Virus_Scan.models.graph.relationship_boundaries import (
    graph_relationship_text,
    graph_relationship_sequence,
)
from Virus_Scan.models.graph import relationships_support as _relationships_support
from Virus_Scan.models.graph.chains import propagate_behavior_chains_from_node
from Virus_Scan.models.graph.features import get_graph_features
from Virus_Scan.models.graph.state import get_graph_node
def _owned_mapping_get(value: object, name: object, default: object=()) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return default
    for key, item in items:
        if type(key) is str and str.__str__(key) == name:
            return item
    return default
def _phase_match_evidence(tags: object, attack_graph: object=None) -> object:
    """Resolve graph phases and their independent contributing root groups."""
    bundle, _root_tags, tags_reason = _relationships_support._relationship_tag_evidence(tags)
    record_graph_input_degraded('graph_phase_tags_degraded', tags_reason)
    graph = attack_graph if attack_graph is not None else ATTACK_GRAPH
    graph_items = no_hook_mapping_items(graph)
    if graph_items is None:
        record_graph_input_degraded('graph_phase_attack_graph_degraded', 'non_mapping_attack_graph')
        return {}, (), bundle
    active = tuple(
        record for record in active_tag_evidence_records(bundle.records)
        if record.evidence_kind in _relationships_support._RELATIONSHIP_EVIDENCE_KINDS
        and record.polarity == 'positive'
    )
    phase_rows: list[tuple[str, tuple[str, ...], frozenset[str]]] = []
    for phase, data in graph_items:
        phase_text, phase_reason = graph_relationship_text(phase, 'graph_phase_unavailable')
        nodes, nodes_reason = graph_relationship_sequence(
            _owned_mapping_get(data, 'nodes', ()), 'graph_phase_nodes_unavailable',
        )
        record_graph_input_degraded(
            'graph_phase_nodes_degraded', graph_first_reason(phase_reason, nodes_reason),
            phase=phase_text,
        )
        matched_nodes: set[str] = set()
        matched_labels: set[str] = set()
        for node in nodes:
            node_text = str.lower(node)
            for record in active:
                labels = (record.canonical_tag_id, record.publication_name)
                if any(label == node_text or str.__contains__(label, node_text) for label in labels):
                    matched_nodes.add(node_text)
                    matched_labels.update(label for label in labels if label)
        if matched_nodes and matched_labels:
            phase_rows.append((phase_text, tuple(sorted(matched_nodes)), frozenset(matched_labels)))
    phase_rows.sort(key=lambda row: row[0])
    matches = {phase: nodes for phase, nodes, _labels in phase_rows}
    groups = tuple(labels for _phase, _nodes, labels in phase_rows)
    return matches, groups, bundle


def phase_matches_from_tags(tags: object, attack_graph: object=None) -> object:
    """Graph-owned phase resolver with deterministic matched-node evidence."""
    matches, _groups, _bundle = _phase_match_evidence(tags, attack_graph)
    return matches


def phase_hits_from_tags(tags: object) -> object:
    """Graph-owned ATT&CK phase resolver for relationship scoring."""
    matches = phase_matches_from_tags(tags)
    items = no_hook_mapping_items(matches)
    if items is None:
        return []
    return sorted(phase for phase, _matched in items if type(phase) is str)


def compute_graph_relationship_layer(node: object, tags: object=None) -> object:
    """Layer 3: read-only relationship scoring from canonical tag evidence."""
    tag_evidence, tags, graph_input_unavailable_reason = _relationships_support._normalized_relationship_inputs(tags)
    concrete_count = len({
        record.root_observation_id
        for record in active_tag_evidence_records(tag_evidence.records)
        if record.evidence_kind in _relationships_support._RELATIONSHIP_EVIDENCE_KINDS
        and record.polarity == 'positive'
    })
    metric_failures: list[str] = []
    phase_matches, phase_groups, _phase_bundle = _phase_match_evidence(tag_evidence)
    phase_hits = sorted(phase_matches)
    phase_root_count = len(positive_tag_group_root_matches(
        tag_evidence.records, phase_groups,
        allowed_evidence_kinds=_relationships_support._RELATIONSHIP_EVIDENCE_KINDS,
    ))
    graph_features, graph_unavailable_reason, node_text, feature_failures = _relationships_support._relationship_node_features(
        node, graph_input_unavailable_reason, get_graph_features
    )
    metric_failures.extend(feature_failures)
    score = 0.0
    hits: list[str] = []
    prop_hits: tuple[object, ...] = ()
    if node_text != '':
        score, hits, prop_hits, graph_features = _relationships_support._relationship_score_from_node(
            node_text, tags, phase_hits, phase_root_count, concrete_count, graph_features, metric_failures,
            get_graph_node, propagate_behavior_chains_from_node,
        )
    return _relationships_support._graph_relationship_output(
        score=score,
        hits=hits,
        phase_hits=phase_hits,
        prop_hits=prop_hits,
        graph_features=graph_features,
        graph_unavailable_reason=graph_unavailable_reason,
        metric_failures=metric_failures,
    )
__all__ = (
    'compute_graph_relationship_layer',
    'phase_hits_from_tags',
    'phase_matches_from_tags',
)
