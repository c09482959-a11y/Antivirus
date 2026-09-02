from __future__ import annotations

from pathlib import Path

from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.tag_evidence import distinct_root_tag_evidence_records
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.detection.api.tag_evidence_contracts import scoreable_tag_evidence
from Virus_Scan.utils.tagging import ordered_unique_tags
from Virus_Scan.models.graph.common import (
    ANALYTICAL_EVIDENCE_SCHEMA_VERSION,
    CAUSAL_ENTITY_MODEL_VERSION,
    coerce_graph_event_time,
    graph_event_time_failure_reason,
    graph_first_reason,
    graph_flag_enabled,
    graph_finite_float,
    graph_unit_interval,
)
from Virus_Scan.models.graph.evidence_boundaries import (
    graph_evidence_entities,
    graph_evidence_entity_field,
    graph_evidence_mapping,
    graph_evidence_mapping_get,
    graph_evidence_metadata_value,
    graph_evidence_sequence,
    graph_evidence_text,
    graph_evidence_unique_entity_sort_key,
)

PLR2004N2 = 2

_GRAPH_CONSUMED_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def _graph_tag_evidence(tags: object, *, reason: str) -> tuple[TagEvidence, str]:
    if type(tags) is TagEvidence:
        raw_tags = tags
        tag_reason = ''
    else:
        raw_tags, tag_reason = graph_evidence_sequence(tags, reason)
    try:
        bundle = scoreable_tag_evidence(
            raw_tags if not tag_reason else (),
            allowed_evidence_kinds=_GRAPH_CONSUMED_EVIDENCE_KINDS,
        )
    except RECOVERABLE_RUNTIME_ERRORS:
        return TagEvidence(reasons={'unavailable_reason': 'graph_tag_evidence_failed'}), (
            tag_reason or 'graph_tag_evidence_failed'
        )
    if not bundle.records and bundle.reasons.get('unavailable_reason'):
        tag_reason = tag_reason or str(bundle.reasons.get('unavailable_reason'))
    return bundle, tag_reason


def _graph_root_records(bundle: TagEvidence) -> tuple[object, ...]:
    return distinct_root_tag_evidence_records(
        bundle.records, allowed_evidence_kinds=_GRAPH_CONSUMED_EVIDENCE_KINDS,
    )


def infer_behavioral_entities(path: object=None, tags: object=None, metadata: object=None) -> object:
    """Graph-owned deterministic entity projection for causal lineage evidence."""
    entities = []
    unavailable_reasons = []
    tag_evidence, tag_reason = _graph_tag_evidence(tags, reason='unreadable_graph_tags')
    if tag_reason:
        unavailable_reasons.append(tag_reason)
    root_records = _graph_root_records(tag_evidence)
    path_text, path_reason = graph_evidence_text(path, 'unreadable_graph_path')
    if path is None:
        path_text = ''
        path_reason = ''
    if path_reason:
        unavailable_reasons.append(path_reason)
    if path_text:
        suffix = Path(path_text).suffix.lower() or '<noext>'
        entities.append({'kind': 'file', 'id': path_text, 'label': Path(path_text).name or path_text})
        entities.append({'kind': 'file_extension', 'id': suffix, 'label': suffix})
    engine, metadata_reason = graph_evidence_metadata_value(metadata, 'engine', 'engine_hint')
    if metadata_reason:
        unavailable_reasons.append(metadata_reason)
    engine = engine.strip().lower()
    if engine:
        entities.append({'kind': 'engine', 'id': engine, 'label': engine})
    for record in root_records[:24]:
        tag_text, tag_text_reason = graph_evidence_text(
            record.canonical_tag_id, 'unreadable_graph_tag',
        )
        if tag_text_reason:
            unavailable_reasons.append(tag_text_reason)
        entities.append({
            'kind': 'behavior_tag',
            'id': tag_text,
            'label': tag_text,
            'evidence_id': record.evidence_id,
            'root_observation_id': record.root_observation_id,
            'evidence_kind': record.evidence_kind,
            'correlation_group': record.correlation_group,
            'behavior_bucket': record.behavior_bucket,
        })
    for index, reason in enumerate(ordered_unique_tags(unavailable_reasons)):
        entities.append({
            'kind': 'graph_input_unavailable',
            'id': reason,
            'label': reason,
            'degraded': True,
            'unavailable_reason': reason,
            'final_json_must_record': True,
            'replay_record_required': True,
            'order': index,
        })
    unique = {}
    for entity in entities:
        key = (entity.get('kind'), entity.get('id'))
        unique.setdefault(key, entity)
    return tuple(unique[key] for key in sorted(unique, key=graph_evidence_unique_entity_sort_key))

def _graph_unavailable_transition_edge(reason: object) -> object:
    reason_text = graph_first_reason(reason, default='graph_transition_edge_unavailable')
    return {
        'src': 'graph_input_unavailable',
        'dst': 'graph_input_unavailable',
        'src_kind': 'graph_input_unavailable',
        'dst_kind': 'graph_input_unavailable',
        'relation': 'unavailable_transition',
        'confidence': 0.0,
        'degraded': True,
        'relation_unavailable_reason': reason_text,
        'final_json_must_record': True,
        'replay_record_required': True,
    }

def infer_causal_transition_edges(path: object=None, tags: object=None, entities: object=None, event_times: object=None) -> object:
    """Graph-owned deterministic transition-edge projection from immutable entity records."""
    del path  # Explicitly unused contract parameters.
    entity_list, entity_reason = graph_evidence_entities(entities, 'unreadable_graph_transition_entities')
    if entity_reason:
        return (_graph_unavailable_transition_edge(entity_reason),)
    if len(entity_list) < 2:
        return ()
    tag_evidence, tag_reason = _graph_tag_evidence(
        tags, reason='unreadable_graph_transition_tags',
    )
    root_records = _graph_root_records(tag_evidence)
    times, times_reason = graph_evidence_mapping(event_times, 'unreadable_graph_event_times')
    confidence_base = graph_unit_interval(
        0.35 + min(0.4, len(root_records) / 20.0),
        reason='graph_transition_confidence_unavailable',
    )[0]
    edges = []
    for left, right in zip(entity_list, entity_list[1:], strict=False):
        left_id, left_id_reason = graph_evidence_entity_field(left, 'id', '', 'unreadable_graph_transition_entity')
        right_id, right_id_reason = graph_evidence_entity_field(right, 'id', '', 'unreadable_graph_transition_entity')
        left_kind, left_kind_reason = graph_evidence_entity_field(left, 'kind', 'unknown', 'unreadable_graph_transition_entity')
        right_kind, right_kind_reason = graph_evidence_entity_field(right, 'kind', 'unknown', 'unreadable_graph_transition_entity')
        left_time = graph_evidence_mapping_get(times, left_id)
        right_time = graph_evidence_mapping_get(times, right_id)
        time_failures = [
            field_reason
            for field_reason in (tag_reason, times_reason, left_id_reason, right_id_reason, left_kind_reason, right_kind_reason)
            if field_reason
        ]
        left_numeric = None
        right_numeric = None
        if left_time is not None:
            left_numeric, left_reason = coerce_graph_event_time(left_time)
            if left_reason:
                time_failures.append(left_reason)
        if right_time is not None:
            right_numeric, right_reason = coerce_graph_event_time(right_time)
            if right_reason:
                time_failures.append(right_reason)
        if time_failures:
            relation = 'co_observed_transition'
        elif left_time is not None and right_time is not None and left_numeric is not None and right_numeric is not None:
            relation = 'ordered_transition' if left_numeric <= right_numeric else 'reverse_timestamp_order'
        else:
            relation = 'co_observed_transition'
        edge = {
            'src': left_id,
            'dst': right_id,
            'src_kind': left_kind,
            'dst_kind': right_kind,
            'relation': relation,
            'confidence': round(confidence_base, 6),
        }
        if time_failures:
            edge['degraded'] = True
            edge['relation_unavailable_reason'] = graph_first_reason(graph_event_time_failure_reason(time_failures), ordered_unique_tags(time_failures)[0])
            edge['invalid_event_time_count'] = len(time_failures)
            edge['final_json_must_record'] = True
            edge['replay_record_required'] = True
        edges.append(edge)
    return tuple(edges)

def causal_entity_lineage_overlay(path: object=None, tags: object=None, event_times: object=None, metadata: object=None) -> object:
    """Add entity continuity and directed edge metadata for causal reasoning."""
    entities = infer_behavioral_entities(path=path, tags=tags, metadata=metadata)
    if type(tags) is TagEvidence:
        graph_tags = tags
        tag_reason = ''
    else:
        graph_tags, tag_reason = graph_evidence_sequence(tags, 'unreadable_graph_tags')
    try:
        edges = infer_causal_transition_edges(path=path, tags=graph_tags, entities=entities, event_times=event_times)
    except RECOVERABLE_RUNTIME_ERRORS:
        edges = ()
        tag_reason = graph_first_reason(tag_reason, default='graph_transition_edge_projection_failed')
    confidence = graph_unit_interval(sum((graph_finite_float(graph_evidence_mapping_get(e, 'confidence', 0.0))[0] for e in edges)) / max(1, len(edges)), reason='graph_lineage_confidence_unavailable')[0] if edges else 0.0
    invalid_reasons = tuple(reason for reason in (graph_first_reason(graph_evidence_mapping_get(edge, 'relation_unavailable_reason')) for edge in edges) if reason != '')
    invalid_count = sum(int(graph_finite_float(graph_evidence_mapping_get(edge, 'invalid_event_time_count', 0), minimum=0.0)[0]) for edge in edges)
    unavailable_reasons = [graph_first_reason(graph_evidence_mapping_get(entity, 'unavailable_reason')) for entity in entities if graph_evidence_mapping_get(entity, 'kind') == 'graph_input_unavailable']
    unavailable_reasons.extend(
        graph_first_reason(graph_evidence_mapping_get(edge, 'relation_unavailable_reason'))
        for edge in edges
        if graph_flag_enabled(graph_evidence_mapping_get(edge, 'degraded'))
        and graph_first_reason(graph_evidence_mapping_get(edge, 'relation_unavailable_reason')) not in {'', 'non_numeric_event_time', 'non_finite_event_time'}
    )
    tag_reason_text = graph_first_reason(tag_reason)
    if tag_reason_text != '': unavailable_reasons.append(tag_reason_text)
    degraded = len([reason for reason in unavailable_reasons if graph_first_reason(reason) != '']) > 0
    concrete_entities = tuple(entity for entity in entities if graph_evidence_mapping_get(entity, 'kind') != 'graph_input_unavailable')
    tag_evidence, _tag_evidence_reason = _graph_tag_evidence(
        tags, reason='unreadable_graph_tags',
    )
    evidence = {'schema_version': ANALYTICAL_EVIDENCE_SCHEMA_VERSION, 'version': CAUSAL_ENTITY_MODEL_VERSION, 'evidence_type': 'causal_entity_lineage', 'ready': bool(concrete_entities) and not degraded, 'entity_continuity_present': bool(len(concrete_entities) >= PLR2004N2), 'directed_edges_present': bool(edges), 'entities': entities[:50], 'transition_edges': edges[:50], 'confidence': round(confidence, 6), 'causality_note': 'candidate_entity_lineage_not_full_bayesian_causal_network', 'tag_evidence_summary': dict(tag_evidence.summary), 'tag_evidence_kinds_consumed': tuple(sorted(_GRAPH_CONSUMED_EVIDENCE_KINDS))}
    if degraded:
        reason = ordered_unique_tags(unavailable_reasons)[0]
        evidence['degraded'] = True
        evidence['unavailable_reason'] = reason
        evidence['graph_unavailable_reason'] = reason
        evidence['final_json_must_record'] = True
        evidence['replay_record_required'] = True
    if invalid_reasons:
        evidence['event_time_unavailable_reason'] = graph_event_time_failure_reason(invalid_reasons)
        evidence['invalid_event_time_count'] = invalid_count
    return evidence

__all__ = ('causal_entity_lineage_overlay', 'infer_behavioral_entities', 'infer_causal_transition_edges')
