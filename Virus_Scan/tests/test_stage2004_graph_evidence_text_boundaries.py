from __future__ import annotations

from collections.abc import Mapping
import json

from Virus_Scan.models import graph


class HostileGraphEvidenceValue:
    touched = 0

    def __bool__(self):
        type(self).touched += 1
        raise RuntimeError('bool hook must not run')

    def __str__(self):
        type(self).touched += 1
        raise RuntimeError('str hook must not run')

    def __repr__(self):
        type(self).touched += 1
        raise RuntimeError('repr hook must not run')

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError('iter hook must not run')

    def __format__(self, spec):
        type(self).touched += 1
        raise RuntimeError('format hook must not run')


class HostileGraphMapping(Mapping):
    touched = 0

    def __iter__(self):
        type(self).touched += 1
        raise RuntimeError('iter hook must not run')

    def __len__(self):
        type(self).touched += 1
        raise RuntimeError('len hook must not run')

    def __getitem__(self, key):
        type(self).touched += 1
        raise RuntimeError('getitem hook must not run')

    def get(self, key, default=None):
        type(self).touched += 1
        raise RuntimeError('get hook must not run')

    def items(self):
        type(self).touched += 1
        raise RuntimeError('items hook must not run')


def test_stage2004_graph_behavioral_entities_reject_sequence_text_and_metadata_hooks() -> None:
    hostile = HostileGraphEvidenceValue()
    hostile_mapping = HostileGraphMapping()
    HostileGraphEvidenceValue.touched = 0
    HostileGraphMapping.touched = 0

    entities = graph.infer_behavioral_entities(
        path=hostile,
        tags=['network_activity', hostile],
        metadata=hostile_mapping,
    )

    assert HostileGraphEvidenceValue.touched == 0
    assert HostileGraphMapping.touched == 0
    unavailable = [entity for entity in entities if entity['kind'] == 'graph_input_unavailable']
    reasons = {entity['unavailable_reason'] for entity in unavailable}
    assert 'unreadable_graph_path' in reasons
    assert 'unreadable_graph_tags' in reasons
    assert 'unreadable_graph_metadata' in reasons
    assert all(entity['final_json_must_record'] is True for entity in unavailable)
    json.dumps(entities, sort_keys=True)


def test_stage2004_graph_transition_edges_reject_event_time_mapping_and_entity_hooks() -> None:
    hostile = HostileGraphEvidenceValue()
    hostile_mapping = HostileGraphMapping()
    HostileGraphEvidenceValue.touched = 0
    HostileGraphMapping.touched = 0

    edges = graph.infer_causal_transition_edges(
        tags=['execution', hostile],
        entities=({'kind': 'file', 'id': 'sample.exe'}, hostile, {'kind': hostile, 'id': 'right'}),
        event_times=hostile_mapping,
    )

    assert HostileGraphEvidenceValue.touched == 0
    assert HostileGraphMapping.touched == 0
    assert edges
    assert any(edge.get('degraded') is True for edge in edges)
    reasons = {edge.get('relation_unavailable_reason') for edge in edges if edge.get('degraded') is True}
    assert reasons & {'unreadable_graph_transition_tags', 'unreadable_graph_event_times', 'unreadable_graph_transition_entity'}
    assert all(edge.get('final_json_must_record') is True for edge in edges if edge.get('degraded') is True)
    json.dumps(edges, sort_keys=True)


def test_stage2004_graph_lineage_overlay_keeps_degraded_evidence_without_hooks() -> None:
    hostile = HostileGraphEvidenceValue()
    hostile_mapping = HostileGraphMapping()
    HostileGraphEvidenceValue.touched = 0
    HostileGraphMapping.touched = 0

    evidence = graph.causal_entity_lineage_overlay(
        path='sample.exe',
        tags=[hostile, 'credential_access'],
        event_times=hostile_mapping,
        metadata={'engine': hostile},
    )

    assert HostileGraphEvidenceValue.touched == 0
    assert HostileGraphMapping.touched == 0
    assert evidence['ready'] is False
    assert evidence['degraded'] is True
    assert evidence['final_json_must_record'] is True
    assert evidence['replay_record_required'] is True
    assert evidence['graph_unavailable_reason'] in {
        'unreadable_graph_tags',
        'unreadable_graph_metadata_value',
        'unreadable_graph_event_times',
    }
    json.dumps(evidence, sort_keys=True)
