from __future__ import annotations

import inspect

from Virus_Scan.contracts.stage_event_time import deterministic_stage_event_time
from Virus_Scan.detection.evidence.timelines.stage_event import emit_stage_event as emit_detection_stage_event
from Virus_Scan.models.graph import emit_stage_event as emit_graph_stage_event


def test_stage1149_detection_stage_event_uses_deterministic_contract_without_wall_clock():
    first = emit_detection_stage_event('sample.bin', 'asset', ['encoded_payload_candidate'])
    second = emit_detection_stage_event('sample.bin', 'asset', ['encoded_payload_candidate'])

    assert first == second
    assert first['time'] == deterministic_stage_event_time('sample.bin', first['stage'], tuple(first['tags']))
    assert first['event_time_available'] is False
    assert first['event_time_source'] == 'deterministic_content_digest'
    assert first['stage_event_publication_request']['event_time_available'] is False
    assert first['stage_event_publication_request']['event'] == {
        'time': first['time'],
        'stage': first['stage'],
        'tags': first['tags'],
    }
    assert 'time.time' not in inspect.getsource(emit_detection_stage_event)


def test_stage1149_graph_stage_event_uses_same_deterministic_time_contract():
    first = emit_graph_stage_event('graph-node', 'cs', [])
    second = emit_graph_stage_event('graph-node', 'cs', [])

    assert first == second
    assert first['time'] == deterministic_stage_event_time('graph-node', first['stage'], first['tags'])
    assert first['event_time_available'] is False
    assert first['event_time_source'] == 'deterministic_content_digest'
    assert 'time.time' not in inspect.getsource(emit_graph_stage_event)


def test_stage1149_stage_event_time_contract_changes_with_material_inputs():
    base = deterministic_stage_event_time('a.bin', 'asset', ('tag-a',))
    changed_file = deterministic_stage_event_time('b.bin', 'asset', ('tag-a',))
    changed_stage = deterministic_stage_event_time('a.bin', 'cs', ('tag-a',))
    changed_tags = deterministic_stage_event_time('a.bin', 'asset', ('tag-b',))

    assert 0.0 <= base < 1.0
    assert len({base, changed_file, changed_stage, changed_tags}) == 4
