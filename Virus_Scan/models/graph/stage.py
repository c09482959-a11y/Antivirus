from __future__ import annotations

from Virus_Scan.contracts.stage_event_time import deterministic_stage_event_time
from Virus_Scan.utils.stages import normalize_stage
from Virus_Scan.models.graph.common import (
    normalize_graph_tags_with_reason,
    graph_first_reason,
)
def emit_stage_event(file: object, stage: object, tags: object) -> object:
    """Graph-owned stage event recorder for scan_cs without detection-layer cycle."""
    normalized_tags, tags_reason = normalize_graph_tags_with_reason(tags, 'graph_stage_event_tags_unavailable')
    canonical_stage = normalize_stage(stage)
    event = {
        'time': deterministic_stage_event_time(file, canonical_stage, normalized_tags),
        'stage': canonical_stage,
        'tags': normalized_tags,
        'event_time_available': False,
        'event_time_source': 'deterministic_content_digest',
    }
    if graph_first_reason(tags_reason) != '':
        event.update({
            'degraded': True,
            'graph_unavailable_reason': graph_first_reason(tags_reason),
            'final_json_must_record': True,
            'replay_record_required': True,
        })
    return event

__all__ = ('emit_stage_event',)
