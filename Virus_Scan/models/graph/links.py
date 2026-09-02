from __future__ import annotations

from pathlib import Path
import zipfile

from Virus_Scan.contracts.telemetry import log_error, record_detector_error
from Virus_Scan.contracts.tag_evidence import TagEvidenceRecord
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.exception_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.models.api.markov_contracts import (
    canonical_behavior_flow,
    markov_transition_score,
)
from Virus_Scan.runtime.graph_state import update_graph_node_owned
from Virus_Scan.runtime.temporal_state import temporal_state_node_key
from Virus_Scan.utils.stages import normalize_stage
from Virus_Scan.utils.tagging import TAG_NORMALIZATION_FAILURE_EVIDENCE
from Virus_Scan.models.graph.common import (
    normalize_graph_tags_with_reason,
    TAG_TO_BEHAVIOR,
    safe_graph_text,
    safe_graph_text_with_reason,
    record_graph_input_degraded,
    graph_first_reason,
)
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_exact_nonnegative_int, no_hook_mapping_items
from Virus_Scan.models.graph.common_text_boundaries import graph_exception_message
from Virus_Scan.models.graph.relationships import phase_matches_from_tags
from Virus_Scan.models.graph.state import add_graph_edge, ensure_graph_node

def _graph_label(prefix: object, value: object) -> object:
    return prefix + safe_graph_text(value)

def _owned_mapping_items(value: object) -> object:
    items = no_hook_mapping_items(value)
    if items is None:
        return ()
    return items

def _graph_path_input(value: object) -> object:
    if isinstance(value, Path):
        return value, str(value), ''
    text, reason = safe_graph_text_with_reason(value, 'graph_path_unavailable')
    if reason != '':
        return None, '', reason
    try:
        return Path(text), text, ''
    except RECOVERABLE_RUNTIME_ERRORS:
        return None, '', 'graph_path_unavailable'

def _archive_member_limit(value: object) -> object:
    limit, reason = no_hook_exact_nonnegative_int(
        value,
        default=500,
        reason='archive_member_limit_rejected',
    )
    if reason != '' or limit < 1:
        return 500
    return limit

def _temporal_flow_source(raw_tags: object, graph_tags: object, tags_reason: object) -> object:
    if graph_first_reason(tags_reason) == '':
        return graph_tags
    if type(raw_tags) in (tuple, list, set, frozenset):
        return raw_tags
    return ()


def incremental_graph_update(
    node: object, tag_evidence: object=None, *,
    context: object=None, context_baseline: object=None,
) -> None:
    """Write one canonical evidence bundle into the owned graph state."""
    if type(tag_evidence) is TagEvidence:
        bundle = tag_evidence
        tags = tuple(bundle.tags)
        tags_reason = str(bundle.reasons.get('unavailable_reason', ''))
    else:
        tags_reason = 'graph_update_tag_evidence_required'
        failure_record = TagEvidenceRecord(
            canonical_tag_id=TAG_NORMALIZATION_FAILURE_EVIDENCE,
            publication_name=TAG_NORMALIZATION_FAILURE_EVIDENCE,
            evidence_id='',
            source_detector='graph_incremental_update',
            source_stage='graph_input',
            evidence_kind='failure',
            polarity='unavailable',
            scoreability_class='none',
            root_observation_id='graph_update_tag_evidence_unavailable',
            unavailable_reason=tags_reason,
            raw_observation_name=TAG_NORMALIZATION_FAILURE_EVIDENCE,
        )
        bundle = TagEvidence.from_records(
            (failure_record,), reasons={'unavailable_reason': tags_reason},
        )
        tags = tuple(bundle.tags)
    try:
        node_text, node_reason = safe_graph_text_with_reason(
            node, 'graph_update_node_unavailable',
        )
        record_graph_input_degraded(
            'graph_incremental_update_input_degraded',
            graph_first_reason(node_reason, tags_reason),
            node=node_text,
        )
        ensure_graph_node(node_text)
        stage = normalize_stage(Path(node_text).suffix.lower())
        context_items = no_hook_mapping_items(context)
        graph_context = (
            {'extension': Path(node_text).suffix.lower(), 'node_type': 'file'}
            if context_items is None else dict(context_items)
        )
        baseline_items = no_hook_mapping_items(context_baseline)
        update_graph_node_owned(
            node_text, tag_evidence_records=bundle.records,
            context=graph_context,
            context_baseline=(None if baseline_items is None else dict(baseline_items)),
            current_scan_cycle_guard='raw_graph_features_only',
        )
        add_graph_edge(
            node_text, _graph_label('stage:', stage),
            edge_type='stage', weight=1.2,
        )
        for tag in tags[:120]:
            add_graph_edge(
                node_text, _graph_label('tag:', tag),
                edge_type='tag', weight=1.0,
            )
        phase_hits = phase_matches_from_tags(tags)
        for phase, matched in _owned_mapping_items(phase_hits):
            phase_label = _graph_label('phase:', phase)
            add_graph_edge(
                node_text, phase_label, edge_type='attack_phase',
                weight=2.0 + min(3.0, len(matched)),
            )
            for tag in matched[:12]:
                add_graph_edge(
                    phase_label, _graph_label('tag:', tag),
                    edge_type='phase_tag', weight=0.6,
                )
        high_signal = [
            tag for tag in tags
            if tag in TAG_TO_BEHAVIOR or tag in {
                'lateral_movement', 'defense_evasion', 'credential_access',
                'network_download', 'network_exfiltration', 'process_injection',
                'scheduled_task', 'ransomware_behavior', 'packed_or_obfuscated',
                'collection', 'script_execution',
            }
        ][:40]
        for index, first in enumerate(high_signal[:24]):
            for second in high_signal[index + 1:index + 7]:
                add_graph_edge(
                    _graph_label('tag:', first), _graph_label('tag:', second),
                    edge_type='tag_cooccur', weight=0.2,
                )
    except RECOVERABLE_RUNTIME_ERRORS as exc:
        log_error(graph_exception_message(
            'incremental_graph_update failed: ', exc,
        ))


def link_archive_members_to_graph(path: object, max_members: object=500) -> object:
    """Add lightweight archive -> member graph edges without executing payloads."""
    linked = 0
    try:
        archive_path, archive_text, path_reason = _graph_path_input(path)
        if path_reason != '' or archive_path is None:
            return 0
        member_limit = _archive_member_limit(max_members)
        if not zipfile.is_zipfile(archive_path):
            return 0
        ensure_graph_node(archive_text)
        with zipfile.ZipFile(archive_path, 'r') as z:
            infos = z.infolist()
            for member in infos[:member_limit]:
                if member.is_dir():
                    continue
                name = member.filename
                if Path(name).is_absolute() or '..' in Path(name).parts:
                    add_graph_edge(archive_text, _graph_label('archive_blocked:', name), edge_type='archive_safety', weight=2.0)
                    continue
                child = 'archive_member:' + archive_text + ':' + safe_graph_text(name)
                ensure_graph_node(child)
                add_graph_edge(archive_text, child, edge_type='archive_member', weight=1.0)
                child_stage = normalize_stage(Path(name).suffix.lower())
                child_stage_label = _graph_label('stage:', child_stage)
                add_graph_edge(child, child_stage_label, edge_type='stage', weight=0.8)
                update_graph_node_owned(child, tags=[child_stage_label], archive_parent=archive_text, archive_member_name=name)
                linked += 1
            if len(infos) > member_limit:
                add_graph_edge(archive_text, 'archive_member_limit', edge_type='archive_safety', weight=1.5)
    except RECOVERABLE_RUNTIME_ERRORS as e:
        record_detector_error('link_archive_members_to_graph', e, context={'file': path})
    return linked

def link_tags_to_graph(node: object, tags: object) -> None:
    graph_tags, tags_reason = normalize_graph_tags_with_reason(tags, 'graph_tag_link_tags_unavailable')
    node_text, node_reason = safe_graph_text_with_reason(node, 'graph_tag_link_node_unavailable')
    record_graph_input_degraded('graph_tag_link_input_degraded', graph_first_reason(node_reason, tags_reason), node=node_text)
    for tag in graph_tags[:120]:
        add_graph_edge(node_text, _graph_label('tag:', tag), 'tag', 1.0)

def link_temporal_to_graph(node: object, prev_stage: object, tags: object, curr_stage: object) -> object:
    """Graph link for temporal transition; uses ordered behavior flow and never learns."""
    graph_tags, tags_reason = normalize_graph_tags_with_reason(tags, 'graph_temporal_link_tags_unavailable')
    node_text, node_reason = safe_graph_text_with_reason(node, 'graph_temporal_link_node_unavailable')
    temporal_reason = graph_first_reason(node_reason, tags_reason)
    record_graph_input_degraded('graph_temporal_link_input_degraded', temporal_reason, node=node_text)
    flow_source = _temporal_flow_source(tags, graph_tags, tags_reason)
    flow = canonical_behavior_flow(flow_source)
    if graph_first_reason(tags_reason) != '' and len(flow) == 0:
        return {'linked': False, 'reason': 'no_behavior_flow'}
    if len(flow) == 0:
        return {'linked': False, 'reason': 'no_behavior_flow'}
    prev_stage_text = safe_graph_text(prev_stage)
    curr_stage_text = safe_graph_text(curr_stage)
    weight = 1.0 + markov_transition_score(prev_stage_text, flow, curr_stage_text)
    transition_label = 'transition:' + prev_stage_text + '->' + curr_stage_text + ':' + '->'.join(flow[:6])
    add_graph_edge(temporal_state_node_key(node_text), transition_label, edge_type='temporal', weight=weight)
    return {'linked': True, 'weight': weight, 'flow': flow}



__all__ = ('incremental_graph_update', 'link_archive_members_to_graph', 'link_tags_to_graph', 'link_temporal_to_graph')
