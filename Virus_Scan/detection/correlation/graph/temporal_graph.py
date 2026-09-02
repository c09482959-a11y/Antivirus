"""Canonical detection temporal/graph reconciliation ownership."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath

from Virus_Scan.contracts.tag_evidence import (
    distinct_root_tag_evidence_records,
    positive_tag_group_root_matches,
)
from Virus_Scan.contracts.no_hook_materialization import (
    exact_int_or_none,
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_materialize,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.detection.correlation.multi_signal.model_context import detection_behavior_flow_from_sources
from Virus_Scan.detection.contracts.error_contracts import TAG_SCAN_RECOVERABLE_EXCEPTIONS
from Virus_Scan.detection.evidence.failure_evidence import failure_evidence_payload, recoverable_failure_evidence
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.scoring.weighting.scoreable_tags import scoreable_tag_evidence
from Virus_Scan.detection.scoring.weighting.stage_enrichment import staged_enrichment_score
from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.detection.correlation.multi_signal.model_projections import (
    detection_markov_features,
    detection_temporal_history_timeline,
    detection_temporal_snapshot,
    detection_temporal_validation,
)
from Virus_Scan.contracts.graph_event_time import (
    coerce_graph_event_time,
    graph_event_time_failure_reason,
)
from Virus_Scan.utils.stages import normalize_stage

_STDLIB_PATH_TYPES = (PurePosixPath, PureWindowsPath, PosixPath, WindowsPath)


@dataclass(frozen=True, slots=True)
class StageTimelineInputRequest:
    node: object
    tags: object
    curr_stage: object
    prev_stage: object
    ordered_events: object
    behavior_flow: object
    engine: object


_TEMPORAL_TAG_EVIDENCE_KINDS = frozenset({
    'observed', 'normalized', 'derived', 'composite',
})


def _temporal_tag_evidence(value: object) -> TagEvidence:
    """Return the single canonical evidence bundle for temporal/graph use."""
    return scoreable_tag_evidence(
        value, allowed_evidence_kinds=_TEMPORAL_TAG_EVIDENCE_KINDS,
    )


def _temporal_root_tags(bundle: TagEvidence) -> tuple[str, ...]:
    """Return one canonical observed semantic label per evidence root."""
    records = distinct_root_tag_evidence_records(
        bundle.records, allowed_evidence_kinds=_TEMPORAL_TAG_EVIDENCE_KINDS,
    )
    return tuple(
        record.canonical_tag_id for record in records
        if record.polarity == 'positive' and record.canonical_tag_id
    )


def _record_failure(failures: list, stage_name: str, error: BaseException | str, node: object) -> dict:
    failure = recoverable_failure_evidence(
        stage_name=stage_name,
        error=error,
        error_source='detection.correlation.graph.temporal_graph',
        affected_context=node,
    )
    failures.append(failure)
    return failure.to_record()


def _temporal_graph_text(
    value: object,
    *,
    default_text: str = '',
    missing_reason: str = 'missing_temporal_graph_text',
    unsupported_reason: str = 'unsafe_temporal_graph_text_rejected',
) -> tuple[str, str]:
    if type(value) in _STDLIB_PATH_TYPES:
        return PurePath.as_posix(value), ''
    replacement_text, _replacement_reason = no_hook_text(
        default_text,
        missing_reason='missing_temporal_graph_default_text',
        unsupported_reason='unsafe_temporal_graph_default_text_rejected',
    )
    text, reason = no_hook_text(value, missing_reason=missing_reason, unsupported_reason=unsupported_reason)
    if reason:
        return str.strip(replacement_text), reason
    text = str.strip(text)
    return (text if text != '' else str.strip(replacement_text)), ''


def _temporal_graph_text_sequence(value: object, *, unsupported_reason: str) -> tuple[str, ...]:
    texts: list[str] = []
    for item in no_hook_sequence_items(value):
        text, reason = _temporal_graph_text(
            item,
            unsupported_reason=unsupported_reason,
        )
        if reason or text == '':
            continue
        texts.append(text)
    return tuple(texts)


def _temporal_stage_hit_label(hit: str) -> str:
    return 'stage:' + str.__str__(hit)


def _temporal_graph_confidence(value: object) -> float:
    confidence, _reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason='unsafe_temporal_graph_confidence_rejected',
        non_finite_reason='non_finite_temporal_graph_confidence',
    )
    return round(confidence, 6)


def _temporal_graph_mapping(value: object) -> dict[object, object] | None:
    items = no_hook_mapping_items(value)
    if items is None:
        return None
    return dict(items)


def _temporal_graph_event_times(value: object) -> tuple[dict[str, object], str]:
    if value is None:
        return {}, ""
    items = no_hook_mapping_items(value)
    if items is None:
        return {}, "unreadable_graph_event_times"
    out: dict[str, object] = {}
    for key, item in items[:128]:
        key_text, key_reason = _temporal_graph_text(key, default_text="")
        if key_reason or key_text == "":
            return out, "unreadable_graph_event_times"
        out[key_text] = item
    return out, ""


def _temporal_graph_edge_time(
    event_times: dict[str, object],
    entity_id: object,
) -> tuple[float | None, str]:
    raw_time = dict.get(event_times, entity_id)
    if raw_time is None:
        return None, ""
    timestamp, reason = coerce_graph_event_time(raw_time)
    if reason:
        return None, str(reason)
    return timestamp, ""


def _temporal_graph_time_reason(reasons: object) -> str:
    reason = graph_event_time_failure_reason(reasons)
    if type(reason) is str and reason:
        return reason
    for item in no_hook_sequence_items(reasons):
        if type(item) is str and item:
            return str.__str__(item)
    return ""


def _temporal_graph_float(value: object, *, default: float = 0.0, minimum: float | None = None, maximum: float | None = None) -> float:
    metric, _reason = no_hook_finite_float(
        value,
        default=default,
        minimum=minimum,
        maximum=maximum,
        reason='unsafe_temporal_graph_numeric_rejected',
        non_finite_reason='non_finite_temporal_graph_number',
    )
    return metric


def _temporal_graph_int(value: object, *, default: int = 0) -> int:
    exact = exact_int_or_none(value)
    if exact is not None:
        return exact
    metric, reason = no_hook_finite_float(
        value,
        default=default,
        reason='unsafe_temporal_graph_integer_rejected',
        non_finite_reason='non_finite_temporal_graph_integer',
    )
    if reason:
        return default
    return int(metric)


def _materialize_temporal_validation(validation: object) -> dict[str, object]:
    """Detach the canonical v5 temporal record without recomputing its facts."""
    validation_mapping = _temporal_graph_mapping(validation)
    if validation_mapping is None:
        return {
            "score": 0.0,
            "hits": ["temporal_validation_invalid_model_output"],
            "ready": False,
            "degraded": True,
            "unavailable_reason": "invalid_temporal_validation_output",
            "evidence_type": "temporal_validation",
        }
    materialized = no_hook_materialize(
        validation_mapping, reason_prefix="temporal_validation",
    )
    if type(materialized) is not dict:
        return {
            "score": 0.0,
            "hits": ["temporal_validation_invalid_model_output"],
            "ready": False,
            "degraded": True,
            "unavailable_reason": "invalid_temporal_validation_output",
            "evidence_type": "temporal_validation",
        }
    materialized["score"] = _temporal_graph_float(
        dict.get(materialized, "score", 0.0),
        default=0.0, minimum=0.0, maximum=18.0,
    )
    materialized["hits"] = list(tuple(sorted(set(
        _temporal_graph_text_sequence(
            dict.get(materialized, "hits"),
            unsupported_reason="unsafe_temporal_validation_hit_rejected",
        )
    ))))
    materialized["chain_score_contribution"] = 0.0
    return materialized



def _stage_timeline_input_state(request: StageTimelineInputRequest) -> dict[str, object]:
    """Materialize one canonical tag bundle and validate timeline inputs."""
    node = request.node
    curr_stage = request.curr_stage
    prev_stage = request.prev_stage
    engine, engine_reason = _temporal_graph_text(
        request.engine, default_text="other",
        missing_reason="stage_timeline_engine_missing",
        unsupported_reason="stage_timeline_engine_rejected",
    )
    if engine_reason or engine == "":
        engine = "other"
    failures: list[object] = []
    tag_evidence = _temporal_tag_evidence(request.tags)
    raw_tags_for_flow = _temporal_root_tags(tag_evidence)
    if int(tag_evidence.summary.get('failure_count', 0)) > 0:
        _record_failure(
            failures, 'stage_timeline_layer_tag_boundary',
            'stage_timeline_tag_evidence_unavailable', node,
        )
    ordered_events = no_hook_sequence_items(request.ordered_events)
    behavior_flow_input = _temporal_graph_text_sequence(
        request.behavior_flow,
        unsupported_reason='unsafe_stage_timeline_behavior_rejected',
    )
    behavior_flow = detection_behavior_flow_from_sources(
        raw_tags=tag_evidence,
        ordered_events=ordered_events,
        behavior_flow=behavior_flow_input,
    )
    node_text, node_reason = _temporal_graph_text(
        node,
        missing_reason='stage_timeline_node_missing',
        unsupported_reason='stage_timeline_node_rejected',
    )
    model_node = node if node_text != '' and node_reason == '' else None
    if node is not None and node_reason:
        _record_failure(failures, 'stage_timeline_layer_node_boundary', node_reason, node)
    if curr_stage is None:
        curr_stage = normalize_stage(Path(node_text).suffix.lower()) if node_text else normalize_stage('')
    else:
        curr_stage, _curr_reason = _temporal_graph_text(curr_stage, default_text=normalize_stage(''))
        curr_stage = normalize_stage(curr_stage)
    if prev_stage is None:
        prev_stage = 'unknown'
    else:
        prev_stage, _prev_reason = _temporal_graph_text(prev_stage, default_text='unknown')
        prev_stage = prev_stage or 'unknown'
    return {
        'failures': failures,
        'raw_tags_for_flow': raw_tags_for_flow,
        'tag_evidence': tag_evidence,
        'ordered_events': ordered_events,
        'behavior_flow': behavior_flow,
        'model_node': model_node,
        'curr_stage': curr_stage,
        'prev_stage': prev_stage,
        'engine': engine,
    }


def _stage_timeline_result_record(
    score: object,
    curr_stage: object,
    prev_stage: object,
    timeline: object,
    temporal: object,
    markov: object,
    temporal_validation: object,
    hits: object,
    failures: object,
) -> dict[str, object]:
    """Build the public stage-timeline layer record with failure evidence."""
    failure_payload = failure_evidence_payload(tuple(failures))
    return {
        'name': 'Layer 2 Stage Score',
        'score': min(100.0, score),
        'stage': curr_stage,
        'previous_stage': prev_stage,
        'timeline': timeline,
        'temporal': temporal,
        'markov': markov,
        'temporal_validation': temporal_validation,
        'hits': sorted(set(hits)),
        'summary': 'behavior timeline',
        'degraded': failure_payload['degraded'],
        'failure_evidence': failure_payload['failures'],
        'confidence_degraded': failure_payload['confidence_degraded'],
        'json_record_required': failure_payload['json_record_required'],
        'replay_record_required': failure_payload['replay_record_required'],
    }

def compute_stage_timeline_layer(
    node: object, tags: object, *, chain_evidence: ChainEvidence, curr_stage: object = None,
    prev_stage: object = None, ordered_events: object = None,
    behavior_flow: object = None, engine: object = "other",
) -> object:
    """Layer 2: stage/timeline behavior using JSON/replay-visible failure evidence."""
    state = _stage_timeline_input_state(
        StageTimelineInputRequest(
            node=node,
            tags=tags,
            curr_stage=curr_stage,
            prev_stage=prev_stage,
            ordered_events=ordered_events,
            behavior_flow=behavior_flow,
            engine=engine,
        )
    )
    failures = state['failures']
    raw_tags_for_flow = state['raw_tags_for_flow']
    tag_evidence = state['tag_evidence']
    ordered_events = state['ordered_events']
    behavior_flow = state['behavior_flow']
    model_node = state['model_node']
    curr_stage = state['curr_stage']
    prev_stage = state['prev_stage']
    engine = state['engine']
    hits = []
    score = 0.0

    try:
        if type(chain_evidence) is not ChainEvidence:
            raise TypeError("stage_timeline_chain_evidence_required")
        stage_score, stage_hits = staged_enrichment_score(
            tag_evidence, chain_evidence, curr_stage,
        )
        score += min(45.0, _temporal_graph_float(stage_score, default=0.0))
        hits.extend(_temporal_stage_hit_label(h) for h in _temporal_graph_text_sequence(stage_hits[:12], unsupported_reason='unsafe_stage_hit_rejected'))
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        hits.append('stage_layer_failure_evidence_recorded')
        _record_failure(failures, 'stage_timeline_layer_stage_enrichment', error, node)

    try:
        if model_node is None:
            temporal = {'belief': 0.0, 'ready': False, 'reason': 'missing_or_rejected_node_for_temporal_snapshot'}
        else:
            temporal = detection_temporal_snapshot(model_node, ordered_events=ordered_events, behavior_timeline=None)
        temporal_mapping = _temporal_graph_mapping(temporal)
        temporal_bonus = min(20.0, _temporal_graph_float(dict.get(temporal_mapping or {}, 'belief', 0.0), default=0.0) * 20.0)
        score += temporal_bonus
        if temporal_bonus >= 5.0:
            hits.append('temporal_behavior_drift')
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        record = _record_failure(failures, 'stage_timeline_layer_temporal_snapshot', error, node)
        temporal = {'belief': 0.0, 'degraded': True, 'failure_evidence': [record]}
        hits.append('temporal_snapshot_failure_evidence_recorded')

    try:
        markov = detection_markov_features(prev_stage, behavior_flow or ordered_events, curr_stage)
        markov_mapping = _temporal_graph_mapping(markov) or {}
        markov_bonus = min(25.0, _temporal_graph_float(dict.get(markov_mapping, 'transition', 0.0), default=0.0) * 8.0 + _temporal_graph_float(dict.get(markov_mapping, 'rarity', 0.0), default=0.0) * 8.0 + _temporal_graph_float(dict.get(markov_mapping, 'pair_anomaly', 0.0), default=0.0) * 8.0)
        score += markov_bonus
        if markov_bonus >= 5.0:
            hits.append('stage_transition_or_tag_rarity')
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        record = _record_failure(failures, 'stage_timeline_layer_markov_features', error, node)
        markov = {'transition': 0.0, 'rarity': 0.0, 'pair_anomaly': 0.0, 'degraded': True, 'failure_evidence': [record]}
        hits.append('markov_feature_failure_evidence_recorded')

    try:
        temporal_validation = _materialize_temporal_validation(
            detection_temporal_validation(
                model_node, tags=behavior_flow or tag_evidence,
                prev_stage=prev_stage, curr_stage=curr_stage, markov=markov,
                ordered_events=ordered_events, engine=engine,
            )
        )
        score += _temporal_graph_float(dict.get(temporal_validation, 'score', 0.0), default=0.0)
        hits.extend(tuple(dict.get(temporal_validation, 'hits', ()))[:12])
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        record = _record_failure(failures, 'stage_timeline_layer_temporal_validation', error, node)
        temporal_validation = {'score': 0.0, 'hits': ['temporal_validation_failure_evidence_recorded'], 'degraded': True, 'failure_evidence': [record], 'ready': False, 'unavailable_reason': 'temporal_validation_failed'}
        hits.append('temporal_validation_failure_evidence_recorded')

    try:
        timeline = detection_temporal_history_timeline(model_node, ordered_events=ordered_events)[-10:] if model_node is not None else []
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        record = _record_failure(failures, 'stage_timeline_layer_history_timeline', error, node)
        timeline = [{'stage': 'failure_evidence_recorded', 'tags': ['temporal_history_failure'], 'failure_evidence': [record]}]
        hits.append('temporal_history_failure_evidence_recorded')

    result = _stage_timeline_result_record(
        score,
        curr_stage,
        prev_stage,
        timeline,
        temporal,
        markov,
        temporal_validation,
        hits,
        failures,
    )
    result['tag_evidence_summary'] = dict(tag_evidence.summary)
    result['tag_evidence_kinds_consumed'] = tuple(sorted(_TEMPORAL_TAG_EVIDENCE_KINDS))
    return result

def infer_causal_transition_edges(path: object=None, tags: object=None, entities: object=None, event_times: object=None) -> object:
    """Create deterministic causal candidates proven by distinct tag roots."""
    tag_evidence = _temporal_tag_evidence(tags)
    by_type: dict[str, dict[str, str]] = {}
    for entity in no_hook_sequence_items(entities):
        mapping = _temporal_graph_mapping(entity)
        if mapping is None:
            continue
        entity_type, type_reason = _temporal_graph_text(dict.get(mapping, 'entity_type'))
        entity_id, id_reason = _temporal_graph_text(dict.get(mapping, 'entity_id'))
        if type_reason or id_reason or entity_type == '' or entity_id == '':
            continue
        by_type[entity_type] = {'entity_id': entity_id}
    edges: list[dict[str, object]] = []
    event_time_map, event_time_reason = _temporal_graph_event_times(event_times)

    def add(
        src_type: str,
        dst_type: str,
        reason: str,
        confidence: float,
        groups: tuple[frozenset[str], frozenset[str]],
    ) -> None:
        root_matches = positive_tag_group_root_matches(
            tag_evidence.records,
            groups,
            allowed_evidence_kinds=_TEMPORAL_TAG_EVIDENCE_KINDS,
        )
        if len(root_matches) != len(groups):
            return
        src = dict.get(by_type, src_type) or dict.get(by_type, 'file')
        dst = dict.get(by_type, dst_type) or dict.get(by_type, 'file')
        if src is None or dst is None or dict.get(src, 'entity_id') == dict.get(dst, 'entity_id'):
            return
        src_time, src_time_reason = _temporal_graph_edge_time(event_time_map, dict.get(src, 'entity_id'))
        dst_time, dst_time_reason = _temporal_graph_edge_time(event_time_map, dict.get(dst, 'entity_id'))
        time_failures = tuple(
            item for item in (event_time_reason, src_time_reason, dst_time_reason) if item
        )
        ordered_times = src_time is None or dst_time is None or src_time <= dst_time
        observed_times = tuple(item for item in (src_time, dst_time) if item is not None)
        timestamp = max(observed_times) if observed_times else float(len(edges))
        edge: dict[str, object] = {
            'parent_entity': dict.get(src, 'entity_id'),
            'child_entity': dict.get(dst, 'entity_id'),
            'edge_reason': reason,
            'confidence': _temporal_graph_confidence(confidence),
            'temporal_window_plausible': bool(ordered_times and not time_failures),
            'timestamp': timestamp,
            'contributing_root_observation_ids': tuple(root for root, _tag in root_matches),
            'tag_evidence_kinds_consumed': tuple(sorted(_TEMPORAL_TAG_EVIDENCE_KINDS)),
        }
        if time_failures:
            edge['degraded'] = True
            edge['relation_unavailable_reason'] = _temporal_graph_time_reason(time_failures)
            edge['invalid_event_time_count'] = len(time_failures)
            edge['final_json_must_record'] = True
            edge['replay_record_required'] = True
        elif not ordered_times:
            edge['edge_order'] = 'reverse_timestamp_order'
        edges.append(edge)

    try:
        add(
            'network_ioc', 'payload_decode_candidate',
            'network_indicator_to_payload_candidate', 0.42,
            (
                frozenset({'network_download', 'url_present', 'network_activity'}),
                frozenset({'decoded_base64_blob', 'encoded_payload', 'payload_decode_candidate', 'embedded_gzip_payload'}),
            ),
        )
        add(
            'payload_decode_candidate', 'execution_context',
            'decoded_payload_to_execution_capability', 0.62,
            (
                frozenset({'decoded_base64_blob', 'encoded_payload', 'payload_decode_candidate', 'embedded_gzip_payload'}),
                frozenset({'process_exec', 'script_execution', 'powershell_exec', 'shell_exec_abuse'}),
            ),
        )
        add(
            'written_artifact', 'execution_context',
            'written_artifact_to_execution_capability', 0.58,
            (
                frozenset({'file_write', 'dropper', 'archive_member', 'persistent_save_data'}),
                frozenset({'process_exec', 'script_execution'}),
            ),
        )
        add(
            'file', 'network_ioc',
            'credential_or_token_access_to_network_transfer', 0.55,
            (
                frozenset({'credential_access', 'token_secret_access', 'browser_profile_access'}),
                frozenset({'network_exfiltration', 'http_upload', 'network_activity'}),
            ),
        )
    except TAG_SCAN_RECOVERABLE_EXCEPTIONS as error:
        path_text, _path_reason = _temporal_graph_text(path, default_text='<unknown>')
        path_text = path_text or '<unknown>'
        failure = recoverable_failure_evidence(
            stage_name='causal_transition_edge_inference',
            error=error,
            error_source='detection.correlation.graph.temporal_graph',
            affected_context=path,
        )
        edges.append({
            'parent_entity': path_text,
            'child_entity': path_text,
            'edge_reason': 'failure_evidence_recorded',
            'confidence': 0.0,
            'temporal_window_plausible': False,
            'timestamp': float(len(edges)),
            'degraded': True,
            'failure_evidence': [failure.to_record()],
        })
    return edges[-50:]
