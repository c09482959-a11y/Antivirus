"""Detection-owned pure model/context projections."""
from __future__ import annotations

from pathlib import Path

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.models.profiles.chain_records import profile_chain_family_count
from Virus_Scan.detection.contracts.filetype_context import CONTAINER_EXECUTION_CAPABILITIES, NON_EXECUTION_CAPABILITIES, filetype_validation_context
from Virus_Scan.contracts.tag_evidence import (
    distinct_positive_root_ids_for_tags,
    distinct_root_tag_evidence_records,
    evidence_level_for_tag,
)
from Virus_Scan.detection.models.evidence_stage_outputs import TagEvidence
from Virus_Scan.detection.registries.chain_registry import HIGH_RISK_BUCKETS
from Virus_Scan.detection.registries.context import detection_registry_value
from Virus_Scan.detection.scoring.weighting.scoreable_tags import (
    concrete_score_count,
    scoreable_tag_evidence,
    scoreable_tag_set,
)
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_tags
from Virus_Scan.detection.contracts.probability import safe_clamp
from Virus_Scan.contracts.no_hook_materialization import no_hook_mapping_items, no_hook_text, no_hook_finite_float, no_hook_sequence_items
from Virus_Scan.models.api.profile_contracts import get_temporal_baselines
from Virus_Scan.models.api.temporal_contracts import compute_temporal_validation
from Virus_Scan.models.api.markov_contracts import (
    canonical_behavior_flow,
    compute_markov_features,
)

PLR2004N0_3 = 0.3
PLR2004N0_6 = 0.6
PLR2004N2 = 2

VECTOR_FEATURE_NAMES = tuple(detection_registry_value("VECTOR_FEATURE_NAMES", ()))

def _finite_projection_metric(value: object, default: float = 0.0) -> float:
    """Return a bounded finite model-projection metric without caller hooks."""
    metric, _reason = no_hook_finite_float(value, default=default, allow_exact_text=True)
    return metric


_PROJECTION_RECOVERABLE_ERRORS = (
    ArithmeticError,
    AttributeError,
    KeyError,
    LookupError,
    OSError,
    RuntimeError,
    TypeError,
    UnicodeError,
    ValueError,
)


def _safe_projection_text(value: object, *, default_text: str = '') -> str:
    replacement_text, _replacement_reason = no_hook_text(
        default_text,
        missing_reason='missing_projection_default_text',
        unsupported_reason='unsafe_projection_default_text_rejected',
    )
    text, reason = no_hook_text(
        value,
        missing_reason='missing_projection_text',
        unsupported_reason='unsafe_projection_text_rejected',
    )
    if reason is not None and reason != '':
        return str.strip(replacement_text)
    text = str.strip(text)
    return text if text != '' else str.strip(replacement_text)


def _projection_sequence(value: object) -> tuple[object, ...]:
    if type(value) is TagEvidence:
        return tuple(value.tags)
    return no_hook_sequence_items(value)


def _projection_tag_evidence(value: object) -> TagEvidence:
    return scoreable_tag_evidence(
        value,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )


def _projection_text_sequence(value: object) -> tuple[str, ...]:
    return tuple(text for text in (_safe_projection_text(item) for item in _projection_sequence(value)) if text != '')


def _first_projection_sequence(*values: object) -> tuple[object, ...]:
    for value in values:
        if value is None:
            continue
        sequence = _projection_sequence(value)
        if len(sequence) > 0:
            return sequence
    return ()

def _projection_mapping(value: object) -> dict[object, object]:
    items = no_hook_mapping_items(value)
    if items is None:
        return {}
    out: dict[object, object] = {}
    for key, child in items:
        key_text = _safe_projection_text(key)
        if key_text != '':
            out[key_text] = child
    return out

def _dominant_engine_context(engine_context: dict[str, object] | None) -> str:
    """Select the dominant engine using only finite context weights."""
    finite_context: dict[str, float] = {}
    context = _projection_mapping(engine_context)
    for key, value in tuple(dict.items(context)):
        metric = _finite_projection_metric(value, 0.0)
        key_text = _safe_projection_text(key)
        if metric > 0.0 and key_text != '':
            finite_context[key_text] = metric
    return max(tuple(finite_context), key=lambda engine: finite_context[engine]) if finite_context else 'other'

def detection_graph_features(node: object) -> dict[str, object]:
    """Pure graph projection without reading or mutating runtime graph state."""
    del node  # Explicitly unused contract parameters.
    return {'risk': 0.0, 'base_risk': 0.0, 'anomaly': 0.0, 'ready': False, 'reason': 'runtime_graph_state_external_to_detection'}

def detection_temporal_snapshot(node: object, ordered_events: object = None, behavior_timeline: object = None) -> dict[str, object]:
    """Pure temporal projection from current ordered evidence only."""
    del node  # Explicitly unused contract parameters.
    events = list(_first_projection_sequence(ordered_events, behavior_timeline))
    if len(events) < PLR2004N2:
        return {'belief': 0.0, 'flow': [], 'ready': False, 'reason': 'insufficient_current_ordered_events'}
    risky = 0
    flow = []
    for ev in events[:64]:
        mapping = _projection_mapping(ev)
        name = dict.get(mapping, 'tag') if mapping else ev
        tag_text = _safe_projection_text(name)
        if tag_text != '':
            flow.append(tag_text)
        bucket = tag_behavior_bucket(tag_text.lower())
        if bucket in HIGH_RISK_BUCKETS:
            risky += 1
    belief = safe_clamp(risky / max(1.0, len(events) + 0.0))
    return {'belief': belief, 'flow': flow, 'ready': True}

def detection_temporal_history_timeline(node: object, ordered_events: object = None, behavior_timeline: object = None) -> list[dict[str, object]]:
    """Return bounded current-run timeline records without runtime history reads."""
    del node  # Explicitly unused contract parameters.
    out = []
    for idx, ev in enumerate(list(_first_projection_sequence(ordered_events, behavior_timeline))[:25]):
        mapping = _projection_mapping(ev)
        if mapping:
            tag = _safe_projection_text(dict.get(mapping, 'tag'))
            if tag == '':
                tag = _safe_projection_text(dict.get(mapping, 'behavior'))
            if tag == '':
                tag = _safe_projection_text(dict.get(mapping, 'raw'))
            stage = _safe_projection_text(dict.get(mapping, 'stage'), default_text='current')
            ts = dict.get(mapping, 'time')
            if ts is None:
                ts = idx
        else:
            tag = ev
            stage = 'current'
            ts = idx
        tag_text = _safe_projection_text(tag)
        out.append({'time': ts, 'stage': _safe_projection_text(stage, default_text='current'), 'tags': [tag_text] if tag_text != '' else []})
    return out

def detection_markov_features(prev_stage: object, behavior_flow: object, curr_stage: object) -> dict[str, object]:
    """Project current flow through the learned-only canonical Markov owner."""
    flow = tuple(canonical_behavior_flow(behavior_flow if behavior_flow is not None else ()))
    bundle = compute_markov_features(prev_stage, flow, curr_stage)
    items = no_hook_mapping_items(bundle)
    projection = {key: value for key, value in items if type(key) is str} if items is not None else {}
    projection['flow'] = list(flow)
    return projection


def detection_temporal_validation(
    node: object, tags: object = None, prev_stage: object = None,
    curr_stage: object = None, markov: object = None,
    ordered_events: object = (), engine: object = "other",
) -> dict[str, object]:
    """Return canonical temporal validation evidence through the detection model boundary.

    The temporal model remains the sole owner of temporal validation facts.
    Detection callers use this boundary so correlation/scoring modules do not
    import model owners directly or recompute temporal probability internals.
    """
    engine_text = _safe_projection_text(engine, default_text="other")
    baselines = get_temporal_baselines(engine_text)
    result = compute_temporal_validation(
        node,
        tags=tags,
        prev_stage=prev_stage,
        curr_stage=curr_stage,
        markov=markov,
        ordered_events=ordered_events,
        engine=engine_text,
        temporal_baselines=baselines,
    )
    return result if isinstance(result, dict) else {
        'score': 0.0,
        'hits': ('temporal_validation_invalid_model_output',),
        'ready': False,
        'degraded': True,
        'unavailable_reason': 'invalid_temporal_validation_output',
        'evidence_type': 'temporal_validation',
    }

def detection_behavior_bucket_validation(engine: object, file_path: object, tags: object, strings_blob: object = '', api_calls: object = None, ordered_events: object = None) -> dict[str, object]:
    """Pure behavior-bucket validation for vector reads without profile mutation."""
    evidence = _projection_tag_evidence(tags if tags is not None else ())
    tagset = {tag.lower() for tag in evidence.tags}
    root_records = distinct_root_tag_evidence_records(
        evidence.records,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    safe_path = _safe_projection_text(file_path)
    safe_engine = _safe_projection_text(engine, default_text='other')
    safe_strings = _safe_projection_text(strings_blob)
    safe_events = _projection_sequence(ordered_events if ordered_events is not None else ())
    records = []
    high_risk_seen = 0
    for tag_record in root_records:
        tag = tag_record.canonical_tag_id
        bucket = tag_record.behavior_bucket or tag_behavior_bucket(tag)
        try:
            ev_name, ev_conf = evidence_level_for_tag(tag, strings_blob=safe_strings, path=safe_path, api_calls=api_calls, ordered_events=safe_events)
        except _PROJECTION_RECOVERABLE_ERRORS:
            ev_name, ev_conf = ('unavailable_evidence_context', 0.0)
        if bucket in HIGH_RISK_BUCKETS:
            high_risk_seen += 1
        records.append({
            'tag': tag,
            'bucket': bucket,
            'evidence': ev_name,
            'confidence': safe_clamp(_finite_projection_metric(ev_conf, 0.0)),
            'probability': 0.0,
            'expected_for_engine_extension': False,
            'evidence_id': tag_record.evidence_id,
            'root_observation_id': tag_record.root_observation_id,
            'evidence_kind': tag_record.evidence_kind,
            'correlation_group': tag_record.correlation_group,
        })
    try:
        fctx = filetype_validation_context(safe_engine, safe_path)
    except _PROJECTION_RECOVERABLE_ERRORS:
        fctx = {'execution_capability': 'unknown', 'filetype_anomaly': 0.0, 'ready': False, 'degraded': True, 'unavailable_reason': 'filetype_validation_unavailable'}
    return {
        'records': records,
        'rare_high_conf_single_indicator': any(r['bucket'] in HIGH_RISK_BUCKETS and r['confidence'] >= 0.6 for r in records),
        'nonexec_execution_violation': bool(fctx.get('execution_capability') in NON_EXECUTION_CAPABILITIES and high_risk_seen),
        'filetype_validation': fctx,
    }

def detection_feature_vector(node: object, tags: object, chain_evidence: ChainEvidence, graph_features: object, temporal_features: object, markov_features: object, engine_context: object, *, risk: object = 0.0, file_path: object = None, strings_blob: object = '', api_calls: object = None, ordered_events: object = None) -> list[float]:
    """Build one stable vector from the canonical shared evidence generation."""
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError("detection_feature_vector_chain_evidence_required")
    tag_evidence = _projection_tag_evidence(tags if tags is not None else ())
    tags = list(tag_evidence.tags)
    tagset = {tag.lower() for tag in tags}
    root_records = distinct_root_tag_evidence_records(
        tag_evidence.records,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    graph_features = _projection_mapping(graph_features)
    temporal_features = _projection_mapping(temporal_features)
    markov_features = _projection_mapping(markov_features)
    engine_context = _projection_mapping(engine_context)
    engine = _dominant_engine_context(engine_context)
    vector_path = file_path if file_path is not None else node
    val = detection_behavior_bucket_validation(engine, vector_path, tags, strings_blob=strings_blob, api_calls=api_calls, ordered_events=ordered_events)
    support = set(detection_registry_value('SUPPORT_ONLY_SCORE_TAGS', set()))
    scoreable = scoreable_tag_set(tag_evidence)
    buckets = [record.behavior_bucket for record in root_records]
    weak = sum(1 for r in val['records'] if r['confidence'] < PLR2004N0_3)
    strong = sum(1 for r in val['records'] if r['confidence'] >= PLR2004N0_6)
    rare_high = sum(1 for r in val['records'] if r['bucket'] in HIGH_RISK_BUCKETS and r['confidence'] >= 0.6)
    safe_vector_path = _safe_projection_text(vector_path)
    try:
        fctx = filetype_validation_context(engine, safe_vector_path)
    except _PROJECTION_RECOVERABLE_ERRORS:
        fctx = {'execution_capability': 'unknown', 'filetype_anomaly': 0.0, 'ready': False, 'degraded': True, 'unavailable_reason': 'filetype_validation_unavailable'}
    counts = {
        'tag_count': len(root_records) / 60.0,
        'scoreable_count': concrete_score_count(tag_evidence) / 30.0,
        'support_only_count': len(distinct_positive_root_ids_for_tags(
            tag_evidence.records, support,
            allowed_evidence_kinds=frozenset({
                'observed', 'normalized', 'derived', 'composite',
            }),
        )) / 15.0,
        'chain_count': profile_chain_family_count(chain_evidence) / 12.0,
        'os_exec_count': buckets.count('os_execution') / 10.0,
        'network_count': buckets.count('network') / 10.0,
        'credential_count': buckets.count('credential') / 10.0,
        'persistence_count': buckets.count('persistence') / 10.0,
        'injection_count': buckets.count('injection') / 10.0,
        'evasion_count': buckets.count('evasion') / 10.0,
        'entropy_count': buckets.count('entropy_or_packing') / 10.0,
        'renpy_script_count': buckets.count('renpy_script_logic') / 10.0,
        'unity_managed_count': buckets.count('unity_managed_code') / 10.0,
        'rpgm_node_count': buckets.count('rpgm_node_runtime') / 10.0,
        'weak_evidence_count': weak / 20.0,
        'strong_evidence_count': strong / 20.0,
        'rare_high_risk_count': rare_high / 10.0,
        'global_passive_asset': 1.0 if fctx.get('execution_capability') in NON_EXECUTION_CAPABILITIES else 0.0,
        'global_container_asset': 1.0 if fctx.get('execution_capability') in CONTAINER_EXECUTION_CAPABILITIES else 0.0,
        'global_script_asset': 1.0 if fctx.get('execution_capability') in {'script', 'managed', 'native'} else 0.0,
        'global_mixed_asset': 1.0 if fctx.get('execution_capability') == 'mixed' else 0.0,
        'nonexec_execution_violation': 1.0 if val.get('nonexec_execution_violation') else 0.0,
        'engine_filetype_risk': _finite_projection_metric(val.get('filetype_validation', {}).get('filetype_anomaly', 0.0)),
        'risk_scaled': _finite_projection_metric(risk, 0.0) / 100.0,
        # Canonical clustering feature names shared with the model feature order.
        'tag_entropy': 0.0,
        'unique_tag_count': len(root_records) / 60.0,
        'graph_risk': _finite_projection_metric(graph_features.get('risk', 0.0)),
        'graph_anomaly': _finite_projection_metric(graph_features.get('anomaly', 0.0)),
        'temporal_belief': _finite_projection_metric(temporal_features.get('belief', 0.0)),
        'markov_transition': _finite_projection_metric(markov_features.get('transition', 0.0)),
        'markov_rarity': _finite_projection_metric(markov_features.get('rarity', 0.0)),
        'markov_pair_anomaly': _finite_projection_metric(markov_features.get('pair_anomaly', 0.0)),
        'unity_context': _finite_projection_metric(engine_context.get('unity', 0.0)),
        'renpy_context': _finite_projection_metric(engine_context.get('renpy', 0.0)),
        'rpgm_context': _finite_projection_metric(engine_context.get('rpgm', 0.0)),
        'media_context': _finite_projection_metric(engine_context.get('media', 0.0)),
        'other_context': _finite_projection_metric(engine_context.get('other', engine_context.get('unknown', 0.0))),
        'cluster_size': 0.0,
        'cluster_risk': 0.0,
        'cluster_anomaly': 0.0,
    }
    return [safe_clamp(_finite_projection_metric(counts.get(name, 0.0))) for name in VECTOR_FEATURE_NAMES]

def detection_cluster_projection(node: object, tags: object, engine_context: object = None) -> str | None:
    """Return an immutable cluster candidate label without mutating cluster state."""
    tag_evidence = _projection_tag_evidence(tags if tags is not None else ())
    usable_roots = distinct_root_tag_evidence_records(
        tag_evidence.records,
        allowed_evidence_kinds=frozenset({"observed", "normalized", "derived", "composite"}),
    )
    if tag_evidence.summary.get("failure_count", 0) and not usable_roots:
        return None
    tags = list(tag_evidence.tags)
    if len(tags) == 0:
        return None
    engine_context = _projection_mapping(engine_context)
    if len(engine_context) == 0:
        engine_context = {'other': 1.0}
    engine = _dominant_engine_context(engine_context)
    ext = Path(_safe_projection_text(node)).suffix.lower().replace('.', '')
    if ext == '':
        ext = 'noext'
    tagset = {_safe_projection_text(t).lower() for t in tags if _safe_projection_text(t) != ''}
    kind = 'malicious' if (tagset & {'process_injection', 'credential_access', 'network_exfiltration', 'ransomware_behavior', 'pickle_dangerous_global', 'pickle_reduce_opcode'}) else 'mixed'
    return engine + '_' + ext + '_' + kind + '_detection_projection'

__all__ = (
    'detection_behavior_bucket_validation',
    'detection_cluster_projection',
    'detection_feature_vector',
    'detection_graph_features',
    'detection_markov_features',
    'detection_temporal_history_timeline',
    'detection_temporal_snapshot',
    'detection_temporal_validation',
)
