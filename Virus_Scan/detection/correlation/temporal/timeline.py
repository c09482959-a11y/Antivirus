"""Canonical temporal-correlation ownership for ordered detection timelines."""
from __future__ import annotations


from Virus_Scan.detection.contracts.error_contracts import RECOVERABLE_RUNTIME_ERRORS
from Virus_Scan.contracts.no_hook_materialization import (
    no_hook_finite_float,
    no_hook_mapping_items,
    no_hook_sequence_items,
    no_hook_text,
)
from Virus_Scan.detection.tags.heuristics.behavior_buckets import tag_behavior_bucket
from Virus_Scan.detection.tags.heuristics.normalization_runtime import normalize_timeline_event_name
from Virus_Scan.detection.profiles.baseline_snapshot import read_extension_baseline_snapshot
from Virus_Scan.detection.registries.chain_registry import HIGH_RISK_BUCKETS



def _timeline_count(value: object) -> int | None:
    """Return a finite non-negative learned timeline count or None.

    Timeline baselines are learned model support.  Corrupt or caller-owned values
    must make the timeline model unavailable instead of executing numeric hooks or
    becoming rare/high-risk evidence.
    """
    if value is None:
        return None
    metric, reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        reason='non_numeric_timeline_count',
        non_finite_reason='non_finite_timeline_count',
        allow_exact_text=True,
    )
    if reason:
        return None
    if not metric.is_integer():
        metric = int(metric)
    return int(metric)


def _timeline_unavailable(reason: str, *, sample_count: object = 0) -> dict[str, object]:
    return {
        'ready': False,
        'anomaly': 0.0,
        'reason': reason,
        'degraded': True,
        'sample_count': _timeline_count(sample_count) or 0,
        'failure_evidence': [{
            'stage': 'extension_timeline_anomaly',
            'error_category': 'InvalidTimelineBaseline',
            'error_source': 'detection.correlation.temporal.timeline',
            'reason': reason,
            'json_record_required': True,
            'replay_record_required': True,
            'confidence_degraded': True,
        }],
    }


def _count_for(mapping: object, key: str) -> int | None:
    items = no_hook_mapping_items(mapping)
    if items is None:
        return None
    item_map = dict(items)
    return _timeline_count(dict.get(item_map, key, 0))

def _timeline_owned_event_mapping(event: object) -> dict[object, object] | None:
    items = no_hook_mapping_items(event)
    if items is None:
        return None
    return dict(items)


def real_ordered_event_names(timeline_or_events: object) -> list[str]:
    """Normalize concrete ordered events into tag names without caller hooks."""
    out = []
    for event in no_hook_sequence_items(timeline_or_events):
        event_map = _timeline_owned_event_mapping(event)
        if event_map is not None:
            tag = dict.get(event_map, 'tag')
            if tag is None:
                tag = dict.get(event_map, 'behavior')
            if tag is None:
                tag = dict.get(event_map, 'raw')
        else:
            tag = event
        text, reason = no_hook_text(
            tag,
            missing_reason='missing_timeline_event_name',
            unsupported_reason='timeline_event_name_rejected',
        )
        if reason == '' and text.strip():
            out.append(text.strip())
    return out


def real_timeline_events(timeline: object) -> list[object]:
    """Concrete ordered timeline events only."""
    return list(no_hook_sequence_items(timeline))


def timeline_event_behavior(event: object) -> str:
    """Map timeline events into broad behavior buckets for baseline comparison."""
    return tag_behavior_bucket(normalize_timeline_event_name(event))


def _timeline_transition_label(left: str, right: str) -> str:
    return str.__str__(left) + '->' + str.__str__(right)


def _timeline_probability(value: object) -> float:
    probability, _reason = no_hook_finite_float(
        value,
        default=0.0,
        minimum=0.0,
        maximum=1.0,
        reason='unsafe_timeline_probability_rejected',
        non_finite_reason='non_finite_timeline_probability',
    )
    return probability


def _timeline_frequency(count: object, denominator: object) -> float:
    metric, _metric_reason = no_hook_finite_float(
        count,
        default=0.0,
        minimum=0.0,
        reason='unsafe_timeline_frequency_count_rejected',
        non_finite_reason='non_finite_timeline_frequency_count',
    )
    divisor, _divisor_reason = no_hook_finite_float(
        denominator,
        default=1.0,
        minimum=1.0,
        reason='unsafe_timeline_frequency_denominator_rejected',
        non_finite_reason='non_finite_timeline_frequency_denominator',
    )
    return _timeline_probability(metric / divisor)


def _timeline_rarity_values(values: list[int], denominator: object) -> float:
    if not values:
        return 0.0
    return sum((1.0 - _timeline_frequency(count, denominator) for count in values)) / max(1, len(values))


def timeline_transitions(ordered_events: object, max_events: int = 256) -> tuple[list[str], list[str], list[str], list[str]]:
    """Build bounded ordered event and transition lists without sorting or deduping."""
    events = []
    for ev in real_timeline_events(ordered_events):
        name = normalize_timeline_event_name(ev)
        if name:
            events.append(name)
        if len(events) >= max_events:
            break
    transitions = [_timeline_transition_label(events[i], events[i + 1]) for i in range(len(events) - 1)]
    behaviors = [timeline_event_behavior(ev) for ev in events]
    behavior_transitions = [_timeline_transition_label(behaviors[i], behaviors[i + 1]) for i in range(len(behaviors) - 1)]
    return (events, transitions, behaviors, behavior_transitions)


def extension_timeline_anomaly(engine: object, file_path: object, ordered_events: object, min_samples: int = 5) -> dict[str, object]:
    """Compare current ordered_events against the clean learned sequence baseline."""
    try:
        baseline = read_extension_baseline_snapshot(engine, file_path)
        tb = baseline.get('timeline_baseline', {})
        samples = _timeline_count(tb.get('sample_count', 0))
        if samples is None:
            return _timeline_unavailable('non_finite_timeline_sample_count')
        events, transitions, behaviors, behavior_transitions = timeline_transitions(ordered_events)
        if samples < min_samples or not events:
            return {'ready': False, 'anomaly': 0.0, 'reason': 'insufficient_timeline_history', 'sample_count': samples}
        event_counts = tb.get('event_counts', {})
        transition_counts = tb.get('transition_counts', {})
        behavior_counts = tb.get('behavior_counts', {})
        behavior_transition_counts = tb.get('behavior_transition_counts', {})
        event_values = []
        for ev in events:
            value = _count_for(event_counts, ev)
            if value is None:
                return _timeline_unavailable('non_finite_timeline_event_count', sample_count=samples)
            event_values.append(value)
        transition_values = []
        for tr in transitions:
            value = _count_for(transition_counts, tr)
            if value is None:
                return _timeline_unavailable('non_finite_timeline_transition_count', sample_count=samples)
            transition_values.append(value)
        behavior_values = []
        for behavior in behaviors:
            value = _count_for(behavior_counts, behavior)
            if value is None:
                return _timeline_unavailable('non_finite_timeline_behavior_count', sample_count=samples)
            behavior_values.append(value)
        behavior_transition_values = []
        for bt in behavior_transitions:
            value = _count_for(behavior_transition_counts, bt)
            if value is None:
                return _timeline_unavailable('non_finite_timeline_behavior_transition_count', sample_count=samples)
            behavior_transition_values.append(value)
        denominator = max(1.0, samples + 0.0)
        event_rare = _timeline_rarity_values(event_values, denominator)
        transition_rare = _timeline_rarity_values(transition_values, denominator) if transition_values else 0.0
        behavior_rare = _timeline_rarity_values(behavior_values, denominator)
        behavior_transition_rare = _timeline_rarity_values(behavior_transition_values, denominator) if behavior_transition_values else 0.0
        never_seen_high_risk = 0
        for ev, event_count in zip(events, event_values, strict=False):
            bucket = tag_behavior_bucket(ev)
            if bucket in HIGH_RISK_BUCKETS and event_count <= 0:
                never_seen_high_risk += 1
        high_risk_boost = _timeline_probability(never_seen_high_risk / max(1, len(events)))
        anomaly = _timeline_probability(event_rare * 0.22 + transition_rare * 0.36 + behavior_rare * 0.12 + behavior_transition_rare * 0.2 + high_risk_boost * 0.1)
        return {'ready': True, 'anomaly': anomaly, 'event_rarity': _timeline_probability(event_rare), 'transition_rarity': _timeline_probability(transition_rare), 'behavior_rarity': _timeline_probability(behavior_rare), 'behavior_transition_rarity': _timeline_probability(behavior_transition_rare), 'never_seen_high_risk_events': never_seen_high_risk, 'sample_count': samples, 'events_seen': len(events), 'transitions_seen': len(transitions)}
    except RECOVERABLE_RUNTIME_ERRORS as e:
        return {'ready': False, 'anomaly': 0.0, 'reason': 'timeline_anomaly_error', 'degraded': True, 'failure_evidence': [{'stage': 'extension_timeline_anomaly', 'error_category': type(e).__name__, 'error_source': 'detection.correlation.temporal.timeline', 'json_record_required': True, 'replay_record_required': True, 'confidence_degraded': True}]}
