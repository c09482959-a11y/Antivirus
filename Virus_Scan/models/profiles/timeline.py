"""Profile timeline transition and anomaly owners."""

from Virus_Scan.models.profiles.baseline import profile_model_failure_record, profile_tag_behavior_bucket, get_extension_baseline
from Virus_Scan.models.profiles.common import profile_first_reason, profile_has_mapping, profile_int, profile_mapping_get, profile_public_ordered_events, profile_ratio, profile_safe_text
from Virus_Scan.runtime.init_state import get_init_value


BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')
HIGH_RISK_BUCKETS = frozenset(get_init_value('HIGH_RISK_BUCKETS') or ())


def _profile_timeline_count(value: object) -> object:
    """Return finite non-negative profile timeline count or None."""
    metric = profile_int(value, None)
    if metric is None or metric < 0:
        return None
    return metric


def profile_timeline_unavailable(reason: object, *, sample_count: object=0) -> object:
    reason_text = profile_first_reason(reason, replacement='profile_timeline_unavailable')
    count = _profile_timeline_count(sample_count)
    return {
        'ready': False,
        'anomaly': 0.0,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'degraded': True,
        'sample_count': count if count is not None else 0,
        'evidence_type': 'profile_timeline_baseline',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (
            profile_model_failure_record(
                'profiles',
                'timeline_baseline_unavailable',
                reason_text,
                affected_fields=('timeline_validation', 'timeline_support'),
            ),
        ),
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def _profile_timeline_count_for(mapping: object, key: object) -> object:
    if not profile_has_mapping(mapping):
        return None
    return _profile_timeline_count(profile_mapping_get(mapping, key, 0))


def _profile_timeline_event_name(value: object) -> object:
    if profile_has_mapping(value):
        for key in ('tag', 'behavior', 'event', 'raw'):
            text = profile_safe_text(profile_mapping_get(value, key), replacement='').strip().lower()
            if text != '':
                return text
        return ''
    return profile_safe_text(value, replacement='').strip().lower()


def _profile_timeline_rarity(values: object, denominator: object) -> object:
    if len(values) == 0:
        return 0.0
    return sum(1.0 - profile_ratio(value, denominator) for value in values) / len(values)


def timeline_transitions(ordered_events: object, max_events: object=256) -> object:
    """Profile-owned bounded ordered-event transition builder."""
    max_events = profile_int(max_events, 256)
    if max_events <= 0:
        max_events = 256
    ordered_values, unavailable_reason = profile_public_ordered_events(
        ordered_events, 'malformed_ordered_profile_events'
    )
    if unavailable_reason is not None:
        return ([], [], [], [])
    events = []
    for ev in ordered_values:
        name = _profile_timeline_event_name(ev)
        if name != '':
            events.append(name)
        if len(events) >= max_events:
            break
    transitions = ['->'.join((events[i], events[i + 1])) for i in range(len(events) - 1)]
    behaviors = [profile_tag_behavior_bucket(ev) for ev in events]
    behavior_transitions = ['->'.join((behaviors[i], behaviors[i + 1])) for i in range(len(behaviors) - 1)]
    return (events, transitions, behaviors, behavior_transitions)


def _profile_timeline_values(mapping: object, keys: object) -> object:
    values = []
    for key in keys:
        value = _profile_timeline_count_for(mapping, key)
        if value is None:
            return None
        values.append(value)
    return values


def _profile_timeline_value_groups(tb: object, groups: object) -> object:
    resolved = []
    for mapping_key, keys, unavailable_reason in groups:
        values = _profile_timeline_values(profile_mapping_get(tb, mapping_key, {}), keys)
        if values is None:
            return (None, unavailable_reason)
        resolved.append(values)
    return (resolved, None)


def _profile_timeline_high_risk_count(events: object, event_values: object) -> object:
    never_seen_high_risk = 0
    for event, event_count in zip(events, event_values, strict=False):
        if profile_tag_behavior_bucket(event) in HIGH_RISK_BUCKETS and event_count <= 0:
            never_seen_high_risk += 1
    return never_seen_high_risk


def extension_timeline_anomaly(engine: object, file_path: object, ordered_events: object, min_samples: object=5) -> object:
    """Profile-owned timeline anomaly against the loaded extension baseline."""
    baseline = get_extension_baseline(engine, file_path)
    tb = profile_mapping_get(baseline, 'timeline_baseline', {})
    samples = _profile_timeline_count(profile_mapping_get(tb, 'sample_count', 0))
    if samples is None:
        return profile_timeline_unavailable('non_finite_timeline_sample_count')
    events, transitions, behaviors, behavior_transitions = timeline_transitions(ordered_events)
    if samples < min_samples or not events:
        return profile_timeline_unavailable('insufficient_timeline_history', sample_count=samples)
    groups = (
        ('event_counts', events, 'non_finite_timeline_event_count'),
        ('transition_counts', transitions, 'non_finite_timeline_transition_count'),
        ('behavior_counts', behaviors, 'non_finite_timeline_behavior_count'),
        ('behavior_transition_counts', behavior_transitions, 'non_finite_timeline_behavior_transition_count'),
    )
    value_groups, unavailable_reason = _profile_timeline_value_groups(tb, groups)
    if unavailable_reason is not None:
        return profile_timeline_unavailable(unavailable_reason, sample_count=samples)
    event_values, transition_values, behavior_values, behavior_transition_values = value_groups
    denominator = max(1, samples)
    event_rare = _profile_timeline_rarity(event_values, denominator)
    transition_rare = _profile_timeline_rarity(transition_values, denominator)
    behavior_rare = _profile_timeline_rarity(behavior_values, denominator)
    behavior_transition_rare = _profile_timeline_rarity(behavior_transition_values, denominator)
    never_seen_high_risk = _profile_timeline_high_risk_count(events, event_values)
    high_risk_boost = profile_ratio(never_seen_high_risk, len(events))
    anomaly = profile_ratio(
        event_rare * 0.22 + transition_rare * 0.36 + behavior_rare * 0.12
        + behavior_transition_rare * 0.2 + high_risk_boost * 0.1,
        1.0,
    )
    return {
        'ready': True,
        'anomaly': anomaly,
        'event_rarity': profile_ratio(event_rare, 1.0),
        'transition_rarity': profile_ratio(transition_rare, 1.0),
        'behavior_rarity': profile_ratio(behavior_rare, 1.0),
        'behavior_transition_rarity': profile_ratio(behavior_transition_rare, 1.0),
        'never_seen_high_risk_events': never_seen_high_risk,
        'sample_count': samples,
        'events_seen': len(events),
        'transitions_seen': len(transitions),
    }


__all__ = (
    'extension_timeline_anomaly',
    'profile_timeline_unavailable',
    'timeline_transitions',
)
