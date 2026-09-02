"""Canonical non-tag extension-baseline learning mutations."""

from Virus_Scan.contracts.chain_evidence import ChainEvidence
from Virus_Scan.models.profiles.baseline import ensure_extension_model_fields
from Virus_Scan.models.profiles.chain_state import PROFILE_CHAIN_STATE_SCHEMA_VERSION
from Virus_Scan.models.profiles.chain_records import (
    profile_chain_frequency_key,
    profile_scoreable_chain_decisions,
)
from Virus_Scan.models.profiles.common import (
    profile_finite_float,
)
from Virus_Scan.models.profiles.timeline import timeline_transitions
from Virus_Scan.utils.counters import increment_counter


def learn_extension_chains(
    extension_baseline: object,
    chain_evidence: ChainEvidence,
) -> object:
    """Persist canonical suspicious-chain frequencies as audit-only evidence."""
    if type(extension_baseline) is not dict:
        raise TypeError('profile_extension_baseline_required')
    if type(chain_evidence) is not ChainEvidence:
        raise TypeError('profile_chain_evidence_required')
    state = extension_baseline.get('chains')
    if (
        type(state) is not dict
        or state.get('schema_version') != PROFILE_CHAIN_STATE_SCHEMA_VERSION
        or type(state.get('suspicious_audit')) is not dict
    ):
        raise ValueError('profile_chain_state_invalid')
    state['registry_version'] = chain_evidence.registry_version
    state['registry_digest'] = chain_evidence.registry_digest
    audit = state['suspicious_audit']
    for decision in profile_scoreable_chain_decisions(chain_evidence):
        increment_counter(audit, profile_chain_frequency_key(decision))
    return state


def update_extension_risk_baseline(
    extension_baseline: object, risk: object,
) -> object:
    """Update the canonical finite extension risk baseline."""
    baseline = extension_baseline.setdefault(
        'risk', {'avg': 0.0, 'max_seen': 0.0, 'samples': 0},
    )
    risk_value = profile_finite_float(risk, 0.0)
    samples = int(baseline.get('samples', 0))
    old_average = float(baseline.get('avg', 0.0))
    baseline['avg'] = (old_average * samples + risk_value) / max(1, samples + 1)
    baseline['max_seen'] = max(float(baseline.get('max_seen', 0.0)), risk_value)
    baseline['samples'] = samples + 1
    return baseline


def update_extension_timeline_baseline(
    extension_baseline: object, ordered_events: object,
) -> object:
    """Update the deterministic extension timeline baseline."""
    ensure_extension_model_fields(extension_baseline)
    timeline = extension_baseline.setdefault('timeline_baseline', {})
    timeline.setdefault('sample_count', 0)
    timeline.setdefault('event_counts', {})
    timeline.setdefault('transition_counts', {})
    timeline.setdefault('behavior_counts', {})
    timeline.setdefault('behavior_transition_counts', {})
    events, transitions, behaviors, behavior_transitions = timeline_transitions(
        ordered_events,
    )
    if not events:
        return timeline
    timeline['sample_count'] = int(timeline.get('sample_count', 0)) + 1
    timeline['max_sequence_len'] = max(
        int(timeline.get('max_sequence_len', 0)), len(events),
    )
    timeline['last_updated'] = float(timeline.get('sample_count', 0))
    for event in events:
        increment_counter(timeline['event_counts'], event)
    for transition in transitions:
        increment_counter(timeline['transition_counts'], transition)
    for behavior in behaviors:
        increment_counter(timeline['behavior_counts'], behavior)
    for transition in behavior_transitions:
        increment_counter(timeline['behavior_transition_counts'], transition)
    return timeline


__all__ = (
    'learn_extension_chains',
    'update_extension_risk_baseline',
    'update_extension_timeline_baseline',
)
