"""Profile learning normalization and behavior-vector owners.

This module owns profile learning input normalization, behavior-flow projection,
chain extraction, and deterministic behavior-vector construction. It does not
import ``profiles.api`` and therefore cannot mutate persisted profile state or
reach back through private API internals.
"""

from pathlib import Path

from Virus_Scan.contracts.tag_evidence import (
    positive_tag_groups_have_distinct_roots,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.profiles.chain_records import profile_chain_family_count
from Virus_Scan.models.profiles.baseline import (
    profile_model_failure_record,
    profile_tag_behavior_bucket,
)
from Virus_Scan.models.profiles.common import (
    profile_first_reason,
    profile_has_mapping,
    profile_mapping_get,
    profile_mapping_items,
    profile_public_ordered_events,
    profile_ratio,
    profile_safe_text,
)
from Virus_Scan.models.profiles.tag_evidence import (
    PROFILE_TAG_EVIDENCE_KINDS,
    profile_scoreable_root_ids,
    profile_tag_evidence_projection,
)
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_NAMES
from Virus_Scan.utils.entropy import tag_entropy
from Virus_Scan.utils.stages import normalize_stage

PLR2004N0_3 = 0.3
PLR2004N0_6 = 0.6

BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')
VECTOR_FEATURE_NAMES = PROFILE_RAW_FEATURE_NAMES


def profile_learning_commit_unavailable(reason: object) -> object:
    reason_text = profile_safe_text(reason, replacement='profile_learning_unavailable')
    return {
        'learned': False,
        'promoted': False,
        'updated': False,
        'ready': False,
        'degraded': True,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'evidence_type': 'profile_learning_commit',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (
            profile_model_failure_record(
                'profiles',
                'profile_learning_input_unavailable',
                reason_text,
                affected_fields=('profile_learning', 'profile_baseline'),
            ),
        ),
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def profile_behavior_vector_unavailable(reason: object) -> object:
    reason_text = profile_safe_text(reason, replacement='profile_behavior_vector_unavailable')
    return {
        'ready': False,
        'degraded': True,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'evidence_type': 'profile_behavior_vector',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (
            profile_model_failure_record(
                'profiles',
                'behavior_vector_input_unavailable',
                reason_text,
                affected_fields=('profile_behavior_vector', 'profile_learning'),
            ),
        ),
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def _profile_learning_event_name(item: object) -> object:
    if profile_has_mapping(item):
        for key in ('tag', 'behavior', 'event', 'name', 'raw'):
            name = profile_safe_text(profile_mapping_get(item, key, None), replacement='').strip().lower()
            if name != '':
                return name
        return ''
    return profile_safe_text(item, replacement='').strip().lower()


def canonical_profile_learning_flow(tags: object=None, ordered_events: object=None, behavior_flow: object=None) -> object:
    """One behavior-flow normalizer for Markov, temporal, timeline and vector learning."""
    source = None
    for candidate in (behavior_flow, ordered_events, tags):
        values, reason = profile_public_ordered_events(candidate, 'malformed_profile_learning_flow')
        if reason:
            return []
        if values:
            source = values
            break
    if source is None:
        source = ()
    out = []
    seen = set()
    for item in source:
        text = _profile_learning_event_name(item)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def canonical_behavior_flow_from_sources(raw_tags: object=None, ordered_events: object=None, behavior_timeline: object=None, behavior_flow: object=None) -> object:
    for candidate in (behavior_flow, behavior_timeline, ordered_events, raw_tags):
        if type(candidate) is TagEvidence:
            _bundle, _records, root_tags, _groups, reason = (
                profile_tag_evidence_projection(
                    candidate, 'malformed_profile_learning_flow'
                )
            )
            return [] if reason else canonical_profile_learning_flow(tags=root_tags)
        values, reason = profile_public_ordered_events(candidate, 'malformed_profile_learning_flow')
        if reason:
            return []
        if values:
            return canonical_profile_learning_flow(tags=values)
    return []


def learning_verdict_is_clean(verdict: object) -> object:
    """Only final clean verdicts may enter benign staging or baseline learning."""
    v = profile_safe_text(verdict, replacement='').strip().lower()
    return v in {'benign', 'clean', 'benign_clean', 'ok'}


def real_ordered_event_names(timeline_or_events: object) -> object:
    """Profile-owned ordered event name normalization for staged learning metadata."""
    events, unavailable_reason = profile_public_ordered_events(
        timeline_or_events, 'malformed_ordered_profile_events'
    )
    if unavailable_reason:
        return []
    out = []
    seen = set()
    for item in events:
        name = _profile_learning_event_name(item)
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _profile_init_mapping_items(name: object) -> object:
    items = profile_mapping_items(get_init_value(name))
    return () if items is None else items


def _profile_init_sequence(name: object) -> object:
    values, unavailable = profile_public_ordered_events(
        get_init_value(name), 'malformed_profile_init_sequence'
    )
    return () if unavailable is not None else values


def _profile_terms_have_distinct_roots(bundle: object, terms: object) -> bool:
    groups = tuple((term,) for term in sorted(set(terms)))
    return positive_tag_groups_have_distinct_roots(
        bundle.records,
        groups,
        allowed_evidence_kinds=PROFILE_TAG_EVIDENCE_KINDS,
    )



def behavior_vector_from_scan(engine: object, file_path: object, tags: object, api_calls: object=None, ordered_events: object=None) -> object:
    """Build the profile raw-observation vector with no downstream model inputs."""
    del engine, file_path
    bundle, root_records, root_tags, correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, 'malformed_profile_behavior_tags')
    )
    event_values, ordered_reason = profile_public_ordered_events(
        ordered_events, 'malformed_ordered_profile_events',
    )
    api_values, api_reason = profile_public_ordered_events(
        api_calls, 'malformed_profile_learning_api_calls',
    )
    malformed_reason = profile_first_reason(
        tag_reason, ordered_reason, api_reason, replacement='',
    )
    if malformed_reason != '':
        return profile_behavior_vector_unavailable(malformed_reason)
    buckets = [
        profile_tag_behavior_bucket(record.publication_name)
        for record in root_records
    ]
    chain_evidence = evaluate_chain_evidence(
        tags=bundle, api_calls=api_values, ordered_events=event_values,
    )
    scoreable_roots = profile_scoreable_root_ids(bundle)
    support_roots = {
        record.root_observation_id for record in root_records
    } - set(scoreable_roots)
    counts = {
        'tag_count': len(root_records) / 60.0,
        'tag_entropy': min(1.0, tag_entropy(root_tags)),
        'unique_tag_count': correlation_group_count / 60.0,
        'scoreable_count': len(scoreable_roots) / 30.0,
        'support_only_count': len(support_roots) / 30.0,
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
    }
    return [profile_ratio(counts[name], 1.0) for name in VECTOR_FEATURE_NAMES]


__all__ = (
    'behavior_vector_from_scan',
    'canonical_behavior_flow_from_sources',
    'canonical_profile_learning_flow',
    'learning_verdict_is_clean',
    'profile_behavior_vector_unavailable',
    'profile_learning_commit_unavailable',
)
