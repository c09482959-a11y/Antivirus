"""Canonical persisted tag-evidence mutation for profile learning."""

from Virus_Scan.contracts.tag_evidence import (
    contextual_dangerous_anchor_hits,
    tag_evidence_record_from_mapping,
    tag_evidence_records,
    tag_evidence_summary,
)
from Virus_Scan.detection.api.tag_evidence_contracts import TagEvidence
from Virus_Scan.models.profiles.baseline import ensure_extension_model_fields
from Virus_Scan.models.profiles.snapshots import (
    PROFILE_TAG_EVIDENCE_SCHEMA_VERSION,
    default_profile_tag_evidence_state,
)
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.models.profiles.tag_state_projection import (
    rebuild_profile_tag_state_projections,
)


def _profile_tag_evidence_state(extension_baseline: object) -> dict[str, object]:
    ensure_extension_model_fields(extension_baseline)
    state = extension_baseline.get('tag_evidence')
    if (
        type(state) is not dict
        or state.get('schema_version') != PROFILE_TAG_EVIDENCE_SCHEMA_VERSION
        or type(state.get('records')) is not dict
        or type(state.get('summary')) is not dict
    ):
        state = default_profile_tag_evidence_state()
        extension_baseline['tag_evidence'] = state
    return state



def learn_profile_tag_evidence(
    extension_baseline: object, tag_evidence: TagEvidence,
) -> dict[str, object]:
    """Persist one observation event for each canonical evidence record."""
    state = _profile_tag_evidence_state(extension_baseline)
    stored_records = state['records']
    ordinal = extension_baseline.get('files', 0)
    if type(ordinal) is not int or type(ordinal) is bool:
        ordinal = 0
    for record in tag_evidence_records(tag_evidence.records):
        previous = stored_records.get(record.evidence_id)
        count = previous.get('observation_count', 0) if type(previous) is dict else 0
        if type(count) is not int or type(count) is bool or count < 0:
            count = 0
        persisted = record.to_record()
        persisted['observation_count'] = count + 1
        persisted['last_observation_ordinal'] = ordinal
        stored_records[record.evidence_id] = persisted
    replay_records = tuple(
        tag_evidence_record_from_mapping(value)
        for value in stored_records.values()
        if type(value) is dict
    )
    summary = dict(tag_evidence_summary(replay_records))
    previous_summary = state.get('summary')
    updates = previous_summary.get('updates', 0) if type(previous_summary) is dict else 0
    events = previous_summary.get('observation_events', 0) if type(previous_summary) is dict else 0
    if type(updates) is not int or type(updates) is bool or updates < 0:
        updates = 0
    if type(events) is not int or type(events) is bool or events < 0:
        events = 0
    root_count = len(profile_tag_evidence_projection(tag_evidence)[1])
    summary['updates'] = updates + 1
    summary['observation_events'] = events + root_count
    state['summary'] = summary
    rebuild_profile_tag_state_projections(extension_baseline)
    return state


def profile_dangerous_root_ids(
    root_records: object, block_dangerous_anchors: bool,
) -> frozenset[str]:
    """Return roots excluded by the configured dangerous-anchor policy."""
    if block_dangerous_anchors is not True:
        return frozenset()
    publications = tuple(record.publication_name for record in root_records)
    dangerous_hits = set(contextual_dangerous_anchor_hits(publications))
    return frozenset(
        record.root_observation_id for record in root_records
        if record.publication_name in dangerous_hits
    )


def learnable_profile_tag_evidence(
    tags: object, block_dangerous_anchors: bool,
) -> tuple[TagEvidence, tuple[object, ...], str | None]:
    """Return a bundle excluding roots forbidden from benign learning."""
    bundle, roots, _root_tags, _correlation_group_count, reason = profile_tag_evidence_projection(
        tags, 'malformed_profile_behavior_bucket_tags',
    )
    if reason is not None:
        return bundle, (), reason
    dangerous_roots = profile_dangerous_root_ids(roots, block_dangerous_anchors)
    if not dangerous_roots:
        return bundle, roots, None
    safe_records = tuple(
        record for record in tag_evidence_records(bundle.records)
        if record.root_observation_id not in dangerous_roots
    )
    safe_roots = tuple(
        record for record in roots
        if record.root_observation_id not in dangerous_roots
    )
    return TagEvidence.from_records(safe_records), safe_roots, None


__all__ = (
    'learn_profile_tag_evidence',
    'learnable_profile_tag_evidence',
    'profile_dangerous_root_ids',
)
