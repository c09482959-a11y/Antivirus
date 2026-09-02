"""Deterministic publication projections for canonical profile tag evidence."""

from Virus_Scan.contracts.tag_evidence_persistence import (
    persisted_tag_frequency_projection,
)

_PROFILE_TAG_STATE_FIELDS = frozenset({
    'schema_version', 'records', 'summary',
})


def rebuild_profile_tag_state_projections(baseline: object) -> bool:
    """Rebuild all string views from the versioned persisted record owner."""
    if type(baseline) is not dict:
        return False
    state = dict.get(baseline, 'tag_evidence')
    if type(state) is not dict:
        changed = dict.get(baseline, 'tags') != {}
        baseline['tags'] = {}
        return changed
    frequencies = persisted_tag_frequency_projection(state)
    changed = False
    for key in tuple(dict.keys(state)):
        if key not in _PROFILE_TAG_STATE_FIELDS:
            dict.pop(state, key, None)
            changed = True
    for tag in sorted(frequencies):
        count = frequencies[tag]
        if dict.get(state, tag) != count:
            state[tag] = count
            changed = True
    publication_tags = {tag: 0 for tag in sorted(frequencies)}
    if dict.get(baseline, 'tags') != publication_tags:
        baseline['tags'] = publication_tags
        changed = True
    return changed


def materialize_profile_tag_state_projections(profile: object) -> bool:
    """Materialize derived runtime tag views after persisted-state validation."""
    if type(profile) is not dict:
        return False
    baselines = dict.get(profile, 'extension_baselines')
    if type(baselines) is not dict:
        return False
    changed = False
    for key in sorted(dict.keys(baselines)):
        if rebuild_profile_tag_state_projections(dict.get(baselines, key)):
            changed = True
    return changed


__all__ = (
    'materialize_profile_tag_state_projections',
    'rebuild_profile_tag_state_projections',
)
