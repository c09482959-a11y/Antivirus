"""Immutable/default profile snapshot owners.

This module owns default profile container and extension-baseline record shapes.
It intentionally does not import ``profiles.api`` so defaults can be reused by
quarantine, persistence, and public API layers without creating cycles.
"""

from Virus_Scan.models.profiles.chain_state import default_profile_chain_state
from Virus_Scan.contracts.temporal_baseline import (
    empty_temporal_baselines,
)
from Virus_Scan.models.profiles.schema import EngineProfileSchemaSnapshot
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics
from Virus_Scan.models.profiles.contamination import (
    PROFILE_CONTAMINATION_SCHEMA_VERSION,
    default_profile_contamination_state,
)
from Virus_Scan.models.profiles.decision_history import default_profile_decision_history
from Virus_Scan.models.profiles.feature_registry import PROFILE_RAW_FEATURE_SCHEMA_VERSION
from Virus_Scan.models.profiles.schema_versions import (
    PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
    PROFILE_SCHEMA_VERSION,
    PROFILE_TAG_EVIDENCE_SCHEMA_VERSION,
)


def default_profile_tag_evidence_state() -> dict[str, object]:
    """Return a fresh versioned persisted tag-evidence state."""
    return {
        'schema_version': PROFILE_TAG_EVIDENCE_SCHEMA_VERSION,
        'records': {},
        'summary': {
            'updates': 0,
            'observation_events': 0,
            'raw_observation_count': 0,
            'canonical_tag_count': 0,
            'distinct_correlation_group_count': 0,
            'derived_composite_count': 0,
            'scoreable_family_count': 0,
            'suppressed_negative_count': 0,
            'failure_count': 0,
        },
    }


def default_engine_profile(engine: object) -> object:
    """Return a fresh engine profile container with canonical schema fields."""
    return {
        'engine': engine,
        'schema_version': PROFILE_SCHEMA_VERSION,
        'extension_baselines': {},
        'model_state': {
            'vector_baselines': {},
            'temporal_baselines': empty_temporal_baselines(),
            'markov_baselines': {},
            'cluster_baselines': {},
            'learning_rejections': {},
            'learning_transactions': {},
            'learning_applied_keys': {'profile': {}},
            'contamination': default_profile_contamination_state(),
            'decision_history': default_profile_decision_history(),
            'feature_registry_versions': {
                'profile_raw_features': PROFILE_RAW_FEATURE_SCHEMA_VERSION,
                'profile_contamination': PROFILE_CONTAMINATION_SCHEMA_VERSION,
                'learning_transaction': PROFILE_LEARNING_TRANSACTION_SCHEMA_VERSION,
            },
        },
        'created': 0.0,
        'updated': 0.0,
    }


def default_extension_baseline(ext: object) -> object:
    """Return a fresh per-extension profile learning baseline."""
    return {
        'extension': ext,
        'files': 0,
        'behavior_buckets': {},
        'tags': {},
        'tag_evidence': default_profile_tag_evidence_state(),
        'vector_baseline': default_profile_vector_statistics(),
        'timeline_baseline': {
            'sample_count': 0,
            'event_counts': {},
            'transition_counts': {},
            'behavior_counts': {},
            'behavior_transition_counts': {},
            'max_sequence_len': 0,
            'last_updated': None,
        },
        'chains': default_profile_chain_state(),
        'risk': {'avg': 0.0, 'max_seen': 0.0, 'samples': 0},
        'learning_gate': {
            'accepted': 0,
            'rejected': 0,
            'last_rejection_reason': '',
        },
    }


__all__ = (
    'EngineProfileSchemaSnapshot',
    'PROFILE_TAG_EVIDENCE_SCHEMA_VERSION',
    'default_engine_profile',
    'default_profile_tag_evidence_state',
    'default_extension_baseline',
)
