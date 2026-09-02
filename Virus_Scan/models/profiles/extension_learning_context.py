"""Internal materialization helpers for extension-baseline learning."""

from Virus_Scan.models.profiles.baseline import ensure_extension_model_fields
from Virus_Scan.models.profiles.common import (
    profile_first_reason,
    profile_public_ordered_events,
    profile_safe_text,
)
from Virus_Scan.models.profiles.context import contextual_profile_baseline_key, contextual_profile_learning_policy
from Virus_Scan.models.api.chain_contracts import evaluate_chain_evidence
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.utils.counters import increment_counter


def normalize_extension_learning_inputs(
    tags: object,
    ordered_events: object,
    *,
    file_path: object = None,
    strings_blob: object = '',
) -> object:
    """Materialize one canonical tag bundle for profile learning."""
    tag_evidence, _root_records, profile_tags, _correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, 'malformed_profile_learning_tags')
    )
    normalized_events, ordered_reason = profile_public_ordered_events(
        ordered_events, 'malformed_ordered_profile_events',
    )
    del file_path, strings_blob
    chain_evidence = evaluate_chain_evidence(
        tags=tag_evidence,
        ordered_events=normalized_events,
    )
    return {
        'tags': profile_tags,
        'tag_evidence': tag_evidence,
        'ordered_events': normalized_events,
        'chain_evidence': chain_evidence,
        'unavailable_reason': profile_first_reason(tag_reason, ordered_reason, replacement=''),
    }


def resolve_extension_learning_key(file_path: object, learning_allowed: object, validation_meta: object) -> object:
    context_fields = validation_meta.get('contextual_engine_identity') if isinstance(validation_meta, dict) else None
    if not isinstance(context_fields, dict):
        context_identity = contextual_profile_learning_policy(
            file_path, trusted_benign=learning_allowed is True, degraded=False
        )
        context_fields = context_identity.as_record_fields()
        if isinstance(validation_meta, dict):
            validation_meta['contextual_engine_identity'] = context_fields
    return profile_first_reason(
        context_fields.get('learning_baseline_key'),
        context_fields.get('baseline_key'),
        replacement=contextual_profile_baseline_key(file_path, trusted_benign=learning_allowed is True),
    )


def prepare_extension_baseline(profile: object, extension: object) -> object:
    extension_baselines = profile.get('extension_baselines')
    if type(extension_baselines) is not dict:
        raise ValueError('profile_extension_baselines_invalid')
    baseline = extension_baselines.get(extension)
    if baseline is None:
        baseline = default_extension_baseline(extension)
        extension_baselines[extension] = baseline
    ensure_extension_model_fields(baseline)
    return baseline


def apply_extension_learning_rejection(
    profile: object,
    baseline: object,
    rejection_reason: object,
    validation_meta: object,
) -> None:
    baseline['learning_gate']['rejected'] += 1
    baseline['learning_gate']['last_rejection_reason'] = rejection_reason
    baseline['learning_gate']['last_validation'] = validation_meta
    profile.setdefault('model_state', {}).setdefault('learning_rejections', {})
    increment_counter(profile['model_state']['learning_rejections'], rejection_reason)


__all__ = (
    'apply_extension_learning_rejection',
    'normalize_extension_learning_inputs',
    'prepare_extension_baseline',
    'resolve_extension_learning_key',
)
