"""Profile evidence and unavailable-record owners."""

from Virus_Scan.contracts.no_hook_materialization import no_hook_exact_nonnegative_int
from Virus_Scan.models.profiles.baseline import profile_model_failure_record
from Virus_Scan.models.profiles.common import (
    profile_first_reason,
    profile_flag_enabled,
    profile_has_mapping,
    profile_mapping_get,
    profile_model_failure_records,
    profile_safe_text,
)
from Virus_Scan.runtime.init_state import get_init_value


BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')


def profile_nonnegative_int(value: object) -> object:
    """Return a finite non-negative integer profile support metric or None."""
    if value is None:
        return None
    metric, reason = no_hook_exact_nonnegative_int(
        value,
        default=0,
        reason='unsafe_profile_support_value_rejected',
        non_finite_reason='non_finite_profile_support_value',
        allow_exact_text=True,
    )
    if reason:
        return None
    return metric


def _profile_support_unavailable(reason: object, *, evidence_type: object, failure_type: object, affected_fields: object, support_field: object='files_seen', support: object=0, extra: object=None) -> object:
    """Return canonical unavailable evidence for a profile support state."""
    reason_text = profile_first_reason(reason, replacement='profile_support_unavailable')
    support_value = profile_nonnegative_int(support)
    support_field_text = profile_safe_text(support_field, replacement='support')
    affected_field_items = tuple(
        affected_fields if affected_fields is not None else ()
    )
    record = {
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'degraded': True,
        support_field_text: int(support_value if support_value is not None else 0),
        'evidence_type': profile_safe_text(
            evidence_type, replacement='profile_evidence_unavailable',
        ),
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (
            profile_model_failure_record(
                'profiles', failure_type, reason_text,
                affected_fields=affected_field_items,
                details={'support_field': support_field_text},
            ),
        ),
        'final_json_must_record': True,
        'replay_record_required': True,
    }
    if support_value is None:
        record[support_field_text + '_unavailable_reason'] = (
            'invalid_' + support_field_text
        )
    if extra is not None:
        record.update(extra)
    return record

def extension_profile_unavailable(extension: object, reason: object, *, files_seen: object=0) -> object:
    return _profile_support_unavailable(
        reason, evidence_type='profile_extension_anomaly',
        failure_type='extension_profile_unavailable',
        affected_fields=('extension_profile', 'profile_anomaly'),
        support_field='files_seen', support=files_seen,
        extra={
            'extension': profile_safe_text(
                extension, replacement='<unreadable_extension>',
            ),
            'anomaly': 0.0, 'ready': False,
        },
    )


def adaptive_profile_unavailable(engine: object, reason: object, *, files_seen: object=0) -> object:
    return _profile_support_unavailable(
        reason, evidence_type='profile_adaptive_signal',
        failure_type='adaptive_profile_unavailable',
        affected_fields=('adaptive_profile_signal', 'profile_anomaly'),
        support_field='files_seen', support=files_seen,
        extra={
            'engine': profile_first_reason(engine, replacement='other'),
            'profile_anomaly': 0.0, 'profile_ready': False, 'ready': False,
        },
    )


def merge_profile_subsignal_unavailable(field_name: object, signal: object, unavailable_reasons: object, model_failures: object) -> None:
    """Project nested unavailable profile sub-signal evidence to its parent."""
    if not profile_has_mapping(signal):
        return
    if not (
        profile_flag_enabled(profile_mapping_get(signal, 'degraded'))
        or profile_flag_enabled(profile_mapping_get(signal, 'final_json_must_record'))
    ):
        return
    field_text = profile_safe_text(field_name, replacement='profile_subsignal_unavailable')
    reason = profile_first_reason(
        profile_mapping_get(signal, 'unavailable_reason'),
        profile_mapping_get(signal, 'reason'),
        replacement=field_text + '_unavailable',
    )
    unavailable_reasons[field_text] = reason
    model_failures.extend(profile_model_failure_records(profile_mapping_get(signal, 'model_failures')))


__all__ = (
    'adaptive_profile_unavailable',
    'extension_profile_unavailable',
    'merge_profile_subsignal_unavailable',
    'profile_nonnegative_int',
)
