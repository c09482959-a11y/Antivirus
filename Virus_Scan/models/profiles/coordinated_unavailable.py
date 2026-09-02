"""Profile coordinated-validation unavailable evidence owners."""

from collections.abc import Mapping

from Virus_Scan.models.profiles.baseline import profile_model_failure_record
from Virus_Scan.models.profiles.common import profile_first_reason
from Virus_Scan.runtime.init_state import get_init_value

BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')


def coordinated_validation_unavailable(reason: object='coordinated_model_validation_failed', *, source_reason: object=None) -> object:
    reason_text = profile_first_reason(reason, replacement='coordinated_model_validation_failed')
    source_text = profile_first_reason(source_reason, replacement=reason_text)
    failure = profile_model_failure_record(
        'profiles', 'coordinated_validation_failed', reason_text,
        affected_fields=('bucket_validation', 'vector_validation', 'timeline_validation', 'model_anomaly'),
        details={'source_reason': source_text},
    )
    unavailable_signal = {
        'anomaly': 0.0,
        'ready': False,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'model_failures': (failure,),
    }
    bucket_signal = dict(unavailable_signal)
    bucket_signal['bucket_anomaly'] = 0.0
    bucket_signal.pop('anomaly')
    return {
        'version': 'adaptive_bucket_vector_validation_unavailable_v1',
        'ready': False,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'degraded': True,
        'evidence_type': 'profile_coordinated_validation',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'bucket_validation': bucket_signal,
        'filetype_validation': {
            'filetype_anomaly': 0.0,
            'ready': False,
            'reason': reason_text,
            'unavailable_reason': reason_text,
        },
        'vector_validation': dict(unavailable_signal),
        'timeline_validation': dict(unavailable_signal),
        'temporal_support': 0.0,
        'markov_support': 0.0,
        'timeline_support': 0.0,
        'unavailable_reasons': {
            'bucket_validation': reason_text,
            'vector_validation': reason_text,
            'timeline_validation': reason_text,
            'temporal_support': reason_text,
        },
        'model_failures': (failure,),
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def baseline_unavailable_reason(baseline: object) -> object:
    if not isinstance(baseline, Mapping) or baseline.get('ready') is not False:
        return None
    return profile_first_reason(
        baseline.get('unavailable_reason'),
        baseline.get('reason'),
        replacement='extension_baseline_unavailable',
    )


__all__ = ('baseline_unavailable_reason', 'coordinated_validation_unavailable')
