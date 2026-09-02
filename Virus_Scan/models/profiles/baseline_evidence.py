"""Profile extension-baseline unavailable evidence owners."""

from Virus_Scan.models.contracts.model_failure import make_model_failure_record, materialize_model_failure_record
from Virus_Scan.models.profiles.common import profile_first_reason, profile_safe_text
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.runtime.init_state import get_init_value

BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')


def extension_baseline_unavailable(extension: object, reason: object) -> object:
    """Return explicit unavailable evidence for unsafe extension-baseline reads."""
    reason_text = profile_first_reason(reason, replacement='extension_baseline_unavailable')
    extension_text = profile_safe_text(extension, replacement='<no_ext>')
    failure = materialize_model_failure_record(make_model_failure_record(
        model_name='profiles',
        failure_type='extension_baseline_unavailable',
        reason=reason_text,
        affected_fields=('extension_baseline', 'profile_history'),
        details={'extension': extension_text},
        model_version=BEHAVIOR_MODEL_VERSION,
    ))
    baseline = default_extension_baseline(extension_text)
    baseline.update({
        'ready': False,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'degraded': True,
        'evidence_type': 'profile_extension_baseline',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (failure,),
        'final_json_must_record': True,
        'replay_record_required': True,
    })
    return baseline


__all__ = ('extension_baseline_unavailable',)
