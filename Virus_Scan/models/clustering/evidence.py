from Virus_Scan.models.clustering.common import (
    cluster_first_reason,
    cluster_flag_enabled,
    safe_cluster_text,
)

_CLUSTER_NON_FAILURE_REASONS = frozenset({'eligible', 'cluster_quality_below_threshold'})


def cluster_assignment_unavailable(reason: object) -> object:
    reason_text = cluster_first_reason(reason, default_text='cluster_assignment_unavailable')
    return {
        'assigned': False,
        'cluster_id': None,
        'updated': False,
        'ready': False,
        'degraded': True,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'cluster_unavailable_reason': reason_text,
        'evidence_type': 'cluster_assignment',
        'final_json_must_record': True,
        'replay_record_required': True,
    }


def cluster_signal_unavailable_reason(record: object) -> object:
    if not isinstance(record, dict):
        return None
    for key in (
        'unavailable_reason',
        'cluster_unavailable_reason',
        'reason',
        'failure_reason',
        'error_reason',
    ):
        value = record.get(key)
        text = safe_cluster_text(value, default_text='')
        if text != '' and text not in _CLUSTER_NON_FAILURE_REASONS:
            return text
    if cluster_flag_enabled(record.get('degraded')):
        return 'degraded_cluster_context_signal'
    if cluster_flag_enabled(record.get('confidence_degraded')):
        return 'confidence_degraded_cluster_context_signal'
    return None


__all__ = (
    'cluster_assignment_unavailable',
    'cluster_signal_unavailable_reason',
)
