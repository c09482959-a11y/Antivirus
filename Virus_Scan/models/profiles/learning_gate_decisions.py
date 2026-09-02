"""Internal decision helpers for profile learning gates."""

from Virus_Scan.models.profiles.common import profile_flag_enabled, profile_mapping_get
from Virus_Scan.models.profiles.learning import learning_verdict_is_clean


def scan_integrity_block_reason(meta: object, missing: object, raw_failed: object) -> object:
    reason = ''
    if profile_flag_enabled(profile_mapping_get(meta, 'raw_queue_degraded')) or profile_flag_enabled(profile_mapping_get(meta, 'scan_incomplete')):
        reason = 'scan_integrity_incomplete_scan_blocks_learning'
    elif profile_flag_enabled(profile_mapping_get(meta, 'partial_retry')):
        reason = 'scan_integrity_partial_retry_blocks_learning'
    elif profile_flag_enabled(profile_mapping_get(meta, 'had_degraded_stage')) or profile_flag_enabled(profile_mapping_get(meta, 'degraded')):
        reason = 'scan_integrity_degraded_stage_blocks_learning'
    elif missing > 0:
        reason = 'scan_integrity_missing_chunks_blocks_learning'
    elif raw_failed > 0:
        reason = 'scan_integrity_raw_failures_block_learning'
    elif profile_flag_enabled(profile_mapping_get(meta, 'file_failed')):
        reason = 'scan_integrity_file_failure_blocks_learning'
    return reason


def learning_gate_primary_rejection(validation: object, verdict: object, evidence: object) -> object:
    reason = ''
    if not learning_verdict_is_clean(verdict):
        reason = 'verdict_not_clean_for_baseline_learning'
    elif evidence['risk_too_high']:
        reason = 'risk_too_high'
    elif evidence['dangerous_blocked']:
        validation['dangerous_anchor_hits'] = evidence['dangerous_anchor_hits'][:40]
        reason = 'dangerous_anchor_blocks_baseline_learning'
    elif evidence['triage_block_hits']:
        validation['triage_learning_block_hits'] = evidence['triage_block_hits'][:40]
        reason = 'triage_red_flag_blocks_baseline_learning'
    elif evidence['high_conf_rare']:
        reason = 'rare_high_confidence_high_risk_indicator'
    elif evidence['high_risk_weak_review']:
        reason = 'weak_high_risk_evidence_needs_review'
    return reason


__all__ = ('learning_gate_primary_rejection', 'scan_integrity_block_reason')
