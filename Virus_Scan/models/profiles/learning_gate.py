"""Profile learning gate and rejection bookkeeping owners.
This module owns learning eligibility decisions and rejected-learning evidence. It
intentionally does not import ``Virus_Scan.models.profiles.api`` so the profile
API remains a facade rather than an executable owner.
"""
from Virus_Scan.contracts.path_identity import get_scan_extension
from Virus_Scan.contracts.tag_evidence import (
    contextual_dangerous_anchor_hits,
    dangerous_anchor_learning_block_enabled,
)
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.runtime.structured_failures import record_suppressed_failure
from Virus_Scan.models.profiles.baseline import profile_behavior_bucket_validation
from Virus_Scan.models.profiles.schema import ProfileSchemaInvariantError
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest, ProfileLearningGateRequest
from Virus_Scan.models.profiles.common import profile_finite_float, profile_first_reason, profile_flag_enabled, profile_has_mapping, profile_int, profile_mapping_copy, profile_mapping_get, profile_public_ordered_events, profile_public_tags, profile_safe_text
from Virus_Scan.models.profiles.context import contextual_profile_bucket_key, contextual_profile_learning_policy
from Virus_Scan.models.profiles.learning_gate_decisions import learning_gate_primary_rejection, scan_integrity_block_reason
from Virus_Scan.models.profiles.persistence import BULK_DEFER_PROFILE_WRITES, DEFAULT_ENGINES, load_engine_profile, save_engine_profile
from Virus_Scan.models.profiles.snapshots import default_extension_baseline
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
TRIAGE_LEARNING_BLOCK_TAGS = frozenset(get_init_value('TRIAGE_LEARNING_BLOCK_TAGS') or ())
HIGH_RISK_BUCKETS = frozenset(get_init_value('HIGH_RISK_BUCKETS') or ())
CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS = dangerous_anchor_learning_block_enabled()
QUALITY_GATE_VERSION = str(get_init_value('QUALITY_GATE_VERSION') or 'quality_gate_v2_canonical_chain_authority')
_HIGH_RISK_WEAK_CONFIDENCE_MAX, _BASELINE_LEARNING_MAX_RISK, _WEAK_HIGH_RISK_REVIEW_MIN_RISK = (
    0.6, 50.0, 25.0)
def _scan_integrity_allows_learning(meta: object) -> object:
    if meta is None:
        materialized = {}
    else:
        materialized = profile_mapping_copy(meta)
        if materialized is None:
            return (False, 'scan_integrity_metadata_unavailable_blocks_learning', {'scan_integrity_unavailable': True})
    if len(materialized) == 0:
        return (True, 'scan_integrity_clean_or_untracked', materialized)
    missing = max(0, profile_int(profile_mapping_get(materialized, 'missing_chunks', 0), 0))
    raw_failed = max(0, profile_int(profile_mapping_get(materialized, 'raw_failed', 0), 0))
    reason = scan_integrity_block_reason(materialized, missing, raw_failed)
    return (reason == '', reason or 'scan_integrity_complete_retry_ok', materialized)
def triage_learning_block_hits(tags: object) -> object:
    normalized_tags, tag_reason = profile_public_tags(tags, 'malformed_profile_triage_tags')
    if tag_reason is not None:
        return []
    normalized = {profile_safe_text(t, replacement='').lower() for t in normalized_tags}
    normalized.discard('')
    return sorted(normalized & TRIAGE_LEARNING_BLOCK_TAGS)
def record_learning_rejection(engine: object, file_path: object, reason: object, validation_meta: object=None) -> object:
    """Profile-owned rejection bookkeeping for blocked learning decisions."""
    try:
        engine_key = profile_safe_text(engine, replacement='other').lower()
        if engine_key not in DEFAULT_ENGINES:
            engine_key = 'other'
        profile = load_engine_profile(engine_key)
        if type(profile) is not dict:
            raise ProfileSchemaInvariantError("authoritative engine profile type invalid")
        validation = profile_mapping_copy(validation_meta)
        if validation is None:
            validation = {}
        context_fields = profile_mapping_get(validation, 'contextual_engine_identity', {})
        if not profile_has_mapping(context_fields):
            context_fields = {}
        ext_key = profile_first_reason(
            profile_mapping_get(context_fields, 'learning_baseline_key'),
            profile_mapping_get(context_fields, 'baseline_key'),
            replacement=contextual_profile_bucket_key(file_path, trusted_benign=False)[0],
        )
        ext_map = profile.setdefault('extension_baselines', {})
        baseline = ext_map.setdefault(ext_key, default_extension_baseline(ext_key))
        baseline.setdefault('extension', ext_key)
        gate = baseline.setdefault('learning_gate', {'accepted': 0, 'rejected': 0, 'last_rejection_reason': ''})
        if not isinstance(gate, dict):
            gate = {'accepted': 0, 'rejected': 0, 'last_rejection_reason': ''}
            baseline['learning_gate'] = gate
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure('learning_rejection_record_failed', exc, domain='model')
        return {
            'recorded': False,
            'reason': profile_first_reason(reason, replacement='unspecified'),
            'error': 'learning_rejection_record_failed',
            'error_type': no_hook_type_name(exc),
        }
    gate['rejected'] = profile_int(profile_mapping_get(gate, 'rejected', 0), 0) + 1
    gate['last_rejection_reason'] = profile_first_reason(reason, replacement='unspecified')
    gate['last_rejection_meta'] = validation
    try:
        if not BULK_DEFER_PROFILE_WRITES:
            save_engine_profile(engine_key, profile)
    except IO_CONFIGURATION_ERRORS as exc:
        record_suppressed_failure('learning_rejection_record_failed', exc, domain='model')
        return {
            'recorded': False,
            'reason': profile_first_reason(reason, replacement='unspecified'),
            'error': 'learning_rejection_record_failed',
            'error_type': no_hook_type_name(exc),
        }
    return {'recorded': True, 'engine': engine_key, 'extension': ext_key, 'reason': gate['last_rejection_reason']}
def _learning_gate_evidence(validation: object, tags: object, risk: object) -> object:
    high_conf_rare = profile_flag_enabled(
        profile_mapping_get(validation, 'rare_high_conf_single_indicator', default=False)
    )
    records, records_reason = profile_public_ordered_events(
        profile_mapping_get(validation, 'records', ()), 'malformed_profile_gate_records'
    )
    if records_reason is not None:
        records = ()
    high_risk_weak = any(
        profile_safe_text(profile_mapping_get(record, 'bucket', ''), replacement='').lower() in HIGH_RISK_BUCKETS
        and profile_finite_float(profile_mapping_get(record, 'confidence', 0.0), 0.0) < _HIGH_RISK_WEAK_CONFIDENCE_MAX
        for record in records
    )
    normalized_tags, tag_reason = profile_public_tags(
        tags, 'malformed_profile_learning_tags',
    )
    dangerous_anchor_hits = (
        contextual_dangerous_anchor_hits(normalized_tags)
        if tag_reason is None else ['contextual_dangerous_anchor_failure']
    )
    triage_block_hits = triage_learning_block_hits(tags)
    risk_value = profile_finite_float(risk, 0.0)
    return {
        'high_conf_rare': high_conf_rare,
        'dangerous_anchor_hits': dangerous_anchor_hits,
        'dangerous_blocked': bool(dangerous_anchor_hits) and CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS,
        'triage_block_hits': triage_block_hits,
        'risk_too_high': risk_value >= _BASELINE_LEARNING_MAX_RISK,
        'high_risk_weak_review': high_risk_weak and risk_value >= _WEAK_HIGH_RISK_REVIEW_MIN_RISK,
    }
def should_learn_scan_result(request: ProfileLearningGateRequest) -> object:
    engine, file_path, tags, risk, strings_blob, verdict, api_calls, ordered_events = request.engine, request.file_path, request.tags, request.risk, request.strings_blob, request.verdict, request.api_calls, request.ordered_events
    validation = profile_behavior_bucket_validation(
        ProfileBucketValidationRequest(
            engine, file_path, tags, strings_blob, api_calls, ordered_events,
        )
    )
    context_identity = contextual_profile_learning_policy(file_path, trusted_benign=True, degraded=False)
    validation['contextual_engine_identity'] = context_identity.as_record_fields()
    if not context_identity.learning_allowed:
        return (False, context_identity.learning_reason, validation)
    integrity_allowed, integrity_reason, integrity_payload = _scan_integrity_allows_learning(request.scan_integrity)
    if integrity_payload:
        validation['scan_integrity'] = integrity_payload
    if not integrity_allowed:
        return (False, integrity_reason, validation)
    evidence = _learning_gate_evidence(validation, tags, risk)
    validation.update(evidence)
    rejection_reason = learning_gate_primary_rejection(validation, verdict, evidence)
    if rejection_reason != '':
        return (False, rejection_reason, validation)
    normalized_tags, tag_reason = profile_public_tags(tags, 'malformed_profile_learning_tags')
    if tag_reason is not None:
        return (False, tag_reason, validation)
    if any(profile_safe_text(tag, replacement='').lower() == 'renpy_bytecode_noise_suppressed' for tag in normalized_tags):
        return (False, 'validation_suppressed_noise', validation)
    return (True, 'trusted_benign_learning_allowed', validation)
def baseline_maturity_report(engine: object, file_path: object) -> object:
    """Return trusted-support extension-baseline maturity without mutation."""
    engine = profile_safe_text(engine, replacement='other').lower()
    if engine not in DEFAULT_ENGINES:
        engine = 'other'
    ext = get_scan_extension(file_path)
    try:
        prof = load_engine_profile(engine)
    except IO_CONFIGURATION_ERRORS as exc:
        return {
            'version': QUALITY_GATE_VERSION,
            'engine': engine,
            'extension': ext,
            'maturity': 'unknown',
            'trusted_support': 0,
            'suppression_strength': 'none',
            'suppression_authority': 0.0,
            'error': 'baseline_maturity_unavailable',
            'error_type': no_hook_type_name(exc),
        }
    extension_baselines = profile_mapping_get(prof, 'extension_baselines', {})
    base = profile_mapping_get(extension_baselines, ext, {})
    maturity = profile_maturity_evidence(
        profile_mapping_get(base, 'vector_baseline', {}),
    )
    gate = profile_mapping_get(base, 'learning_gate', {})
    return {
        'version': QUALITY_GATE_VERSION,
        'engine': engine,
        'extension': ext,
        'maturity': maturity['maturity'],
        'trusted_support': maturity['trusted_count'],
        'observations_seen': maturity['count'],
        'minimum_support': dict(maturity['minimum_support']),
        'learning_gate': {
            'accepted': max(0, profile_int(profile_mapping_get(gate, 'accepted', 0), 0)),
            'rejected': max(0, profile_int(profile_mapping_get(gate, 'rejected', 0), 0)),
        },
        'suppression_strength': maturity['suppression_strength'],
        'suppression_authority': maturity['suppression_authority'],
        'ready': maturity['ready'],
        'reason': maturity['reason'],
    }
