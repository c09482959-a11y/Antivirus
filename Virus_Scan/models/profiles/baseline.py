"""Profile baseline evidence and validation owners."""
from types import MappingProxyType
from Virus_Scan.contracts.library_baseline import library_baseline_has_hard_proof, library_behavior_baseline_profile
from Virus_Scan.contracts.tag_evidence import (
    contextual_dangerous_anchor_hits,
    dangerous_anchor_learning_block_enabled,
)
from Virus_Scan.models.contracts.model_failure import make_model_failure_record, materialize_model_failure_record
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.models.profiles.persistence import DEFAULT_ENGINES, get_scoring_profile
from Virus_Scan.models.profiles.chain_state import PROFILE_CHAIN_STATE_SCHEMA_VERSION
from Virus_Scan.models.profiles.context import contextual_profile_bucket_key
from Virus_Scan.models.profiles.common import profile_finite_float, profile_first_reason, profile_has_mapping, profile_mapping_get, profile_public_path_text, profile_public_tags, profile_ratio, profile_safe_text
from Virus_Scan.models.profiles.snapshots import PROFILE_TAG_EVIDENCE_SCHEMA_VERSION, default_extension_baseline, default_profile_tag_evidence_state
from Virus_Scan.models.profiles.vector_statistics import default_profile_vector_statistics
from Virus_Scan.models.profiles.request_contracts import ProfileBucketValidationRequest
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.models.profiles.baseline_evidence import extension_baseline_unavailable
from Virus_Scan.utils.stages import normalize_profile_extension
from Virus_Scan.utils.tagging import ordered_unique_tags
BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')
CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS = dangerous_anchor_learning_block_enabled()
HIGH_RISK_BUCKETS = frozenset(get_init_value('HIGH_RISK_BUCKETS') or ())
QUALITY_GATE_VERSION = str(get_init_value('QUALITY_GATE_VERSION') or 'quality_gate_v2_canonical_chain_authority')
_LIBRARY_BASELINE_REPLACEMENTS = MappingProxyType(dict(get_init_value('_LIBRARY_BASELINE_REPLACEMENTS') or {}))
_LIBRARY_BASELINE_VERSION = str(get_init_value('_LIBRARY_BASELINE_VERSION') or 'library_baseline_v2_hard_proof')
_PROFILE_BEHAVIOR_BUCKET_PATTERNS = (('credential', ('credential', 'mimikatz', 'lsass', 'keylog', 'clipboard')), ('injection', ('inject', 'virtualalloc', 'writeprocessmemory', 'createremotethread', 'apc')), ('persistence', ('persist', 'schtask', 'startup', 'registry', 'service_create')), ('evasion', ('defender_disable', 'amsi', 'etw', 'evasion', 'obfuscat', 'packed')), ('os_execution', ('exec', 'powershell', 'cmd', 'process', 'shell', 'script')), ('network', ('download', 'http', 'socket', 'network', 'exfil', 'dns')), ('entropy_or_packing', ('entropy', 'encoded', 'base64', 'xor', 'payload')), ('renpy_script_logic', ('renpy',)), ('unity_managed_code', ('unity',)), ('rpgm_node_runtime', ('rpgm', 'nwjs', 'node')))
def profile_model_failure_record(model_name: object, failure_type: object, reason: object, affected_fields: object=None, details: object=None) -> object:
    """Materialize profile-model failure evidence for final JSON/replay projection."""
    return materialize_model_failure_record(make_model_failure_record(
        model_name=model_name,
        failure_type=failure_type,
        reason=reason,
        affected_fields=affected_fields if affected_fields is not None else (),
        details=details if details is not None else {},
        model_version=BEHAVIOR_MODEL_VERSION,
    ))
def _profile_model_nonnegative_int(value: object, default: object=0) -> object:
    numeric = profile_finite_float(value, None)
    if numeric is None or numeric < 0.0 or not numeric.is_integer():
        return default if type(default) is int and default >= 0 else 0
    return int(numeric)
def profile_model_unavailable(reason: object, *, count: object=0, dimension: object=None) -> object:
    reason_text = profile_first_reason(reason, replacement='profile_model_unavailable')
    record = {
        'ready': False,
        'anomaly': 0.0,
        'reason': reason_text,
        'unavailable_reason': reason_text,
        'degraded': True,
        'count': _profile_model_nonnegative_int(count, 0),
        'evidence_type': 'profile_vector_baseline',
        'profile_model_version': BEHAVIOR_MODEL_VERSION,
        'model_failures': (
            profile_model_failure_record(
                'profiles',
                'vector_baseline_unavailable',
                reason_text,
                affected_fields=('vector_validation', 'vector_support'),
            ),
        ),
        'final_json_must_record': True,
        'replay_record_required': True,
    }
    if dimension is not None:
        record['dimension'] = _profile_model_nonnegative_int(dimension, 0)
    return record
def apply_library_behavior_baseline(tags: object, path: object=None, strings_blob: object='') -> object:
    normalized_tags, tag_reason = profile_public_tags(tags, 'malformed_profile_library_tags')
    if tag_reason is not None:
        return ()
    profile = library_behavior_baseline_profile(path, strings_blob)
    if not profile:
        return ordered_unique_tags(normalized_tags)
    identity_tags_raw = profile.get('identity_tags', [])
    identity_tags, identity_reason = profile_public_tags(identity_tags_raw, 'malformed_profile_library_identity_tags')
    if identity_reason is not None:
        identity_tags = ()
    if library_baseline_has_hard_proof(normalized_tags, strings_blob):
        return ordered_unique_tags(list(normalized_tags) + list(identity_tags) + ['library_behavior_baseline_hard_proof_bypass'])
    normal_tags, normal_reason = profile_public_tags(profile.get('normal_tags', ()), 'malformed_profile_library_normal_tags')
    normal = set() if normal_reason is not None else {profile_safe_text(t, replacement='').lower() for t in normal_tags}
    cleaned, extras, suppressed = [], [*list(identity_tags), _LIBRARY_BASELINE_VERSION], False
    for t in normalized_tags:
        low = profile_safe_text(t, replacement='').lower()
        if low in normal:
            suppressed = True
            repl = _LIBRARY_BASELINE_REPLACEMENTS.get(low)
            if repl:
                extras.append(repl)
            continue
        cleaned.append(t)
    if suppressed:
        extras.append('library_baseline_normal_behavior_suppressed')
    return ordered_unique_tags(cleaned + extras)
def profile_tag_behavior_bucket(tag: object) -> object:
    name = profile_safe_text(tag, replacement='').lower()
    for bucket, patterns in _PROFILE_BEHAVIOR_BUCKET_PATTERNS:
        if any((pattern in name) if pattern != 'etw' else (name == 'etw' or name.startswith('etw_') or name.endswith('_etw') or '_etw_' in name) for pattern in patterns):
            return bucket
    return 'other'
def profile_behavior_bucket_validation(request: ProfileBucketValidationRequest) -> object:
    """Validate one distinct-root profile record per observed behavior."""
    engine, file_path, tags = request.engine, request.file_path, request.tags
    bundle, root_records, root_tags, _correlation_group_count, tag_reason = profile_tag_evidence_projection(
        tags, 'malformed_profile_bucket_tags',
    )
    tagset = set(root_tags)
    dangerous = (
        contextual_dangerous_anchor_hits(root_tags)
        if CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS else []
    )
    high_risk = sorted({
        record.canonical_tag_id for record in root_records
        if profile_tag_behavior_bucket(record.canonical_tag_id) in HIGH_RISK_BUCKETS
        or record.canonical_tag_id in HIGH_RISK_BUCKETS
    })
    records = []
    for record in root_records:
        tag_text = record.canonical_tag_id
        bucket = profile_tag_behavior_bucket(tag_text)
        high = bucket in HIGH_RISK_BUCKETS or tag_text in HIGH_RISK_BUCKETS
        confidence = 0.75 if high else 0.45 if bucket != 'other' else 0.2
        policy_prior = 0.01 if high else 0.25 if bucket != 'other' else 0.6
        records.append({
            'tag': tag_text, 'bucket': bucket, 'confidence': confidence,
            'policy_prior': policy_prior,
            'policy_prior_source': 'profile_bucket_validation_policy_v1_not_learned',
            'effective_score': confidence * (1.0 - policy_prior) * (8.0 if high else 2.0),
            'root_observation_id': record.root_observation_id,
            'evidence_kind': record.evidence_kind,
        })
    blocked = len(dangerous) > 0 or len(high_risk) > 0
    bucket_scores = [float(row['effective_score']) / 8.0 for row in records]
    bucket_anomaly = profile_ratio(sum(bucket_scores), max(1, len(bucket_scores)))
    filetype_validation = {
        'filetype_anomaly': bucket_anomaly if blocked else min(bucket_anomaly, 0.35),
        'nonexec_execution_violation': False,
        'context': {'execution_capability': 'unknown'},
    }
    result = {
        'version': QUALITY_GATE_VERSION,
        'engine': engine if engine in DEFAULT_ENGINES else 'other',
        'extension': normalize_profile_extension(file_path),
        'allow_learning': not blocked and tag_reason is None,
        'blocked': blocked,
        'dangerous_tags': dangerous[:40],
        'high_risk_tags': high_risk[:40],
        'tag_count': len(root_records),
        'records': records[:80],
        'bucket_anomaly': bucket_anomaly,
        'filetype_validation': filetype_validation,
        'rare_high_conf_single_indicator': any(
            row['bucket'] in HIGH_RISK_BUCKETS and row['policy_prior'] < 0.05
            for row in records
        ),
        'nonexec_execution_violation': False,
        'tag_evidence_summary': dict(bundle.summary),
    }
    if tag_reason is not None:
        result.update({
            'degraded': True, 'unavailable_reason': tag_reason,
            'final_json_must_record': True, 'replay_record_required': True,
            'model_failures': (profile_model_failure_record(
                'profiles', 'profile_bucket_validation_failed', tag_reason,
                affected_fields=('bucket_validation', 'profile_anomaly'),
                details={'error_type': tag_reason},
            ),),
        })
    return result
def ensure_extension_model_fields(baseline: object) -> object:
    """Validate one current extension baseline without repairing it in place."""
    if type(baseline) is not dict:
        raise ValueError('profile_extension_baseline_invalid')
    for field in ('behavior_buckets', 'timeline_baseline', 'learning_gate', 'risk'):
        if type(baseline.get(field)) is not dict:
            raise ValueError('profile_extension_' + field + '_invalid')
    tag_evidence = baseline.get('tag_evidence')
    if (
        type(tag_evidence) is not dict
        or tag_evidence.get('schema_version') != PROFILE_TAG_EVIDENCE_SCHEMA_VERSION
        or type(tag_evidence.get('records')) is not dict
        or type(tag_evidence.get('summary')) is not dict
    ):
        raise ValueError('profile_extension_tag_evidence_invalid')
    vector = baseline.get('vector_baseline')
    if type(vector) is not dict:
        raise ValueError('profile_extension_vector_baseline_invalid')
    chains = baseline.get('chains')
    if (
        type(chains) is not dict
        or chains.get('schema_version') != PROFILE_CHAIN_STATE_SCHEMA_VERSION
        or type(chains.get('suspicious_audit')) is not dict
        or 'normal' in chains or 'suspicious' in chains
    ):
        raise ValueError('profile_extension_chain_state_invalid')
    return baseline

def get_extension_baseline(engine: object, file_path: object, *, evidence_context: object | None=None, router_identity: object | None=None) -> object:
    """Read the contextual profile baseline under one engine without saving."""
    engine = engine if engine in DEFAULT_ENGINES else 'other'
    path_text, path_reason = profile_public_path_text(file_path, reason='extension_baseline_public_input_invalid', replacement='')
    if path_reason is not None: return extension_baseline_unavailable('<no_ext>', path_reason)
    ext, _ctx = (
        contextual_profile_bucket_key(
            path_text, trusted_benign=True, router_identity=router_identity,
        )
        if evidence_context is None
        else contextual_profile_bucket_key(
            path_text, trusted_benign=True, evidence_context=evidence_context,
            router_identity=router_identity,
        )
    )
    profile = get_scoring_profile(engine)
    baselines = profile.get('extension_baselines') if type(profile) is dict else None
    if type(baselines) is not dict:
        return extension_baseline_unavailable(ext, 'profile_extension_baselines_invalid')
    baseline = baselines.get(ext)
    if baseline is None:
        return default_extension_baseline(ext)
    try:
        return ensure_extension_model_fields(baseline)
    except ValueError as exc:
        return extension_baseline_unavailable(ext, str(exc))
__all__ = ('BEHAVIOR_MODEL_VERSION', 'CONTEXTUAL_BASELINE_NEVER_LEARN_DANGEROUS', 'HIGH_RISK_BUCKETS', 'QUALITY_GATE_VERSION', 'apply_library_behavior_baseline', 'ensure_extension_model_fields', 'extension_baseline_unavailable', 'get_extension_baseline', 'profile_behavior_bucket_validation', 'profile_model_failure_record', 'profile_model_unavailable', 'profile_tag_behavior_bucket')
