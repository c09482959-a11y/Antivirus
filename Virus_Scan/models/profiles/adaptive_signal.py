"""Profile adaptive-signal owners without profile API imports."""
from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.models.profiles.baseline import get_extension_baseline, profile_model_failure_record
from Virus_Scan.models.profiles.context import engine_extension_key
from Virus_Scan.models.profiles.common import profile_finite_float, profile_first_reason, profile_flag_enabled, profile_has_mapping, profile_int, profile_mapping_get, profile_model_failure_records, profile_nested_metric, profile_ratio, profile_safe_text
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.models.profiles.evidence import adaptive_profile_unavailable, extension_profile_unavailable, profile_nonnegative_int
from Virus_Scan.models.profiles.coordinated_validation import coordinated_model_validation_signal
from Virus_Scan.models.profiles.anomaly_frequency import (
    extension_profile_chain_anomalies,
    extension_tag_frequency_evidence,
)
from Virus_Scan.models.profiles.maturity import profile_maturity_evidence
from Virus_Scan.runtime.init_state import get_init_value
from Virus_Scan.utils.probability import safe_clamp
from Virus_Scan.utils.stages import normalize_profile_extension
ADAPTIVE_WEIGHT_MIN_HISTORY = int(get_init_value('ADAPTIVE_WEIGHT_MIN_HISTORY') or 5)
MIN_CLUSTER_SIZE = int(get_init_value('MIN_CLUSTER_SIZE') or 2)
BEHAVIOR_MODEL_VERSION = str(get_init_value('BEHAVIOR_MODEL_VERSION') or 'engine_extension_bucket_vector_v4')
HIGH_RISK_BUCKETS = frozenset(get_init_value('HIGH_RISK_BUCKETS') or ())
def infer_profile_engine(tags: object, file_structure: object=None, strings_blob: object='') -> object:
    bundle, _root_records, _root_tags, _correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, 'malformed_profile_engine_tags')
    )
    tagset = {tag.lower() for tag in bundle.tags if type(tag) is str}
    path_text = profile_safe_text(file_structure, replacement='').lower()
    blob = profile_safe_text(strings_blob, replacement='').lower()
    media_exts = {
        '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.tif', '.tiff',
        '.ico', '.dds', '.ktx', '.ktx2', '.pvr', '.qoi', '.tga', '.mp3',
        '.wav', '.ogg', '.oga', '.opus', '.flac', '.mp4', '.m4v', '.m4a',
        '.mov', '.avi', '.webm', '.mkv',
    }
    media_tags = {
        'media_asset', 'image_asset', 'audio_asset', 'video_asset',
        'stego_payload_suspect', 'embedded_payload_after_eof',
    }
    engine = 'other'
    if 'renpy' in tagset or '.rpy' in path_text or '.rpa' in path_text:
        engine = 'renpy'
    elif 'rpgm' in tagset or '.rgss' in path_text or 'www/data' in path_text:
        engine = 'rpgm'
    elif 'unity' in tagset or 'unityplayer' in blob or 'assembly-csharp' in blob:
        engine = 'unity'
    elif tagset & media_tags or any(path_text.endswith(ext) for ext in media_exts):
        engine = 'media'
    context: dict[str, object] = {engine: 1.0}
    if tag_reason:
        context.update({
            'degraded': True,
            'unavailable_reason': tag_reason,
            'evidence_type': 'profile_engine_inference',
            'final_json_must_record': True,
            'replay_record_required': True,
        })
    return engine, context
def _extension_profile_risk_anomaly(baseline: object, risk: object) -> float:
    risk_baseline = profile_mapping_get(baseline, 'risk', {})
    avg_risk = profile_finite_float(profile_mapping_get(risk_baseline, 'avg', 0.0), 0.0)
    max_seen = profile_finite_float(profile_mapping_get(risk_baseline, 'max_seen', 0.0), 0.0)
    risk_value = profile_finite_float(risk, 0.0)
    return 0.0 if max_seen <= 0 else profile_ratio(risk_value - avg_risk, max_seen)
def _extension_profile_coordinated_metrics(engine: object, file_path: object, tags: object, risk: object, strings_blob: object, api_calls: object, ordered_events: object) -> tuple[object, float, float, float]:
    try:
        model_v = coordinated_model_validation_signal(
            engine,
            file_path,
            tags,
            risk=risk,
            strings_blob=profile_safe_text(strings_blob, replacement=''),
            api_calls=api_calls,
            ordered_events=ordered_events if ordered_events is not None else (),
        )
        return (
            model_v,
            profile_nested_metric(model_v, 'bucket_validation', 'bucket_anomaly'),
            profile_nested_metric(model_v, 'vector_validation', 'anomaly'),
            profile_nested_metric(model_v, 'timeline_validation', 'anomaly'),
        )
    except IO_CONFIGURATION_ERRORS as exc:
        log_error('coordinated model validation failed in profile anomaly')
        reason_text = 'coordinated_model_validation_failed'
        model_v = {
            'degraded': True,
            'reason': reason_text,
            'unavailable_reason': reason_text,
            'evidence_type': 'profile_coordinated_validation',
            'profile_model_version': BEHAVIOR_MODEL_VERSION,
            'model_failures': (
                profile_model_failure_record(
                    'profiles',
                    'coordinated_validation_failed',
                    reason_text,
                    affected_fields=('coordinated_model', 'profile_anomaly'),
                    details={'error_type': no_hook_type_name(exc)},
                ),
            ),
            'final_json_must_record': True,
            'replay_record_required': True,
        }
        return model_v, 0.0, 0.0, 0.0
def _apply_coordinated_profile_degraded(result: dict[str, object], model_v: object) -> None:
    if profile_has_mapping(model_v) and (
        profile_flag_enabled(profile_mapping_get(model_v, 'degraded'))
        or profile_flag_enabled(profile_mapping_get(model_v, 'final_json_must_record'))
    ):
        reason = profile_first_reason(
            profile_mapping_get(model_v, 'unavailable_reason'),
            profile_mapping_get(model_v, 'reason'),
            replacement='coordinated_model_unavailable',
        )
        result['degraded'] = True
        result['unavailable_reason'] = reason
        result['final_json_must_record'] = True
        result['replay_record_required'] = True
        result['model_failures'] = profile_model_failure_records(profile_mapping_get(model_v, 'model_failures'))
def extension_profile_anomaly(engine: object, file_path: object, tags: object, risk: object=0.0, strings_blob: object='', api_calls: object=None, ordered_events: object=None) -> object:
    """Compare current tags/chains/risk to the learned engine/extension baseline."""
    baseline = get_extension_baseline(engine, file_path)
    ext = normalize_profile_extension(file_path)
    if profile_has_mapping(baseline) and profile_mapping_get(baseline, 'ready') is False:
        reason = profile_first_reason(
            profile_mapping_get(baseline, 'unavailable_reason'),
            profile_mapping_get(baseline, 'reason'),
            replacement='extension_baseline_unavailable',
        )
        return extension_profile_unavailable(ext, reason)
    files = profile_nonnegative_int(profile_mapping_get(baseline, 'files', 0))
    if files is None:
        return extension_profile_unavailable(ext, 'invalid_extension_profile_files_seen')
    maturity = profile_maturity_evidence(
        profile_mapping_get(baseline, 'vector_baseline', {}),
    )
    trusted_support = maturity['trusted_count']
    if maturity['ready'] is not True:
        return extension_profile_unavailable(
            ext, maturity['reason'] or 'profile_maturity_unavailable',
            files_seen=trusted_support,
        )
    bundle, _root_records, _root_tags, _correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, 'malformed_extension_profile_tags')
    )
    if tag_reason is not None:
        return extension_profile_unavailable(ext, tag_reason, files_seen=files)
    tag_anomaly, chain_anomaly = extension_profile_chain_anomalies(
        engine, file_path, bundle, api_calls, ordered_events,
    )
    risk_anomaly = _extension_profile_risk_anomaly(baseline, risk)
    model_v, bucket_anomaly, vector_anomaly, timeline_anomaly = _extension_profile_coordinated_metrics(
        engine, file_path, bundle, risk, strings_blob, api_calls, ordered_events
    )
    raw_anomaly = safe_clamp(
        profile_finite_float(tag_anomaly, 0.0) * 0.26
        + profile_finite_float(chain_anomaly, 0.0) * 0.21
        + profile_finite_float(risk_anomaly, 0.0) * 0.13
        + profile_finite_float(bucket_anomaly, 0.0) * 0.14
        + profile_finite_float(vector_anomaly, 0.0) * 0.13
        + profile_finite_float(timeline_anomaly, 0.0) * 0.13
    )
    final = safe_clamp(raw_anomaly * maturity['suppression_authority'])
    result: dict[str, object] = {
        'extension': ext,
        'anomaly': final,
        'tag_anomaly': safe_clamp(tag_anomaly),
        'chain_anomaly': safe_clamp(chain_anomaly),
        'risk_anomaly': safe_clamp(risk_anomaly),
        'bucket_anomaly': safe_clamp(bucket_anomaly),
        'vector_anomaly': safe_clamp(vector_anomaly),
        'timeline_anomaly': safe_clamp(timeline_anomaly),
        'coordinated_model': model_v,
        'files_seen': files,
        'trusted_support': trusted_support,
        'maturity': maturity['maturity'],
        'suppression_authority': maturity['suppression_authority'],
        'raw_anomaly': raw_anomaly,
    }
    _apply_coordinated_profile_degraded(result, model_v)
    return result
def adaptive_profile_signal(node: object, tags: object, preliminary_risk: object=0.0, strings_blob: object='') -> object:
    """Return a non-mutating anomaly signal for the engine/extension profile."""
    try:
        engine, _ = infer_profile_engine(tags=tags, file_structure=node, strings_blob=strings_blob)
    except IO_CONFIGURATION_ERRORS:
        engine, _ = ('other', {'unknown': 1.0})
    try:
        baseline = get_extension_baseline(engine, node)
    except IO_CONFIGURATION_ERRORS:
        baseline = adaptive_profile_unavailable(engine, 'profile_baseline_load_failed')
    if profile_has_mapping(baseline) and profile_mapping_get(baseline, 'ready') is False:
        reason = profile_first_reason(
            profile_mapping_get(baseline, 'unavailable_reason'),
            profile_mapping_get(baseline, 'reason'),
            replacement='extension_baseline_unavailable',
        )
        return adaptive_profile_unavailable(engine, reason)
    files_seen = profile_nonnegative_int(profile_mapping_get(baseline, 'files', 0)) if profile_has_mapping(baseline) else None
    if files_seen is None:
        return adaptive_profile_unavailable(engine, 'invalid_profile_history_support')
    maturity = profile_maturity_evidence(
        profile_mapping_get(baseline, 'vector_baseline', {}),
    )
    trusted_support = maturity['trusted_count']
    if maturity['ready'] is not True:
        return adaptive_profile_unavailable(
            engine, maturity['reason'] or 'profile_maturity_unavailable',
            files_seen=trusted_support,
        )
    try:
        prof = extension_profile_anomaly(engine, node, tags, risk=preliminary_risk)
        anomaly = safe_clamp(profile_mapping_get(prof, 'anomaly', 0.0))
        result = {
            'engine': engine,
            'files_seen': files_seen,
            'trusted_support': trusted_support,
            'maturity': maturity['maturity'],
            'suppression_authority': maturity['suppression_authority'],
            'profile_anomaly': anomaly,
            'tag_anomaly': safe_clamp(profile_mapping_get(prof, 'tag_anomaly', 0.0)),
            'chain_anomaly': safe_clamp(profile_mapping_get(prof, 'chain_anomaly', 0.0)),
            'risk_anomaly': safe_clamp(profile_mapping_get(prof, 'risk_anomaly', 0.0)),
            'profile_ready': True,
        }
        if profile_has_mapping(prof) and (
            profile_flag_enabled(profile_mapping_get(prof, 'degraded'))
            or profile_flag_enabled(profile_mapping_get(prof, 'final_json_must_record'))
        ):
            reason = profile_first_reason(
                profile_mapping_get(prof, 'unavailable_reason'),
                profile_mapping_get(prof, 'reason'),
                replacement='extension_profile_unavailable',
            )
            result['degraded'] = True
            result['unavailable_reason'] = reason
            result['final_json_must_record'] = True
            result['replay_record_required'] = True
            result['model_failures'] = profile_model_failure_records(profile_mapping_get(prof, 'model_failures'))
        return result
    except IO_CONFIGURATION_ERRORS as e:
        log_error('adaptive profile signal failed')
        result = adaptive_profile_unavailable(engine, 'profile_signal_error', files_seen=files_seen)
        result['model_failures'] = result['model_failures'] + (
            profile_model_failure_record(
                'profiles',
                'adaptive_profile_signal_failed',
                'profile_signal_error',
                affected_fields=('adaptive_profile_signal', 'profile_anomaly'),
                    details={'error_type': no_hook_type_name(e)},
            ),
        )
        return result
def profile_prior_for_scoring(engine: object, file_path: object, tags: object, risk: object=0.0) -> object:
    """
    Cold-start safe profile anomaly.
    Fixes:
    - empty/new profiles no longer spike anomaly
    """
    del risk
    try:
        baseline = get_extension_baseline(engine, file_path)
    except IO_CONFIGURATION_ERRORS:
        log_error('profile prior baseline load failed')
        baseline = extension_profile_unavailable(normalize_profile_extension(file_path), 'profile_prior_baseline_load_failed')
    if profile_has_mapping(baseline) and (
        profile_mapping_get(baseline, 'ready') is False
        or profile_flag_enabled(profile_mapping_get(baseline, 'degraded'))
    ):
        return safe_clamp(profile_mapping_get(baseline, 'anomaly', 0.0))
    maturity = profile_maturity_evidence(
        profile_mapping_get(baseline, 'vector_baseline', {}),
    )
    if maturity['ready'] is not True:
        return 0.0
    _bundle, root_records, _root_tags, _correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, 'malformed_profile_prior_tags')
    )
    if tag_reason is not None:
        return 0.0
    records = tuple(
        extension_tag_frequency_evidence(
            engine, file_path, record.publication_name,
        )
        for record in root_records
    )
    ready = tuple(record for record in records if record['ready'] is True)
    if not ready:
        return 0.0
    rarity = sum(1.0 - record['probability'] for record in ready)
    return safe_clamp(
        rarity / len(ready) * maturity['suppression_authority']
    )
__all__ = ('adaptive_profile_signal', 'coordinated_model_validation_signal', 'engine_extension_key', 'extension_profile_anomaly', 'infer_profile_engine', 'profile_prior_for_scoring')
