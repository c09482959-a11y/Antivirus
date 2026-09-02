"""Support helpers for profile coordinated model-validation assembly."""

from __future__ import annotations

from Virus_Scan.contracts.telemetry import log_error
from Virus_Scan.exception_contracts import IO_CONFIGURATION_ERRORS
from Virus_Scan.models.api.markov_contracts import canonical_behavior_flow
from Virus_Scan.models.contracts.no_hook_materialization import no_hook_type_name
from Virus_Scan.models.profiles.baseline import (
    profile_model_failure_record,
    profile_model_unavailable,
)
from Virus_Scan.models.profiles.common import (
    profile_first_reason,
    profile_has_mapping,
    profile_mapping_get,
    profile_public_ordered_events,
    profile_ratio,
)
from Virus_Scan.models.profiles.evidence import merge_profile_subsignal_unavailable
from Virus_Scan.models.profiles.timeline import profile_timeline_unavailable
from Virus_Scan.models.profiles.tag_evidence import profile_tag_evidence_projection
from Virus_Scan.utils.stages import normalize_profile_extension, normalize_stage


def profile_metric(mapping: object, key: object, default: object = 0.0) -> object:
    return profile_ratio(profile_mapping_get(mapping, key, default), 1.0)


def profile_nested_metric(mapping: object, outer_key: object, inner_key: object, default: object = 0.0) -> object:
    return profile_metric(profile_mapping_get(mapping, outer_key, {}), inner_key, default)


def profile_max_metric(mapping: object, *keys: object) -> object:
    best = 0.0
    for key in keys:
        metric = profile_metric(mapping, key, 0.0)
        if metric > best:
            best = metric
    return best


def ordered_events_unavailable_reason(ordered_events: object) -> str | None:
    if ordered_events is not None and not isinstance(ordered_events, (str, bytes)):
        try:
            iter(ordered_events)
        except IO_CONFIGURATION_ERRORS:
            return 'malformed_ordered_profile_events'
    return None


def coordinated_vector_validation(engine: object, file_path: object, tags: object, risk: object, strings_blob: object, api_calls: object, ordered_events: object, baseline: object, ordered_reason: str | None, unavailable_reasons: dict[str, object], model_failures: list[object], behavior_vector_fn: object, vector_anomaly_fn: object) -> object:
    if ordered_reason:
        unavailable_reasons['vector_validation'] = 'profile_vector_validation_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'vector_validation_failed',
            'profile_vector_validation_failed',
            affected_fields=('vector_validation', 'model_anomaly'),
            details={'error_type': ordered_reason},
        ))
        return profile_model_unavailable('profile_vector_validation_failed')
    try:
        vector = behavior_vector_fn(
            engine,
            file_path,
            tags,
            api_calls=api_calls,
            ordered_events=ordered_events,
        )
        return vector_anomaly_fn(profile_mapping_get(baseline, 'vector_baseline', {}), vector)
    except IO_CONFIGURATION_ERRORS as exc:
        log_error('profile behavior vector validation failed')
        unavailable_reasons['vector_validation'] = 'profile_vector_validation_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'vector_validation_failed',
            'profile_vector_validation_failed',
            affected_fields=('vector_validation', 'model_anomaly'),
            details={'error_type': no_hook_type_name(exc)},
        ))
        return profile_model_unavailable('profile_vector_validation_failed')


def coordinated_temporal_support(file_path: object, unavailable_reasons: dict[str, object], model_failures: list[object], snapshot_fn: object) -> float:
    try:
        temporal_snapshot = snapshot_fn(file_path) if file_path is not None else {}
        if profile_has_mapping(temporal_snapshot) and profile_mapping_get(temporal_snapshot, 'ready') is not True:
            reason = profile_first_reason(
                profile_mapping_get(temporal_snapshot, 'unavailable_reason'),
                profile_mapping_get(temporal_snapshot, 'reason'),
                replacement='temporal_support_unavailable',
            )
            unavailable_reasons['temporal_support'] = reason
            model_failures.append(profile_model_failure_record(
                'profiles',
                'temporal_support_unavailable',
                reason,
                affected_fields=('temporal_support', 'model_anomaly'),
                details={'source_model': 'temporal_snapshot'},
            ))
            return 0.0
        if profile_has_mapping(temporal_snapshot):
            return profile_metric(temporal_snapshot, 'belief')
    except IO_CONFIGURATION_ERRORS as exc:
        log_error('profile temporal support failed')
        unavailable_reasons['temporal_support'] = 'profile_temporal_support_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'temporal_support_failed',
            'profile_temporal_support_failed',
            affected_fields=('temporal_support', 'model_anomaly'),
            details={'error_type': no_hook_type_name(exc)},
        ))
    return 0.0


def _flow_source_from_ordered_or_tags(ordered_events: object, tags: object, tag_reason_text: str) -> object:
    source_events, source_reason = profile_public_ordered_events(
        ordered_events, 'malformed_ordered_profile_events',
    )
    if source_reason is None and source_events:
        return source_events
    _bundle, _records, root_tags, _correlation_group_count, tag_reason = (
        profile_tag_evidence_projection(tags, tag_reason_text)
    )
    return () if tag_reason is not None else root_tags


def coordinated_markov_support(file_path: object, tags: object, ordered_events: object, ordered_reason: str | None, unavailable_reasons: dict[str, object], model_failures: list[object], markov_features_fn: object) -> float:
    if ordered_reason:
        unavailable_reasons['markov_support'] = 'profile_markov_support_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'markov_support_failed',
            'profile_markov_support_failed',
            affected_fields=('markov_support', 'model_anomaly'),
            details={'error_type': ordered_reason},
        ))
        return 0.0
    try:
        markov_flow_source = _flow_source_from_ordered_or_tags(ordered_events, tags, 'malformed_profile_markov_tags')
        mf = markov_features_fn(
            'unknown',
            canonical_behavior_flow(markov_flow_source),
            normalize_stage(normalize_profile_extension(file_path)),
        )
        if profile_has_mapping(mf) and profile_mapping_get(mf, 'ready') is not True:
            reason = profile_first_reason(profile_mapping_get(mf, 'reason'), replacement='markov_support_unavailable')
            unavailable_reasons['markov_support'] = reason
            model_failures.append(profile_model_failure_record(
                'profiles',
                'markov_support_unavailable',
                reason,
                affected_fields=('markov_support', 'model_anomaly'),
                details={'source_model': 'markov_features'},
            ))
            return 0.0
        if profile_has_mapping(mf):
            return profile_max_metric(mf, 'transition', 'rarity', 'pair_anomaly')
    except IO_CONFIGURATION_ERRORS as exc:
        log_error('profile markov support failed')
        unavailable_reasons['markov_support'] = 'profile_markov_support_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'markov_support_failed',
            'profile_markov_support_failed',
            affected_fields=('markov_support', 'model_anomaly'),
            details={'error_type': no_hook_type_name(exc)},
        ))
    return 0.0


def coordinated_timeline_validation(engine: object, file_path: object, tags: object, ordered_events: object, ordered_reason: str | None, unavailable_reasons: dict[str, object], model_failures: list[object], timeline_anomaly_fn: object) -> object:
    if ordered_reason:
        unavailable_reasons['timeline_validation'] = 'profile_timeline_validation_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'timeline_validation_failed',
            'profile_timeline_validation_failed',
            affected_fields=('timeline_validation', 'model_anomaly'),
            details={'error_type': ordered_reason},
        ))
        return profile_timeline_unavailable('profile_timeline_validation_failed')
    try:
        timeline_flow_source = _flow_source_from_ordered_or_tags(ordered_events, tags, 'malformed_profile_timeline_tags')
        return timeline_anomaly_fn(engine, file_path, canonical_behavior_flow(timeline_flow_source))
    except IO_CONFIGURATION_ERRORS as exc:
        log_error('profile timeline validation failed')
        unavailable_reasons['timeline_validation'] = 'profile_timeline_validation_failed'
        model_failures.append(profile_model_failure_record(
            'profiles',
            'timeline_validation_failed',
            'profile_timeline_validation_failed',
            affected_fields=('timeline_validation', 'model_anomaly'),
            details={'error_type': no_hook_type_name(exc)},
        ))
        return profile_timeline_unavailable('profile_timeline_validation_failed')


def coordinated_validation_result(*, model_version: str, engine_extension: object, bucket_v: object, vector_v: object, timeline_v: object, temporal_boost: object, markov_boost: object, unavailable_reasons: dict[str, object], model_failures: list[object]) -> dict[str, object]:
    merge_profile_subsignal_unavailable('bucket_validation', bucket_v, unavailable_reasons, model_failures)
    merge_profile_subsignal_unavailable('vector_validation', vector_v, unavailable_reasons, model_failures)
    merge_profile_subsignal_unavailable('timeline_validation', timeline_v, unavailable_reasons, model_failures)
    timeline_boost = profile_metric(timeline_v, 'anomaly')
    filetype_boost = profile_nested_metric(bucket_v, 'filetype_validation', 'filetype_anomaly')
    bucket_boost = profile_metric(bucket_v, 'bucket_anomaly')
    vector_boost = profile_metric(vector_v, 'anomaly')
    final = profile_ratio(
        bucket_boost * 0.26
        + vector_boost * 0.22
        + filetype_boost * 0.12
        + temporal_boost * 0.1
        + markov_boost * 0.14
        + timeline_boost * 0.16,
        1.0,
    )
    degraded = len(unavailable_reasons) > 0 or len(model_failures) > 0
    result: dict[str, object] = {
        'version': model_version,
        'ready': not degraded,
        'degraded': degraded,
        'evidence_type': 'profile_coordinated_validation',
        'profile_model_version': model_version,
        'model_evidence_ready': not degraded,
        'engine_extension': engine_extension,
        'model_anomaly': final,
        'bucket_validation': bucket_v,
        'filetype_validation': profile_mapping_get(bucket_v, 'filetype_validation', {}),
        'vector_validation': vector_v,
        'timeline_validation': timeline_v,
        'temporal_support': temporal_boost,
        'markov_support': markov_boost,
        'timeline_support': timeline_boost,
    }
    if degraded:
        result['unavailable_reasons'] = unavailable_reasons
        result['final_json_must_record'] = True
        result['replay_record_required'] = True
    if model_failures:
        result['model_failures'] = tuple(model_failures)
    return result
